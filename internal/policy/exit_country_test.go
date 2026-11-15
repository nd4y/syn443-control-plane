package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestExitCountryRequiresExactCapabilityAndKeyBoundHealthConfiguration(t *testing.T) {
	_, baseline, now := sample(t)
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route_checks":[{"outbound":"direct","checks":[{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU"}]}]}`)
	sum := sha256.Sum256(engine)
	qualified := baseline
	qualified.SchemaVersion = 2
	qualified.KeyThumbprint = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	qualified.EngineConfigB64, qualified.ContentHash = base64.RawURLEncoding.EncodeToString(engine), hex.EncodeToString(sum[:])
	qualified.RequiredCapabilities = append(append([]string{}, baseline.RequiredCapabilities...), "policy.keybound.v2", "route.health.v1", RouteExitCountry)
	if err := qualified.Validate(now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Payload){
		func(p *Payload) { p.Operation = "release" },
		func(p *Payload) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == RouteExitCountry })
		},
		func(p *Payload) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == "route.health.v1" })
		},
		func(p *Payload) { p.RequiredCapabilities = append(p.RequiredCapabilities, RouteExitIP) },
		func(p *Payload) { p.EngineConfigB64, p.ContentHash = baseline.EngineConfigB64, baseline.ContentHash },
		func(p *Payload) {
			p.SchemaVersion, p.KeyThumbprint = 1, ""
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == "policy.keybound.v2" })
		},
	} {
		candidate := qualified
		candidate.RequiredCapabilities = append([]string(nil), qualified.RequiredCapabilities...)
		change(&candidate)
		if candidate.Validate(now) == nil {
			t.Fatal("country check escaped exact capability, operation or key binding")
		}
	}
	engine = []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route_checks":[{"outbound":"direct","checks":[{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"NON_RU"},{"method":"https_exit_ip","target":"https://health.example.invalid/address","expected_ip":"192.0.2.9"}]}]}`)
	sum = sha256.Sum256(engine)
	qualified.EngineConfigB64, qualified.ContentHash = base64.RawURLEncoding.EncodeToString(engine), hex.EncodeToString(sum[:])
	qualified.RequiredCapabilities = append(qualified.RequiredCapabilities, RouteExitIP)
	if err := qualified.Validate(now); err != nil {
		t.Fatal("independent country and fixed-address checks cannot coexist", err)
	}
}

func TestExitCountryPolicySchemaRequiresKeyBoundHealthConfigure(t *testing.T) {
	raw, err := contracts.Files.ReadFile("v1/policy-payload.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("invalid contract")
	}
	compiler := jsonschema.NewCompiler()
	base := document["$id"].(string)
	if err := compiler.AddResource(base, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, _ := sample(t)
	payload.SchemaVersion = 2
	payload.KeyThumbprint = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	payload.RequiredCapabilities = append(payload.RequiredCapabilities, "policy.keybound.v2", "route.health.v1", RouteExitCountry)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var qualified map[string]any
	if json.Unmarshal(data, &qualified) != nil {
		t.Fatal("invalid fixture")
	}
	if err := schema.Validate(qualified); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(p map[string]any) { p["operation"] = "release" },
		func(p map[string]any) {
			p["requiredCapabilities"] = []any{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", RouteExitCountry}
		},
		func(p map[string]any) {
			p["schemaVersion"] = float64(1)
			delete(p, "keyThumbprint")
			p["requiredCapabilities"] = []any{"engine-config.v1", "tun.lease.v1", "route.health.v1", RouteExitCountry}
		},
		func(p map[string]any) {
			p["requiredCapabilities"] = []any{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", "route.exit-country.v2"}
		},
	} {
		var candidate map[string]any
		if json.Unmarshal(data, &candidate) != nil {
			t.Fatal("invalid fixture")
		}
		change(candidate)
		if schema.Validate(candidate) == nil {
			t.Fatal("schema accepted unsupported primitive or missing capability scope")
		}
	}
}
