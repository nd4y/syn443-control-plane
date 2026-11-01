package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEnrollmentWireSchemasMatchRuntime(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/enrollment-openapi.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("OpenAPI JSON")
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatal("OpenAPI version")
	}
	compiler := jsonschema.NewCompiler()
	base := "https://contracts.example.invalid/enrollment-openapi.json"
	if e = compiler.AddResource(base, doc); e != nil {
		t.Fatal(e)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	values := map[string]any{"Enroll": Request{random(), identity.PublicJWK(&key.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}}, "Cleanup": Cleanup{random(), []string{random()}}, "Mutation": map[string]string{"requestId": random()}, "Session": Session{random(), random(), random(), 1800000600000, 1800086400000, 0, random()}}
	for name, value := range values {
		schema, e := compiler.Compile(base + "#/components/schemas/" + name)
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(value)
		var object map[string]any
		json.Unmarshal(encoded, &object)
		if e = schema.Validate(object); e != nil {
			t.Fatal("runtime disagrees with wire schema", name)
		}
		object["unexpected"] = true
		if schema.Validate(object) == nil {
			t.Fatal("unknown member accepted", name)
		}
		delete(object, "unexpected")
		for field := range object {
			changed := map[string]any{}
			for k, v := range object {
				if k != field {
					changed[k] = v
				}
			}
			if schema.Validate(changed) == nil {
				t.Fatal("missing required field accepted", name, field)
			}
		}
	}
	paths := doc["paths"].(map[string]any)
	if len(paths) != 5 {
		t.Fatal("unexpected API scope")
	}
	for path, value := range paths {
		methods := value.(map[string]any)
		method := "post"
		if path == "/v1/device/policy" {
			method = "get"
		}
		operation := methods[method].(map[string]any)
		if operation["security"] == nil || operation["parameters"] == nil {
			t.Fatal("unauthenticated endpoint")
		}
	}
}
