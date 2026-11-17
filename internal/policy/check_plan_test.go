package policy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func checkPlanPayload(t *testing.T) (policy.Payload, time.Time) {
	t.Helper()
	now := time.Unix(1800000000, 0)
	profile := &configuration.OutboundCheckProfile{SchemaVersion: 2, ID: "health", Revision: 1, DeadlineMs: 12000, Leaves: []configuration.OutboundCheckLeaf{{ID: "country", Check: configuration.OutboundCheck{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "RU"}}, {ID: "ip", Check: configuration.OutboundCheck{Method: "https_exit_ip", Target: "https://ip.example.invalid/", ExpectedIP: "192.0.2.9"}}, {ID: "tcp", Check: configuration.OutboundCheck{Method: "tcp", Target: "a.example.invalid:443"}}}, Gates: []string{"country", "ip"}, Stages: []configuration.OutboundCheckExpr{{Leaf: "tcp"}}}
	p := configuration.NetworkPlan{SchemaVersion: 1, Graph: configuration.Graph{Profiles: map[string]configuration.ProfileReference{}, Chains: map[string]configuration.Chain{}, Balancers: map[string]configuration.Balancer{}, Final: "direct"}, Network: configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4", RouteChecks: []configuration.OutboundCheckPlan{{Outbound: "direct", Required: true, Profile: profile}}}, Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.invalid/", Required: true}}}}
	compiled, e := configuration.CompileNetworkPlan(context.Background(), p, func(configuration.ProfileReference) (subscriptions.Profile, error) {
		t.Fatal("direct fixture resolved a source")
		return subscriptions.Profile{}, configuration.ErrInvalid
	})
	if e != nil {
		t.Fatal(e)
	}
	return policy.Payload{SchemaVersion: 2, Operation: "configure", Revision: 1, SecurityEpoch: 1, TargetDevice: "synthetic-device", KeyThumbprint: identity.Hash([]byte("synthetic-key")), Audience: "syn443-device", IssuedAtMs: now.UnixMilli(), NotBeforeMs: now.UnixMilli(), RefreshAfterMs: now.Add(30 * time.Second).UnixMilli(), OfflineUntilMs: now.Add(time.Hour).UnixMilli(), RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", policy.RouteCheckPlanV2, policy.RouteExitIP, policy.RouteExitCountry}, AlgorithmRevision: policy.BaselineAlgorithm, ContentHash: compiled.ContentHash, EngineConfigB64: base64.RawURLEncoding.EncodeToString(compiled.EngineConfig), Activation: compiled.Activation}, now
}
func setCheckPlanEngine(p *policy.Payload, raw []byte) {
	s := sha256.Sum256(raw)
	p.EngineConfigB64 = base64.RawURLEncoding.EncodeToString(raw)
	p.ContentHash = hex.EncodeToString(s[:])
}

func TestCheckPlanV2PolicyRequiresIffCapabilityKeyBoundConfigureAndHealth(t *testing.T) {
	p, now := checkPlanPayload(t)
	if p.Validate(now) != nil {
		t.Fatal("actual compiled profile rejected")
	}
	for _, change := range []func(*policy.Payload){func(p *policy.Payload) {
		p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(v string) bool { return v == policy.RouteCheckPlanV2 })
	}, func(p *policy.Payload) {
		p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(v string) bool { return v == "route.health.v1" })
	}, func(p *policy.Payload) { p.Operation = "release" }, func(p *policy.Payload) {
		p.SchemaVersion = 1
		p.KeyThumbprint = ""
		p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(v string) bool { return v == "policy.keybound.v2" })
	}, func(p *policy.Payload) {
		setCheckPlanEngine(p, []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`))
	}} {
		v := p
		v.RequiredCapabilities = append([]string(nil), p.RequiredCapabilities...)
		change(&v)
		if v.Validate(now) == nil {
			t.Fatal("profile capability escaped exact envelope fence")
		}
	}
}

func TestCheckPlanV2PolicyScansAllLeavesAndDoesNotSubstituteExitCapabilities(t *testing.T) {
	p, now := checkPlanPayload(t)
	for _, cap := range []string{policy.RouteExitIP, policy.RouteExitCountry} {
		v := p
		v.RequiredCapabilities = slices.DeleteFunc(append([]string(nil), p.RequiredCapabilities...), func(s string) bool { return s == cap })
		if v.Validate(now) == nil {
			t.Fatal("nested exit leaf lost required capability")
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(p.EngineConfigB64)
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil {
		t.Fatal("fixture")
	}
	profile := root["route_checks"].([]any)[0].(map[string]any)["profile"].(map[string]any)
	profile["gates"] = []any{}
	profile["stages"] = []any{map[string]any{"all": []any{map[string]any{"leaf": "country"}, map[string]any{"leaf": "ip"}, map[string]any{"leaf": "tcp"}}}}
	bad, _ := json.Marshal(root)
	setCheckPlanEngine(&p, bad)
	if p.Validate(now) == nil {
		t.Fatal("conditional security leaves accepted despite capabilities")
	}
}

func TestCheckPlanV2SignedBoundPolicyCannotLoseKeyOrMutateClosedProgram(t *testing.T) {
	p, now := checkPlanPayload(t)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(p)
	signed, e := policy.Sign(raw, "fixture-root", key, p.TargetDevice, p.Revision, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := policy.VerifyBound(signed, map[string]*ecdsa.PublicKey{"fixture-root": &key.PublicKey}, p.TargetDevice, p.KeyThumbprint, now); e != nil {
		t.Fatal(e)
	}
	if _, e := policy.VerifyBound(signed, map[string]*ecdsa.PublicKey{"fixture-root": &key.PublicKey}, p.TargetDevice, identity.Hash([]byte("another-key")), now); e == nil {
		t.Fatal("signed profile crossed device-key binding")
	}
	engine, _ := base64.RawURLEncoding.DecodeString(p.EngineConfigB64)
	for _, pair := range [][2]string{{`"profile":`, `"checks":[],"profile":`}, {`"profile":`, `"profile":null,"unknown":`}, {`"schemaVersion":2`, `"schemaVersion":2.0`}} {
		bad := []byte(strings.Replace(string(engine), pair[0], pair[1], 1))
		v := p
		setCheckPlanEngine(&v, bad)
		if v.Validate(now) == nil {
			t.Fatal("policy accepted null/XOR/noninteger profile")
		}
	}
}
