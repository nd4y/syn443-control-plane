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
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func adaptivePolicyFixture(t *testing.T) (policy.Payload, time.Time) {
	t.Helper()
	metadata, _ := json.Marshal(map[string]any{"schemaVersion": 1,
		"hops": []any{map[string]any{"id": "hop", "entryModes": []string{"WIFI"}, "exitClass": "PUBLIC", "features": []string{"TCP"}}}, "edges": []any{},
		"templates": []any{map[string]any{"id": "single", "slots": [][]string{{"hop"}}}},
		"groups":    []any{map[string]any{"id": "external", "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"single"}}}})
	bindings, _ := json.Marshal(map[string]map[string]string{"hop": {"profileId": "source_profile", "sourceId": "source-a"}})
	plan := configuration.NetworkPlan{SchemaVersion: 1, Graph: configuration.Graph{Final: "managed"},
		Network:    configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4", RouteChecks: []configuration.OutboundCheckPlan{{Outbound: "managed", Checks: []configuration.OutboundCheck{{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "NON_RU"}}}}},
		Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.invalid/generate_204", Required: true}}},
		Adaptive:   &configuration.AdaptivePlan{MetadataB64: base64.RawURLEncoding.EncodeToString(metadata), BindingsB64: base64.RawURLEncoding.EncodeToString(bindings), Groups: map[string]string{"external": "managed"}}}
	compiled, err := configuration.CompileNetworkPlan(context.Background(), plan, func(ref configuration.ProfileReference) (subscriptions.Profile, error) {
		if ref.SourceID != "source-a" || ref.ProfileID != "source_profile" {
			return subscriptions.Profile{}, configuration.ErrInvalid
		}
		return subscriptions.Profile{ID: ref.ProfileID, Kind: "http", Outbound: json.RawMessage(`{"type":"http","tag":"source_profile","server":"proxy.example.invalid","server_port":443}`)}, nil
	})
	if err != nil {
		t.Fatal("actual adaptive compiler fixture", err)
	}
	now := time.Unix(1800000000, 0)
	payload := policy.Payload{SchemaVersion: 2, Operation: "configure", Revision: 3, TargetDevice: "synthetic-device", Audience: "syn443-device", KeyThumbprint: identity.Hash([]byte("synthetic-device-key")),
		IssuedAtMs: now.UnixMilli(), NotBeforeMs: now.UnixMilli(), RefreshAfterMs: now.Add(30 * time.Second).UnixMilli(), OfflineUntilMs: now.Add(time.Minute).UnixMilli(),
		RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", policy.RouteDecision, policy.RouteAdaptiveTCP, policy.RouteExitCountry},
		AlgorithmRevision:    compiled.AlgorithmRevision, EngineConfigB64: base64.RawURLEncoding.EncodeToString(compiled.EngineConfig), ContentHash: compiled.ContentHash, Activation: compiled.Activation}
	return payload, now
}

func replaceAdaptivePolicyEngine(t *testing.T, payload *policy.Payload, change func(map[string]any)) {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(payload.EngineConfigB64)
	var root map[string]any
	if err != nil || json.Unmarshal(raw, &root) != nil {
		t.Fatal("invalid engine fixture")
	}
	change(root)
	raw, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	payload.EngineConfigB64, payload.ContentHash = base64.RawURLEncoding.EncodeToString(raw), hex.EncodeToString(sum[:])
}

func TestAdaptivePolicyBindsActualCompilerAlgorithmCapabilityAndDeviceKey(t *testing.T) {
	payload, now := adaptivePolicyFixture(t)
	if payload.AlgorithmRevision != policy.AdaptiveTCPAlgorithm || payload.Validate(now) != nil {
		t.Fatal("actual compiler output lacks its negotiated evaluator")
	}
	root, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(payload)
	envelope, err := policy.Sign(raw, "fixture-root", root, payload.TargetDevice, payload.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*ecdsa.PublicKey{"fixture-root": &root.PublicKey}
	verified, err := policy.VerifyBound(envelope, keys, payload.TargetDevice, payload.KeyThumbprint, now)
	if err != nil || verified.ContentHash != payload.ContentHash || verified.AlgorithmRevision != policy.AdaptiveTCPAlgorithm {
		t.Fatal("signed adaptive bytes or evaluator changed", err)
	}
	if _, err := policy.VerifyBound(envelope, keys, payload.TargetDevice, identity.Hash([]byte("another-device-key")), now); err == nil {
		t.Fatal("adaptive publication accepted another device key")
	}
}

func TestAdaptivePolicyRequiresExactEnvelopeCapabilitySchemaAndConfigureScope(t *testing.T) {
	for _, change := range []func(*policy.Payload){
		func(p *policy.Payload) { p.Operation = "release" },
		func(p *policy.Payload) { p.AlgorithmRevision = policy.BaselineAlgorithm },
		func(p *policy.Payload) { p.AlgorithmRevision = policy.ConfirmedFailoverAlgorithm },
		func(p *policy.Payload) { p.AlgorithmRevision = "m4-graph-tcp-v2" },
		func(p *policy.Payload) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == policy.RouteAdaptiveTCP })
		},
		func(p *policy.Payload) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == policy.RouteDecision })
		},
		func(p *policy.Payload) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == policy.RouteExitCountry })
		},
		func(p *policy.Payload) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == "route.health.v1" })
		},
		func(p *policy.Payload) {
			p.RequiredCapabilities = append(p.RequiredCapabilities, policy.RouteAdaptiveTCP)
		},
		func(p *policy.Payload) { p.RequiredCapabilities = append(p.RequiredCapabilities, "route.failover.v1") },
		func(p *policy.Payload) {
			p.RequiredCapabilities = append(p.RequiredCapabilities, policy.ReserveProbeCooldown)
		},
		func(p *policy.Payload) {
			p.SchemaVersion, p.KeyThumbprint = 1, ""
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == "policy.keybound.v2" })
		},
		func(p *policy.Payload) {
			replaceAdaptivePolicyEngine(t, p, func(root map[string]any) { delete(root, "adaptive_routes") })
		},
		func(p *policy.Payload) {
			replaceAdaptivePolicyEngine(t, p, func(root map[string]any) { root["adaptive_routes"] = nil })
		},
		func(p *policy.Payload) {
			replaceAdaptivePolicyEngine(t, p, func(root map[string]any) { root["route_failover"] = map[string]any{} })
		},
		func(p *policy.Payload) {
			replaceAdaptivePolicyEngine(t, p, func(root map[string]any) { root["route_failover"] = nil })
		},
	} {
		payload, now := adaptivePolicyFixture(t)
		change(&payload)
		if payload.Validate(now) == nil {
			t.Fatal("adaptive policy escaped exact capability, algorithm or legacy-failover exclusion")
		}
	}
	payload, now := adaptivePolicyFixture(t)
	replaceAdaptivePolicyEngine(t, &payload, func(root map[string]any) {
		delete(root, "adaptive_routes")
		root["outbounds"] = []any{map[string]any{"type": "direct", "tag": "direct"}}
		root["route"] = map[string]any{"final": "direct"}
		root["route_checks"].([]any)[0].(map[string]any)["outbound"] = "direct"
	})
	payload.RequiredCapabilities = slices.DeleteFunc(payload.RequiredCapabilities, func(c string) bool { return c == policy.RouteDecision || c == policy.RouteAdaptiveTCP })
	payload.AlgorithmRevision = policy.BaselineAlgorithm
	if err := payload.Validate(now); err != nil {
		t.Fatal("ordinary baseline policy with its own country check was changed", err)
	}
}
