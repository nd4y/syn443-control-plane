package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func compiledAdaptivePreparation(t *testing.T) (*PreparedConfiguration, policy.Payload, time.Time) {
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
		t.Fatal("actual adaptive compiler fixture failed", err)
	}
	payload, now := configuredPayload()
	return &PreparedConfiguration{EngineConfig: compiled.EngineConfig, Activation: compiled.Activation, AlgorithmRevision: compiled.AlgorithmRevision,
		RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", policy.RouteDecision, policy.RouteAdaptiveTCP, policy.RouteExitCountry},
		UntilMs:              now.Add(time.Minute).UnixMilli(), Fence: &fixtureConfigurationFence{}, Source: ConfigurationSource{Revision: 2, Hash: strings.Repeat("a", 64)}}, payload, now
}

func mutateAdaptivePreparedEngine(t *testing.T, prepared *PreparedConfiguration, change func(map[string]any, map[string]any)) {
	t.Helper()
	var root map[string]any
	if json.Unmarshal(prepared.EngineConfig, &root) != nil {
		t.Fatal("invalid fixture engine")
	}
	wire := root["adaptive_routes"].(map[string]any)
	change(root, wire)
	prepared.EngineConfig, _ = json.Marshal(root)
}

func TestPreparedAdaptiveConfigurationUsesActualCompilerAndPreservesDeviceKeyAndLease(t *testing.T) {
	prepared, payload, now := compiledAdaptivePreparation(t)
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload.KeyThumbprint, err = identity.PublicJWK(&deviceKey.PublicKey).Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	before := payload
	if err := applyPreparedConfiguration(&payload, prepared, prepared.RequiredCapabilities, now); err != nil {
		t.Fatal("actual compiler output was not accepted by independent issuer validation", err)
	}
	if payload.TargetDevice != before.TargetDevice || payload.KeyThumbprint != before.KeyThumbprint || payload.Revision != before.Revision || payload.SecurityEpoch != before.SecurityEpoch || payload.RevocationFloor != before.RevocationFloor || payload.Audience != before.Audience || payload.AlgorithmRevision != policy.AdaptiveTCPAlgorithm || payload.OfflineUntilMs != prepared.UntilMs {
		t.Fatal("adaptive callback replaced recipient/key/revision or extended the permit")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(payload.EngineConfigB64)
	if err != nil || !bytes.Equal(raw, prepared.EngineConfig) || payload.Validate(now) != nil {
		t.Fatal("accepted policy did not bind exact compiler bytes", err)
	}
	root, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(payload)
	envelope, err := policy.Sign(data, "fixture-root", root, payload.TargetDevice, payload.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*ecdsa.PublicKey{"fixture-root": &root.PublicKey}
	if _, err := policy.VerifyBound(envelope, keys, payload.TargetDevice, before.KeyThumbprint, now); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.VerifyBound(envelope, keys, payload.TargetDevice, identity.Hash([]byte("another-key")), now); err == nil {
		t.Fatal("accepted envelope can be delivered under another device key")
	}
	prepared.Activation.Checks[0].Target = "https://changed.example.invalid/"
	copy(prepared.EngineConfig, bytes.Repeat([]byte{'!'}, len(prepared.EngineConfig)))
	prepared.RequiredCapabilities[0] = "changed.v1"
	if payload.Activation.Checks[0].Target == prepared.Activation.Checks[0].Target || !bytes.Equal(raw, mustDecodeAdaptiveEngine(t, payload.EngineConfigB64)) || payload.RequiredCapabilities[0] != "engine-config.v1" {
		t.Fatal("issuer retained mutable callback buffers or capabilities")
	}
}

func mustDecodeAdaptiveEngine(t *testing.T, raw string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestPreparedAdaptiveConfigurationCannotBypassIndependentWireAndSourceFences(t *testing.T) {
	for _, mutate := range []func(*PreparedConfiguration){
		func(p *PreparedConfiguration) { p.Fence = nil },
		func(p *PreparedConfiguration) { p.Source = ConfigurationSource{Revision: 2} },
		func(p *PreparedConfiguration) {
			p.Source = ConfigurationSource{Revision: -1, Hash: strings.Repeat("a", 64)}
		},
		func(p *PreparedConfiguration) {
			p.Source = ConfigurationSource{Revision: 2, Hash: strings.Repeat("A", 64)}
		},
		func(p *PreparedConfiguration) { p.AlgorithmRevision = "" },
		func(p *PreparedConfiguration) { p.AlgorithmRevision = policy.ConfirmedFailoverAlgorithm },
		func(p *PreparedConfiguration) { p.AlgorithmRevision = "external-program" },
		func(p *PreparedConfiguration) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == policy.RouteAdaptiveTCP })
		},
		func(p *PreparedConfiguration) {
			p.RequiredCapabilities = slices.DeleteFunc(p.RequiredCapabilities, func(c string) bool { return c == policy.RouteDecision })
		},
		func(p *PreparedConfiguration) {
			p.RequiredCapabilities = append(p.RequiredCapabilities, policy.RouteAdaptiveTCP)
		},
		func(p *PreparedConfiguration) {
			p.RequiredCapabilities = append(p.RequiredCapabilities, make([]string, 17)...)
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(root, _ map[string]any) { delete(root, "adaptive_routes") })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(root, _ map[string]any) { root["adaptive_routes"] = nil })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(root, _ map[string]any) { root["route_failover"] = map[string]any{} })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(root, _ map[string]any) { root["targetDevice"] = "foreign-device" })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(_, wire map[string]any) {
				wire["catalogueB64"] = base64.RawURLEncoding.EncodeToString([]byte(`{}`))
			})
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(_, wire map[string]any) { wire["groups"] = map[string]any{"external": "direct"} })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(root, _ map[string]any) { root["outbounds"].([]any)[1].(map[string]any)["detour"] = "direct" })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(root, _ map[string]any) { root["outbounds"].([]any)[1].(map[string]any)["group"] = "other" })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(root, _ map[string]any) { root["route_checks"].([]any)[0].(map[string]any)["outbound"] = "direct" })
		},
		func(p *PreparedConfiguration) {
			mutateAdaptivePreparedEngine(t, p, func(_, wire map[string]any) {
				raw := mustDecodeAdaptiveEngine(t, wire["catalogueB64"].(string))
				var nodes map[string]any
				json.Unmarshal(raw, &nodes)
				nodes["hop"].(map[string]any)["detour"] = "direct"
				changed, _ := json.Marshal(nodes)
				wire["catalogueB64"] = base64.RawURLEncoding.EncodeToString(changed)
			})
		},
	} {
		prepared, payload, now := compiledAdaptivePreparation(t)
		before, _ := json.Marshal(payload)
		available := append([]string(nil), prepared.RequiredCapabilities...)
		mutate(prepared)
		if err := applyPreparedConfiguration(&payload, prepared, available, now); err == nil {
			t.Fatal("forged callback bypassed source/scope/algorithm or independent raw-wire validation")
		}
		after, _ := json.Marshal(payload)
		if !bytes.Equal(before, after) {
			t.Fatal("rejected adaptive callback partially changed the candidate")
		}
	}
}

func TestPreparedAdaptiveConfigurationNeedsNegotiationAndCannotBecomeSharedGrant(t *testing.T) {
	prepared, payload, now := compiledAdaptivePreparation(t)
	for _, missing := range []string{policy.RouteAdaptiveTCP, policy.RouteDecision, policy.RouteExitCountry, "route.health.v1", "policy.keybound.v2"} {
		available := slices.DeleteFunc(append([]string(nil), prepared.RequiredCapabilities...), func(c string) bool { return c == missing })
		candidate := payload
		candidate.RequiredCapabilities = append([]string(nil), payload.RequiredCapabilities...)
		if err := applyPreparedConfiguration(&candidate, prepared, available, now); err == nil || !reflect.DeepEqual(candidate, payload) {
			t.Fatal("missing primitive availability was inferred or changed the candidate", missing, err)
		}
	}
	if err := applyPreparedConfiguration(&payload, prepared, prepared.RequiredCapabilities, now); err != nil {
		t.Fatal(err)
	}
	payload.KeyThumbprint = ""
	grant := Grant{Issuer: "https://identity.example.invalid/realms/test", Subject: "synthetic-user", DeviceLimit: 2, Until: now.Add(time.Hour).Unix(), Template: payload}
	if err := grant.Validate(now); err == nil {
		t.Fatal("a shared grant bypassed addressed adaptive approval")
	}
	if err := applyPreparedConfiguration(nil, prepared, prepared.RequiredCapabilities, now); err == nil {
		t.Fatal("nil candidate accepted")
	}
}
