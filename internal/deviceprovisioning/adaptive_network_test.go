package deviceprovisioning

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func adaptiveAuthorityPlan(t *testing.T, refs []configuration.ProfileReference) configuration.NetworkPlan {
	t.Helper()
	hops, ids := []any{}, []string{}
	bindings := map[string]map[string]string{}
	for i, ref := range refs {
		hop := fmt.Sprintf("hop-%03d", i)
		hops = append(hops, map[string]any{"id": hop, "entryModes": []string{"WIFI"}, "exitClass": "PUBLIC", "features": []string{"TCP"}})
		ids = append(ids, hop)
		bindings[hop] = map[string]string{"profileId": ref.ProfileID, "sourceId": ref.SourceID}
	}
	metadata, _ := json.Marshal(map[string]any{"schemaVersion": 1, "hops": hops, "edges": []any{}, "templates": []any{map[string]any{"id": "single", "slots": [][]string{ids}}},
		"groups": []any{map[string]any{"id": "public", "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"single"}}}})
	rawBindings, _ := json.Marshal(bindings)
	return configuration.NetworkPlan{SchemaVersion: 1,
		Graph:      configuration.Graph{Profiles: map[string]configuration.ProfileReference{}, Chains: map[string]configuration.Chain{}, Balancers: map[string]configuration.Balancer{}, Final: "managed-public"},
		Network:    configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4", RouteChecks: []configuration.OutboundCheckPlan{{Outbound: "managed-public", Checks: []configuration.OutboundCheck{{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "NON_RU"}}}}},
		Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.invalid/generate_204", Required: true}}},
		Adaptive:   &configuration.AdaptivePlan{MetadataB64: base64.RawURLEncoding.EncodeToString(metadata), BindingsB64: base64.RawURLEncoding.EncodeToString(rawBindings), Groups: map[string]string{"public": "managed-public"}}}
}

func adaptiveAuthorityCapabilities() []string {
	return []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", policy.RouteDecision, adaptiveNetworkCapability, policy.RouteExitCountry}
}

func TestAdaptiveNetworkReferenceUnionOwnsSortsAndDeduplicates500Plus32(t *testing.T) {
	bindings := make([]configuration.ProfileReference, 500)
	for i := range bindings {
		bindings[i] = configuration.ProfileReference{SourceID: "source-z", ProfileID: fmt.Sprintf("profile-%03d", i)}
	}
	plan := adaptiveAuthorityPlan(t, bindings)
	for i := 0; i < 32; i++ {
		plan.Graph.Profiles[fmt.Sprintf("static-%02d", i)] = configuration.ProfileReference{SourceID: "source-a", ProfileID: fmt.Sprintf("static-%02d", i)}
	}
	refs, err := networkSelectionReferences(plan)
	if err != nil || len(refs) != 532 || refs[0].SourceID != "source-a" || refs[531].ProfileID != "profile-499" {
		t.Fatal("source selection omitted or failed to sort the full union", err)
	}
	plan.Graph.Profiles["static-00"] = bindings[0]
	shared, err := networkSelectionReferences(plan)
	if err != nil || len(shared) != 531 {
		t.Fatal("static/adaptive source alias was resolved twice", err)
	}
	plan.Graph.Profiles["static-00"] = configuration.ProfileReference{SourceID: "changed-source", ProfileID: "changed-profile"}
	if refs[0].SourceID != "source-a" || shared[0].SourceID != "source-a" {
		t.Fatal("draft mutation altered an owned selection request")
	}
	plan.Graph.Profiles["static-extra"] = configuration.ProfileReference{SourceID: "source-a", ProfileID: "extra"}
	if refs, err := networkSelectionReferences(plan); err == nil || refs != nil {
		t.Fatal("adaptive union hid an oversized ordinary graph")
	}
	plan = adaptiveAuthorityPlan(t, bindings[:1])
	plan.Adaptive.BindingsB64 += "="
	if refs, err := networkSelectionReferences(plan); err == nil || refs != nil {
		t.Fatal("invalid adaptive bindings fell back to static-only sources")
	}
	plan.Adaptive = nil
	plan.Graph.Profiles["one"], plan.Graph.Profiles["alias"] = bindings[0], bindings[0]
	if ordinary, err := networkSelectionReferences(plan); err != nil || len(ordinary) != 1 {
		t.Fatal("ordinary alias deduplication changed", err)
	}
}

func TestAdaptiveNetworkRequiresActualPrimitiveDecisionKeyAndProbeAvailability(t *testing.T) {
	plan := adaptiveAuthorityPlan(t, []configuration.ProfileReference{{SourceID: "source-a", ProfileID: "profile-a"}})
	target := enrollment.ConfigurationTarget{Capabilities: adaptiveAuthorityCapabilities()}
	if err := adaptiveNetworkAvailable(plan, target); err != nil {
		t.Fatal(err)
	}
	for _, required := range adaptiveAuthorityCapabilities() {
		old := target
		old.Capabilities = slices.DeleteFunc(append([]string(nil), target.Capabilities...), func(c string) bool { return c == required })
		if err := adaptiveNetworkAvailable(plan, old); !errors.Is(err, enrollment.ErrDenied) {
			t.Fatal("unadvertised capability was inferred from the plan or grant", required, err)
		}
	}
	plan.Network.RouteChecks[0].Checks = append(plan.Network.RouteChecks[0].Checks, configuration.OutboundCheck{Method: "https_exit_ip", Target: "https://health.example.invalid/address", ExpectedIP: "192.0.2.9"})
	if err := adaptiveNetworkAvailable(plan, target); !errors.Is(err, enrollment.ErrDenied) {
		t.Fatal("country support substituted fixed-IP support", err)
	}
	target.Capabilities = append(target.Capabilities, policy.RouteExitIP)
	if err := adaptiveNetworkAvailable(plan, target); err != nil {
		t.Fatal(err)
	}
	zero := 0
	plan.Network.RouteFailover = &configuration.RouteFailoverPlan{Selector: "managed-public", NetworkMode: "wifi", Intent: "INTERNAL", DecisionRevision: policy.ConfirmedFailoverAlgorithm, DecisionRollout: &configuration.DeviceRollout{ID: "disabled-cohort", BasisPoints: &zero}}
	if err := adaptiveNetworkAvailable(plan, target); !errors.Is(err, configuration.ErrInvalid) {
		t.Fatal("legacy zero-percent rollout overrode the adaptive algorithm", err)
	}
	plan.Adaptive = nil
	if err := adaptiveNetworkAvailable(plan, enrollment.ConfigurationTarget{}); err != nil {
		t.Fatal("ordinary capability/rollout path was changed", err)
	}
}

func TestHomeProofRequiresAnAdaptivePlanAndAnIndependentlyCapableTarget(t *testing.T) {
	plan := adaptiveAuthorityPlan(t, []configuration.ProfileReference{{SourceID: "src", ProfileID: "one"}})
	target := enrollment.ConfigurationTarget{Capabilities: adaptiveAuthorityCapabilities()}
	plan.Network.HomeProof = &policy.HomeProof{}
	if err := adaptiveNetworkAvailable(plan, target); err != enrollment.ErrDenied {
		t.Fatal("incapable target accepted", err)
	}
	target.Capabilities = append(target.Capabilities, policy.HomeWiFiProof)
	if err := adaptiveNetworkAvailable(plan, target); err != nil {
		t.Fatal("capable target rejected", err)
	}
	plan.Adaptive = nil
	if err := adaptiveNetworkAvailable(plan, target); err != configuration.ErrInvalid {
		t.Fatal("non-adaptive policy accepted proof", err)
	}
}
