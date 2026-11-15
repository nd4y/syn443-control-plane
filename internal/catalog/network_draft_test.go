package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func draftExample() NetworkDraft {
	return NetworkDraft{ID: "draft-a", TargetKind: "device", TargetID: "device-a", Plan: configuration.NetworkPlan{SchemaVersion: 1,
		Graph:      configuration.Graph{Profiles: map[string]configuration.ProfileReference{}, Chains: map[string]configuration.Chain{}, Balancers: map[string]configuration.Balancer{}, Final: "direct"},
		Network:    configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp", "udp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4"},
		Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://private-health.example.invalid/generate_204", Required: true}}}}}
}

func TestNetworkDraftBoundsScopeAndDeclaredBaseAreClosedButNotPublication(t *testing.T) {
	base := draftExample()
	if base.validate() != nil || strings.Contains(base.String(), "private-health") || strings.Contains(base.GoString(), "private-health") {
		t.Fatal("valid bounded draft/redaction")
	}
	for _, kind := range []string{"template", "group", "user", "device"} {
		draft := base
		draft.TargetKind = kind
		draft.BaseRevision = 4
		draft.BaseHash = strings.Repeat("a", 64)
		if draft.validate() != nil {
			t.Fatal("supported explicit target/base rejected")
		}
	}
	for _, change := range []func(*NetworkDraft){
		func(d *NetworkDraft) { d.ID = "../other" }, func(d *NetworkDraft) { d.TargetID = "" },
		func(d *NetworkDraft) { d.TargetKind = "*" }, func(d *NetworkDraft) { d.Revision = -1 },
		func(d *NetworkDraft) { d.Revision = 9007199254740992 }, func(d *NetworkDraft) { d.BaseRevision = -1 },
		func(d *NetworkDraft) { d.BaseRevision = 9007199254740992 }, func(d *NetworkDraft) { d.BaseHash = strings.Repeat("a", 64) },
		func(d *NetworkDraft) { d.BaseRevision = 1 }, func(d *NetworkDraft) { d.BaseRevision = 1; d.BaseHash = strings.Repeat("A", 64) },
		func(d *NetworkDraft) { d.BaseRevision = 1; d.BaseHash = strings.Repeat("z", 64) },
		func(d *NetworkDraft) { d.Plan.SchemaVersion = 2 },
	} {
		raw, _ := json.Marshal(base)
		var draft NetworkDraft
		json.Unmarshal(raw, &draft)
		change(&draft)
		if draft.validate() == nil {
			t.Fatal("invalid scope/base/shape accepted")
		}
	}
	// An incomplete reference can be saved, never independently compiled/signed.
	base.Plan.Graph.Final = "unresolved"
	if base.validate() != nil {
		t.Fatal("draft cannot retain an incomplete edit")
	}
}
