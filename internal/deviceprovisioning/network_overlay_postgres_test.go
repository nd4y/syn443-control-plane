//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

func TestSQLApprovedNetworkNetBirdRequiresAdvertisedCredentialModuleAndRetainsSourceFence(t *testing.T) {
	n := newNetworkFixture(t)
	found := false
	for i, change := range n.approved.Layers[0].Changes {
		if change.Path != "/graph" {
			continue
		}
		var graph configuration.Graph
		if json.Unmarshal(change.Value, &graph) != nil {
			t.Fatal("fixture graph")
		}
		graph.NetBird = &configuration.NetBirdNode{Tag: "home", OverlayID: "home", ResourceID: "overlay-resource", NetworkID: "tenant", IdentityEpoch: 1, ManagementURL: "https://overlay.example.invalid", Mode: "direct"}
		graph.Final = "home"
		raw, e := json.Marshal(graph)
		if e != nil {
			t.Fatal(e)
		}
		n.approved.Layers[0].Changes[i].Value = raw
		found = true
	}
	if !found {
		t.Fatal("fixture graph layer missing")
	}
	if _, e := n.authority.Prepare(context.Background(), n.target, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("unadvertised overlay credentials accepted", e)
	}
	target := n.target
	target.Capabilities = append(append([]string(nil), target.Capabilities...), "overlay.credentials.v1")
	approved := *n.approved
	approved.Target = target
	authority := *n.authority
	authority.Layers = networkLayersFunc(func(_ context.Context, actual enrollment.ConfigurationTarget, _ time.Time) (*ApprovedNetworkLayers, error) {
		if !sameNetworkTarget(actual, target) {
			t.Fatal("independent recipient/capability substitution")
		}
		return &approved, nil
	})
	prepared, e := authority.Prepare(context.Background(), target, n.f.now)
	if e != nil || !slices.Contains(prepared.RequiredCapabilities, "overlay.credentials.v1") || !bytes.Contains(prepared.EngineConfig, []byte(`"type":"netbird"`)) || bytes.Contains(prepared.EngineConfig, []byte(`"setup_key"`)) {
		t.Fatal("typed overlay capability handoff", e)
	}
	if prepared.UntilMs != n.f.now.Add(time.Hour).UnixMilli() {
		t.Fatal("overlay bypassed shorter source freshness")
	}
	tx, e := fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = prepared.Fence.Lock(context.Background(), tx, n.f.now); e != nil {
		t.Fatal("composed source/layer fence", e)
	}
	// This component test advertises capabilities at the independent reader
	// boundary. Actual enrolled capability/broker publication is separately
	// required by TestSQLPortableNetBirdPublicationRequiresBrokerAndKeepsIdentityAcrossEmergencyTransport.
}
