package chatweb

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
)

func TestGroupReviewChecksEffectivePlansAndNeverFetchesPrivateResources(t *testing.T) {
	raw, err := os.ReadFile("../../docs/examples/first-device-reference-plans.json")
	if err != nil {
		t.Fatal(err)
	}
	var plans map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	template := configuration.Layer{ID: "template-a", Kind: "template", Revision: 1}
	for _, field := range []string{"schemaVersion", "graph", "network", "activation"} {
		template.Changes = append(template.Changes, configuration.Change{Path: "/" + field, Operation: "set", Value: plans["personal"][field]})
	}
	// The second device replaces inherited private routes and DNS.
	override := configuration.Layer{ID: "device-b", Kind: "device", Revision: 1}
	for _, field := range []string{"graph", "network"} {
		override.Changes = append(override.Changes, configuration.Change{Path: "/" + field, Operation: "set", Value: plans["invited"][field]})
	}
	bundles := []configuration.LayerBundle{
		{Device: "device-a", Layers: []configuration.Layer{template}},
		{Device: "device-b", Layers: []configuration.Layer{template, override}},
	}
	var manifest []struct{ Device, Hash string }
	for _, bundle := range bundles {
		effective, _, err := configuration.MergeNetworkPlan(context.Background(), bundle.Layers)
		if err != nil {
			t.Fatal(err)
		}
		manifest = append(manifest, struct{ Device, Hash string }{bundle.Device, fmt.Sprintf("%x", sha256.Sum256(effective.Document))})
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	body := func(hash string) string {
		payload, err := json.Marshal(map[string]any{"bundles": bundles, "effectiveHash": hash})
		if err != nil {
			t.Fatal(err)
		}
		return string(payload)
	}
	s, _, principal := webFixture(t)
	const path = "/control/group-network-impact"
	chat := loginWeb(t, s)
	if got := webCall(s, path, body(digest), chat); got.Code != 404 {
		t.Fatal("available in user chat", got.Code)
	}
	s.config.ControlConsole = true
	principal.Scope = "syn443.control"
	session := loginWeb(t, s)
	s.client.Transport = consoleTransportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected upstream request"); return nil, nil })
	got := webCall(s, path, body(digest), session)
	want := `{"effectiveHash":"` + digest + `","recipients":[{"device":"device-a","netbird":true,"overlayDns":true,"homeProof":false},{"device":"device-b","netbird":false,"overlayDns":false,"homeProof":false}]}`
	if got.Code != 200 || strings.TrimSpace(got.Body.String()) != want {
		t.Fatalf("incorrect projection: %d %s", got.Code, got.Body.String())
	}
	if got := webCall(s, path, body(strings.Repeat("a", 64)), session); got.Code != 400 {
		t.Fatal("mismatched manifest", got.Code)
	}
	bundles[1].Layers = []configuration.Layer{template}
	if got := webCall(s, path, body(digest), session); got.Code != 400 {
		t.Fatal("changed effective plan", got.Code)
	}
	if got := webCall(s, path, body(digest), nil); got.Code != 401 {
		t.Fatal("missing session", got.Code)
	}
	s.sessions[session.Value].principal.Scope = "openid"
	if got := webCall(s, path, body(digest), session); got.Code != 403 {
		t.Fatal("missing control scope", got.Code)
	}
}
