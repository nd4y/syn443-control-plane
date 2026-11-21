package policy

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestConsoleSettingsProjectsOnlyCredentialFreeFields(t *testing.T) {
	payload := Payload{
		Operation: "configure", Revision: 21, AlgorithmRevision: BaselineAlgorithm,
		EngineConfigB64: base64.RawURLEncoding.EncodeToString([]byte(
			"{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"proxy\",\"server\":\"server.example.invalid\",\"uuid\":\"synthetic-value\",\"tls\":{\"password\":\"synthetic-password\"}},{\"type\":\"selector\",\"tag\":\"select\",\"outbounds\":[\"proxy\"],\"default\":\"proxy\"}],\"route\":{\"final\":\"select\",\"rules\":[{\"domain\":[\"rule.example.invalid\"]}]},\"dns\":{\"final\":\"system\"}}")),
		Activation: Gate{TimeoutSeconds: 60, Checks: []Check{{Type: "https_204", Target: "https://example.invalid/synthetic", Required: true}}},
	}
	view := payload.ConsoleSettings()
	if view == nil || view.Revision != 21 || view.RouteFinal != "select" || view.RouteRuleCount != 1 ||
		view.DNSFinal != "system" || len(view.Outbounds) != 2 || view.Outbounds[1].Default != "proxy" ||
		len(view.Activation.Checks) != 1 || !view.Activation.Checks[0].Required {
		t.Fatalf("incorrect safe policy fields: %+v", view)
	}
	raw, err := json.Marshal(view)
	if err != nil || strings.Contains(string(raw), "synthetic") || strings.Contains(string(raw), "example.invalid") {
		t.Fatal("policy projection exposed private engine or check fields")
	}
	payload.Operation = "release"
	if payload.ConsoleSettings() != nil {
		t.Fatal("release policy exposed native settings")
	}
}

func TestIssuedNetBirdProjectsOnlyExplicitTransportAndManagedNamespace(t *testing.T) {
	project := func(outbounds string) *IssuedSettings {
		t.Helper()
		p := Payload{Operation: "configure", EngineConfigB64: base64.RawURLEncoding.EncodeToString([]byte(`{"outbounds":[` + outbounds + `]}`))}
		view := p.ConsoleSettings()
		if view == nil {
			t.Fatal("lost existing inventory")
		}
		return view
	}
	const authorized = `"type":"netbird","tag":"mesh","management_url":"https://secret.example.invalid","hostname":"private-fixture"`
	const managed = `,"managed":{"overlayId":"overlay-a","networkId":"network-a","resourceId":"resource-a","setupReference":"private-fixture","identityEpoch":7,"setupVersion":1}`
	for _, tc := range []struct{ fields, mode string }{
		{`"connection_mode":"direct"`, "direct"},
		{`"connection_mode":"vless","detour":"entry"`, "vless"},
	} {
		view := project(`{"type":"vless","tag":"entry"},{` + authorized + "," + tc.fields + managed + "}")
		if view.NetBird == nil || *view.NetBird != (IssuedOverlay{Tag: "mesh", Transport: tc.mode, OverlayID: "overlay-a", ResourceID: "resource-a", NetworkID: "network-a"}) {
			t.Fatal("missing public projection", tc.mode)
		}
		raw, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"private-fixture", "example.invalid", "setupReference", "identityEpoch", "management_url", "setupVersion"} {
			if strings.Contains(string(raw), bad) {
				t.Fatal("unexpected field", bad)
			}
		}
	}
	for _, body := range []string{
		"{" + authorized + "}",
		"{" + authorized + `,"connection_mode":"vless"}`,
		"{" + authorized + `,"connection_mode":{},"managed":"unrelated"}`,
		"{" + authorized + `,"connection_mode":"direct","managed":false}`,
		`{"type":"vless","tag":"entry","managed":"vendor-metadata"}`,
		"{" + authorized + `,"connection_mode":"direct","detour":"entry"}`,
		"{" + authorized + `,"connection_mode":"vless","detour":"mesh"}`,
		"{" + authorized + `,"connection_mode":"direct","managed":{"networkId":"network-a","resourceId":"unsafe.example.invalid"}}`,
		"{" + authorized + `,"connection_mode":"direct"},{"type":"netbird","tag":"mesh-b","connection_mode":"direct"}`,
		`{"type":"vless","tag":"entry","connection_mode":"direct","netbird":{"tag":"entry","transport":"direct"}}`,
	} {
		if project(body).NetBird != nil {
			t.Fatal("invented a managed network or transport")
		}
	}
	if view := project("{" + authorized + `,"connection_mode":"direct"}`); view.NetBird == nil || view.NetBird.NetworkID != "" {
		t.Fatal("unmanaged connection acquired a network")
	}
}
