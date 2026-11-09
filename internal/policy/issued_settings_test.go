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
