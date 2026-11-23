package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func TestFirstDeviceReferencePlansCompileWithRecipientScopedResources(t *testing.T) {
	raw, err := os.ReadFile("../../docs/examples/first-device-reference-plans.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples map[string]json.RawMessage
	if err := json.Unmarshal(raw, &examples); err != nil || len(examples) != 2 {
		t.Fatal("expected two reference plans", err)
	}
	for _, name := range []string{"invited", "personal"} {
		t.Run(name, func(t *testing.T) {
			plan, err := DecodeNetworkPlan(examples[name])
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			compiled, err := CompileNetworkPlan(context.Background(), plan, func(ref ProfileReference) (subscriptions.Profile, error) {
				calls++
				if ref != graphRef("vless") {
					t.Fatal("unexpected profile dependency")
				}
				return defaultGraphResolver()(ref)
			})
			if err != nil || calls != 1 {
				t.Fatal("profile resolution", calls, err)
			}
			var wire struct {
				Route struct {
					Final string
					Rules []map[string]any
				}
				DNS struct {
					Final   string
					Rules   []map[string]any
					Servers []map[string]any
				}
				Outbounds []map[string]any
			}
			if err := json.Unmarshal(compiled.EngineConfig, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.Route.Final != "internet" || wire.DNS.Final != "resolver" || len(compiled.Activation.Checks) != 1 || !compiled.Activation.Checks[0].Required {
				t.Fatal("default route, DNS or activation check changed")
			}
			dns := map[string]map[string]any{}
			for _, server := range wire.DNS.Servers {
				dns[server["tag"].(string)] = server
			}
			if dns["resolver"]["type"] != "tls" || dns["resolver"]["detour"] != "internet" {
				t.Fatal("resolver escaped its assigned proxy")
			}
			var overlay map[string]any
			for _, node := range wire.Outbounds {
				if node["type"] == "netbird" {
					overlay = node
				}
			}
			if name == "invited" {
				if overlay != nil || dns["home"] != nil || len(wire.DNS.Rules) != 0 || len(wire.Route.Rules) != 0 || bytes.Contains(compiled.EngineConfig, []byte("home.example.invalid")) {
					t.Fatal("invited plan includes private dependencies")
				}
			} else if overlay["connection_mode"] != "direct" || overlay["detour"] != nil || dns["home"]["outbound"] != "home" ||
				len(wire.DNS.Rules) != 1 || wire.DNS.Rules[0]["server"] != "home" ||
				len(wire.Route.Rules) != 1 || wire.Route.Rules[0]["outbound"] != "home" {
				t.Fatal("private overlay, DNS or routing binding changed")
			}
			if _, err := CompileNetworkPlan(context.Background(), plan, func(ProfileReference) (subscriptions.Profile, error) {
				return subscriptions.Profile{}, ErrInvalid
			}); err == nil {
				t.Fatal("unassigned source accepted")
			}
		})
	}
}
