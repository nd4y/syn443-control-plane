package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func checkPlanPreparation(t *testing.T) (*PreparedConfiguration, policy.Payload, time.Time) {
	t.Helper()
	prepared, p, now := configuredPreparation(t)
	graph, e := configuration.CompileGraph(configuration.Graph{Profiles: map[string]configuration.ProfileReference{}, Chains: map[string]configuration.Chain{}, Balancers: map[string]configuration.Balancer{}, Final: "direct"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	profile := &configuration.OutboundCheckProfile{SchemaVersion: 2, ID: "health", Revision: 1, DeadlineMs: 12000, Leaves: []configuration.OutboundCheckLeaf{{ID: "a", Check: configuration.OutboundCheck{Method: "tcp", Target: "a.example.invalid:443"}}, {ID: "b", Check: configuration.OutboundCheck{Method: "tcp", Target: "b.example.invalid:443"}}}, Gates: []string{}, Stages: []configuration.OutboundCheckExpr{{Any: []configuration.OutboundCheckExpr{{Leaf: "a"}, {Leaf: "b"}}}}}
	prepared.EngineConfig, e = configuration.CompileNetwork(graph, configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4", RouteChecks: []configuration.OutboundCheckPlan{{Outbound: "direct", Required: true, Profile: profile}}})
	if e != nil {
		t.Fatal(e)
	}
	prepared.RequiredCapabilities = []string{"route.health.v1", policy.RouteCheckPlanV2}
	return prepared, p, now
}

func TestPreparedCheckPlanV2RequiresAddressedAvailabilityWithoutGrantInference(t *testing.T) {
	prepared, p, now := checkPlanPreparation(t)
	available := append(append([]string(nil), p.RequiredCapabilities...), prepared.RequiredCapabilities...)
	original, _ := json.Marshal(p)
	if e := applyPreparedConfiguration(&p, prepared, available[:len(available)-1], now); !errors.Is(e, ErrDenied) {
		t.Fatal("unavailable v2 client received profile", e)
	}
	after, _ := json.Marshal(p)
	if !bytes.Equal(original, after) {
		t.Fatal("failed prepare mutated candidate")
	}
	if e := applyPreparedConfiguration(&p, prepared, available, now); e != nil || !slices.Contains(p.RequiredCapabilities, policy.RouteCheckPlanV2) || p.TargetDevice != "synthetic-device" || p.KeyThumbprint == "" || p.AlgorithmRevision != policy.BaselineAlgorithm {
		t.Fatal("approved profile lost owner/key/algorithm", e)
	}
	p.KeyThumbprint = ""
	g := Grant{Issuer: "https://identity.example.invalid/realms/test", Subject: "synthetic-user", DeviceLimit: 1, Until: now.Add(time.Hour).Unix(), Template: p}
	if !errors.Is(g.Validate(now), identity.ErrInvalid) {
		t.Fatal("shared grant enabled advanced check plan")
	}
}

func TestPreparedCheckPlanV2IffCapabilityCannotBeForgedByCallback(t *testing.T) {
	for _, mode := range []string{"missing", "extraneous", "duplicate"} {
		prepared, p, now := checkPlanPreparation(t)
		available := append(append([]string(nil), p.RequiredCapabilities...), prepared.RequiredCapabilities...)
		switch mode {
		case "missing":
			prepared.RequiredCapabilities = []string{"route.health.v1"}
		case "extraneous":
			prepared.EngineConfig = compiledFixtureNetwork(t)
		case "duplicate":
			prepared.RequiredCapabilities = append(prepared.RequiredCapabilities, policy.RouteCheckPlanV2)
		}
		before, _ := json.Marshal(p)
		if e := applyPreparedConfiguration(&p, prepared, available, now); e == nil {
			t.Fatal("forged capability declaration accepted", mode)
		}
		after, _ := json.Marshal(p)
		if !bytes.Equal(before, after) {
			t.Fatal("rejected callback partially applied")
		}
	}
}

func TestPreparedCheckPlanV2IndependentRawValidationRejectsNullAlternativesAndVariablePaths(t *testing.T) {
	for _, mode := range []string{"both", "null", "integer", "variable", "duplicate", "security"} {
		prepared, p, now := checkPlanPreparation(t)
		available := append(append([]string(nil), p.RequiredCapabilities...), prepared.RequiredCapabilities...)
		raw := string(prepared.EngineConfig)
		switch mode {
		case "both":
			raw = strings.Replace(raw, `"profile":`, `"checks":[],"profile":`, 1)
		case "null":
			raw = strings.Replace(raw, `"profile":`, `"profile":null,"unknown":`, 1)
		case "integer":
			raw = strings.Replace(raw, `"revision":1`, `"revision":1.0`, 1)
		case "duplicate":
			raw = strings.Replace(raw, `"profile":`, `"profile":{},"profile":`, 1)
		case "variable":
			raw = strings.Replace(raw, `"type":"direct"`, `"type":"selector","outbounds":["direct"]`, 1)
		case "security":
			raw = strings.Replace(raw, `"method":"tcp","target":"a.example.invalid:443"`, `"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU"`, 1)
			prepared.RequiredCapabilities = append(prepared.RequiredCapabilities, policy.RouteExitCountry)
			available = append(available, policy.RouteExitCountry)
		}
		prepared.EngineConfig = json.RawMessage(raw)
		before, _ := json.Marshal(p)
		if applyPreparedConfiguration(&p, prepared, available, now) == nil {
			t.Fatal("forged prepared engine bypassed independent validator", mode)
		}
		after, _ := json.Marshal(p)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid engine changed payload")
		}
	}
	// The old adaptive issuer required all three row members even though a
	// general legacy policy can omit required. A forged callback cannot reuse
	// that compatibility rule to change adaptive activation participation.
	for _, mode := range []string{"missing", "null", "number", "string", "extra"} {
		prepared, p, now := compiledAdaptivePreparation(t)
		available := append(append([]string(nil), p.RequiredCapabilities...), prepared.RequiredCapabilities...)
		mutateAdaptivePreparedEngine(t, prepared, func(root, _ map[string]any) {
			row := root["route_checks"].([]any)[0].(map[string]any)
			switch mode {
			case "missing":
				delete(row, "required")
			case "null":
				row["required"] = nil
			case "number":
				row["required"] = 0
			case "string":
				row["required"] = "false"
			case "extra":
				row["foreign"] = false
			}
		})
		before, _ := json.Marshal(p)
		if applyPreparedConfiguration(&p, prepared, available, now) == nil {
			t.Fatal("adaptive callback lost explicit required envelope", mode)
		}
		after, _ := json.Marshal(p)
		if !bytes.Equal(before, after) {
			t.Fatal("forged adaptive envelope changed prior payload")
		}
	}
}
