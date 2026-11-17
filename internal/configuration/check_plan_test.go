package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func v2Profile(checks ...OutboundCheck) *OutboundCheckProfile {
	p := &OutboundCheckProfile{SchemaVersion: 2, ID: "health", Revision: 1, DeadlineMs: 12000, Leaves: []OutboundCheckLeaf{}, Gates: []string{}, Stages: []OutboundCheckExpr{}}
	for i, c := range checks {
		id := fmt.Sprintf("check-%d", i)
		p.Leaves = append(p.Leaves, OutboundCheckLeaf{ID: id, Check: c})
		if c.Method == "tls" || c.Method == "https_exit_ip" || c.Method == "https_exit_country" {
			p.Gates = append(p.Gates, id)
		} else {
			p.Stages = append(p.Stages, OutboundCheckExpr{Leaf: id})
		}
	}
	return p
}
func v2Network() NetworkSettings {
	s := networkBase()
	s.RouteChecks = []OutboundCheckPlan{{Outbound: "entry", Required: true, Profile: v2Profile(OutboundCheck{Method: "tcp", Target: "a.example.invalid:443"}, OutboundCheck{Method: "https_204", Target: "https://b.example.invalid/"})}}
	return s
}

func TestCheckPlanV2ActualNetworkCompilerPreservesProgramAndLegacyBytes(t *testing.T) {
	g := networkGraph(t)
	s := v2Network()
	s.RouteChecks[0].Profile.Stages = []OutboundCheckExpr{{Any: []OutboundCheckExpr{{Leaf: "check-0"}, {Leaf: "check-1"}}}}
	raw, e := CompileNetwork(g, s)
	if e != nil || ValidateIssuedCheckPlans(raw) != nil {
		t.Fatal("actual static compiled program rejected", e)
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || bytes.Contains(root["route_checks"], []byte(`"checks":`)) {
		t.Fatal("profile flattened into legacy checks")
	}
	var plans []OutboundCheckPlan
	if json.Unmarshal(root["route_checks"], &plans) != nil || len(plans) != 1 || plans[0].Profile == nil || len(plans[0].Profile.Stages[0].Any) != 2 {
		t.Fatal("expression lost")
	}
	legacy := networkBase()
	legacy.RouteChecks = []OutboundCheckPlan{{Outbound: "entry", Checks: []OutboundCheck{{Method: "tcp", Target: "a.example.invalid:443"}}}}
	b, e := CompileNetwork(g, legacy)
	if e != nil || json.Unmarshal(b, &root) != nil || string(root["route_checks"]) != `[{"outbound":"entry","required":false,"checks":[{"method":"tcp","target":"a.example.invalid:443"}]}]` {
		t.Fatal("legacy emitted bytes changed")
	}
}

func TestCheckPlanV2CompilerAndIndependentIssuerRejectVariablePaths(t *testing.T) {
	source := graphBase()
	source.Balancers["chooser"] = Balancer{Type: "selector", Members: []string{"entry", "socks"}, Default: "entry"}
	g, e := CompileGraph(source, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	g.Outbounds = append(g.Outbounds, json.RawMessage(`{"type":"http","tag":"prefixed","detour":"chooser"}`))
	g.Capabilities["prefixed"] = GraphCapability{TCP: true}
	for _, tag := range []string{"chooser", "prefixed"} {
		s := v2Network()
		s.RouteChecks[0].Outbound = tag
		if _, e := CompileNetwork(g, s); e == nil {
			t.Fatal("variable ordinary path compiled")
		}
	}
	valid, e := CompileNetwork(networkGraph(t), v2Network())
	if e != nil {
		t.Fatal(e)
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(valid, &root) != nil {
		t.Fatal("fixture")
	}
	root["outbounds"] = json.RawMessage(`[{"type":"direct","tag":"direct"},{"type":"selector","tag":"entry","outbounds":["direct"]}]`)
	forged, _ := json.Marshal(root)
	if ValidateIssuedCheckPlans(forged) == nil {
		t.Fatal("forged callback bypassed ordinary fixed-path admission")
	}
	root["outbounds"] = json.RawMessage(`[{"type":"direct","tag":"direct","detour":"entry"},{"type":"http","tag":"entry","detour":"direct"}]`)
	forged, _ = json.Marshal(root)
	if ValidateIssuedCheckPlans(forged) == nil {
		t.Fatal("direct detour/cycle accepted")
	}
}

func TestCheckPlanV2DirectTerminalFourNodeLimitAndNetBirdBoundary(t *testing.T) {
	profile := v2Profile(OutboundCheck{Method: "tcp", Target: "a.example.invalid:443"})
	plans := []OutboundCheckPlan{{Outbound: "a", Profile: profile}}
	for _, tc := range []struct {
		raw string
		ok  bool
	}{
		{`[{"type":"direct","tag":"a"}]`, true},
		{`[{"type":"http","tag":"a","detour":"b"},{"type":"socks","tag":"b","detour":"c"},{"type":"ssh","tag":"c","detour":"d"},{"type":"direct","tag":"d"}]`, true},
		{`[{"type":"http","tag":"a","detour":"b"},{"type":"socks","tag":"b","detour":"c"},{"type":"ssh","tag":"c","detour":"d"},{"type":"http","tag":"d","detour":"e"},{"type":"direct","tag":"e"}]`, false},
		{`[{"type":"netbird","tag":"a"}]`, false},
		{`[{"type":"vless","tag":"a","network":"udp"}]`, false},
		{`[{"type":"http","tag":"a","detour":"missing"}]`, false},
		{`[{"type":"http","tag":"a","detour":"group"},{"type":"syn443-adaptive","tag":"group","group":"g"}]`, false},
	} {
		var nodes []json.RawMessage
		if json.Unmarshal([]byte(tc.raw), &nodes) != nil {
			t.Fatal("fixture")
		}
		if (validateConcreteCheckPaths(nodes, plans, map[string]bool{"group": true}) == nil) != tc.ok {
			t.Fatal("concrete path boundary diverged")
		}
	}
}

func TestCheckPlanV2AdaptiveCompilerAndIndependentIssuerRequireUnconditionalCountryGate(t *testing.T) {
	for _, intent := range []string{"INTERNAL", "RU", "NON_RU"} {
		p, profiles := adaptiveCompilerFixture(t, 2, intent)
		check := p.Network.RouteChecks[0].Checks[0]
		p.Network.RouteChecks[0].Checks = nil
		p.Network.RouteChecks[0].Profile = v2Profile(check, OutboundCheck{Method: "tcp", Target: "other.example.invalid:443"})
		compiled, e := CompileNetworkPlan(context.Background(), p, adaptiveCompilerResolver(profiles))
		if e != nil || ValidateAdaptiveIssuedEngine(compiled.EngineConfig) != nil || ValidateIssuedCheckPlans(compiled.EngineConfig) != nil {
			t.Fatal("actual adaptive v2 publication rejected", intent, e)
		}
		if intent != "INTERNAL" {
			bad := p
			bad.Network.RouteChecks = append([]OutboundCheckPlan(nil), p.Network.RouteChecks...)
			bad.Network.RouteChecks[0].Profile = v2Profile(OutboundCheck{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "RU"})
			if intent == "RU" {
				bad.Network.RouteChecks[0].Profile.Leaves[0].Check.ExpectedExitClass = "NON_RU"
			}
			if _, e := CompileNetworkPlan(context.Background(), bad, adaptiveCompilerResolver(profiles)); e == nil {
				t.Fatal("foreign class passed compiler")
			}
			var root map[string]any
			if json.Unmarshal(compiled.EngineConfig, &root) != nil {
				t.Fatal("fixture")
			}
			profile := root["route_checks"].([]any)[0].(map[string]any)["profile"].(map[string]any)
			profile["gates"] = []any{}
			profile["stages"] = []any{map[string]any{"any": []any{map[string]any{"leaf": "check-0"}, map[string]any{"leaf": "check-1"}}}}
			forged, _ := json.Marshal(root)
			if ValidateAdaptiveIssuedEngine(forged) == nil || ValidateIssuedCheckPlans(forged) == nil {
				t.Fatal("optional country leaf bypassed independent authority gate")
			}
		}
	}
}

func TestCheckPlanV2WholeNetworkDecodeRejectsNullBothAndExactNumbers(t *testing.T) {
	s := v2Network()
	raw, _ := json.Marshal(s)
	for _, pair := range [][2]string{{`"profile":`, `"checks":[],"profile":`}, {`"profile":`, `"profile":null,"ignored":`}, {`"revision":1`, `"revision":1.0`}, {`"revision":1`, `"revision":1e0`}, {`"deadlineMs":12000`, `"deadlineMs":12001`}, {`"gates":[]`, `"gates":null`}} {
		bad := strings.Replace(string(raw), pair[0], pair[1], 1)
		if _, e := DecodeNetworkSettings([]byte(bad)); e == nil {
			t.Fatal("whole settings decoder lost strict profile shape")
		}
	}
}

func TestCheckPlanV2ActualPlanOwnsProfileBeforeSourceResolverMutation(t *testing.T) {
	p := planBase()
	p.Network.RouteChecks = v2Network().RouteChecks
	compiled, e := CompileNetworkPlan(context.Background(), p, func(ref ProfileReference) (subscriptions.Profile, error) {
		p.Network.RouteChecks[0].Profile.Leaves[0].Check.Target = "mutated.example.invalid:443"
		return defaultGraphResolver()(ref)
	})
	if e != nil || bytes.Contains(compiled.EngineConfig, []byte("mutated.example.invalid")) || !bytes.Contains(compiled.EngineConfig, []byte("a.example.invalid")) {
		t.Fatal("compiler retained mutable caller profile", e)
	}
}

func TestCheckPlanV2MetadataBudgetCountsEveryDeclaredLeafAndAllRows(t *testing.T) {
	g := CompiledGraph{Final: "direct", Capabilities: map[string]GraphCapability{"direct": {TCP: true}}, Outbounds: []json.RawMessage{json.RawMessage(`{"type":"direct","tag":"direct"}`)}}
	s := networkBase()
	s.RequiredNetworks = []string{"tcp"}
	for i := 0; i < 16; i++ {
		tag := fmt.Sprintf("route-%d", i)
		g.Capabilities[tag] = GraphCapability{TCP: true}
		g.Outbounds = append(g.Outbounds, json.RawMessage(fmt.Sprintf(`{"type":"http","tag":%q}`, tag)))
		s.RouteChecks = append(s.RouteChecks, OutboundCheckPlan{Outbound: tag, Profile: v2Profile(OutboundCheck{Method: "https_204", Target: "https://a.example.invalid/"})})
	}
	if _, e := CompileNetwork(g, s); e != nil {
		t.Fatal("sixteen bounded profiles rejected", e)
	}
	for i := range s.RouteChecks {
		p := s.RouteChecks[i].Profile
		for j := 0; j < 4; j++ {
			c := OutboundCheck{Method: "https_204", Target: "https://a.example.invalid/" + strings.Repeat("a", 1900) + fmt.Sprint(j)}
			if j == 0 {
				p.Leaves[0].Check = c
			} else {
				id := fmt.Sprintf("check-%d", j)
				p.Leaves = append(p.Leaves, OutboundCheckLeaf{ID: id, Check: c})
				p.Stages = append(p.Stages, OutboundCheckExpr{Leaf: id})
			}
		}
	}
	if _, e := CompileNetwork(g, s); e == nil {
		t.Fatal("large alternative metadata escaped unchanged 24KB budget")
	}
}

func TestCheckPlanV2DoesNotOptLegacySelectorFailoverIntoMixedObservations(t *testing.T) {
	source := graphBase()
	source.Balancers["internal"] = Balancer{Type: "selector", Members: []string{"entry", "socks"}, Default: "entry"}
	g, e := CompileGraph(source, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	s := networkBase()
	s.Rules = []RouteRule{{ID: "home", HostMatch: HostMatch{Domains: []string{"home.example.invalid"}}, Networks: []string{"tcp"}, Action: "route", Outbound: "internal"}}
	s.RouteFailover = &RouteFailoverPlan{Selector: "internal", NetworkMode: "wifi", Intent: "INTERNAL"}
	for _, tag := range []string{"internal", "entry", "socks"} {
		s.RouteChecks = append(s.RouteChecks, OutboundCheckPlan{Outbound: tag, Required: tag == "internal", Checks: []OutboundCheck{{Method: "tcp", Target: "home.example.invalid:22"}}})
	}
	legacy, e := CompileNetwork(g, s)
	if e != nil || ValidateIssuedCheckPlans(legacy) != nil {
		t.Fatal("legacy failover changed", e)
	}
	s.RouteChecks = append(s.RouteChecks, OutboundCheckPlan{Outbound: "exit", Profile: v2Profile(OutboundCheck{Method: "tcp", Target: "other.example.invalid:443"})})
	if _, e := CompileNetwork(g, s); e == nil {
		t.Fatal("mixed legacy selector/V2 plan accepted")
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(legacy, &root) != nil {
		t.Fatal("fixture")
	}
	root["route_checks"], e = json.Marshal(s.RouteChecks)
	if e != nil {
		t.Fatal(e)
	}
	forged, _ := json.Marshal(root)
	if ValidateIssuedCheckPlans(forged) == nil {
		t.Fatal("forged mixed failover bypassed independent boundary")
	}
}

func TestCheckPlanV2EmbeddedOpenAPIAndActualCompilerPreserveClosedRows(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/control-openapi.json")
	if e != nil {
		t.Fatal(e)
	}
	var document any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("invalid embedded OpenAPI")
	}
	compiler := jsonschema.NewCompiler()
	const base = "https://contracts.example.invalid/control-openapi.json"
	if e := compiler.AddResource(base, document); e != nil {
		t.Fatal(e)
	}
	rowSchema, e := compiler.Compile(base + "#/components/schemas/PlanOutboundChecks")
	if e != nil {
		t.Fatal(e)
	}
	// This is the same embedded Action root used by catalog.loadControlSchema,
	// not a standalone replacement schema that bypasses the actual HTTP gate.
	actionSchema, e := compiler.Compile(base + "#/components/schemas/Action")
	if e != nil {
		t.Fatal(e)
	}
	vectorsRaw, e := contracts.Files.ReadFile("v1/route-check-profile-v2-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors struct {
		Valid []struct {
			Name    string          `json:"name"`
			Profile json.RawMessage `json:"profile"`
		} `json:"validCases"`
	}
	if json.Unmarshal(vectorsRaw, &vectors) != nil || len(vectors.Valid) != 9 {
		t.Fatal("shared positive profile scope changed")
	}
	graph := networkGraph(t)
	compileRow := func(row map[string]any) (OutboundCheckPlan, []byte, error) {
		wire, err := json.Marshal(row)
		if err != nil {
			return OutboundCheckPlan{}, nil, err
		}
		var plan OutboundCheckPlan
		if err = json.Unmarshal(wire, &plan); err != nil {
			return OutboundCheckPlan{}, nil, err
		}
		settings := networkBase()
		settings.RouteChecks = []OutboundCheckPlan{plan}
		engine, err := CompileNetwork(graph, settings)
		return plan, engine, err
	}
	for _, vector := range vectors.Valid {
		var profile any
		if json.Unmarshal(vector.Profile, &profile) != nil {
			t.Fatal("invalid positive vector")
		}
		row := map[string]any{"outbound": "entry", "required": true, "profile": profile}
		if e := rowSchema.Validate(row); e != nil {
			t.Fatal("embedded row rejected valid shared profile", vector.Name, e)
		}
		decoded, engine, e := compileRow(row)
		if e != nil || decoded.Profile == nil || ValidateIssuedCheckPlans(engine) != nil {
			t.Fatal("actual compiler rejected OpenAPI profile", vector.Name, e)
		}
		var root struct {
			Plans []OutboundCheckPlan `json:"route_checks"`
		}
		if json.Unmarshal(engine, &root) != nil || len(root.Plans) != 1 || root.Plans[0].Checks != nil || root.Plans[0].Profile == nil {
			t.Fatal("schema/codec handoff flattened profile")
		}
		before, _ := json.Marshal(decoded.Profile)
		after, _ := json.Marshal(root.Plans[0].Profile)
		if !bytes.Equal(before, after) {
			t.Fatal("compiler rewrote the accepted program")
		}
		portable := planBase()
		portable.Network.RouteChecks = []OutboundCheckPlan{decoded}
		planWire, e := json.Marshal(portable)
		var planValue any
		if e != nil || json.Unmarshal(planWire, &planValue) != nil {
			t.Fatal("portable fixture")
		}
		action := map[string]any{"version": 1, "action": "configuration.draft.put", "requestId": "check-plan-openapi-request-0001", "payload": map[string]any{"draft": map[string]any{"id": "check-plan-draft", "revision": 0, "targetKind": "device", "targetId": "synthetic-device", "baseRevision": 0, "baseHash": "", "plan": planValue, "savedAt": 0}}}
		if e := actionSchema.Validate(action); e != nil {
			t.Fatal("actual HTTP Action schema rejected portable profile", vector.Name, e)
		}
		owned, e := DecodeNetworkPlan(planWire)
		if e != nil {
			t.Fatal(e)
		}
		compiled, e := CompileNetworkPlan(context.Background(), owned, defaultGraphResolver())
		if e != nil || !bytes.Contains(compiled.EngineConfig, []byte(`"profile":`)) {
			t.Fatal("full compiler dropped schema-accepted profile", e)
		}
	}
	legacy := map[string]any{"outbound": "entry", "required": false, "checks": []any{map[string]any{"method": "tcp", "target": "a.example.invalid:443"}}}
	if rowSchema.Validate(legacy) != nil {
		t.Fatal("legacy row contract changed")
	}
	if p, _, e := compileRow(legacy); e != nil || p.Profile != nil || len(p.Checks) != 1 {
		t.Fatal("legacy row no longer compiles", e)
	}
	var firstProfile map[string]any
	if json.Unmarshal(vectors.Valid[0].Profile, &firstProfile) != nil {
		t.Fatal("fixture")
	}
	for _, kind := range []string{"both", "neither", "null-profile", "null-checks", "unknown", "unknown-profile", "missing-required", "wrong-required", "null-required", "wrong-outbound", "empty-outbound", "invalid-outbound"} {
		row := map[string]any{"outbound": "entry", "required": true, "profile": firstProfile}
		switch kind {
		case "both":
			row["checks"] = legacy["checks"]
		case "neither":
			delete(row, "profile")
		case "null-profile":
			row["profile"] = nil
		case "null-checks":
			delete(row, "profile")
			row["checks"] = nil
		case "unknown":
			row["unknown"] = false
		case "unknown-profile":
			changed := map[string]any{}
			for key, value := range firstProfile {
				changed[key] = value
			}
			changed["unknown"] = false
			row["profile"] = changed
		case "missing-required":
			delete(row, "required")
		case "wrong-required":
			row["required"] = "true"
		case "null-required":
			row["required"] = nil
		case "wrong-outbound":
			row["outbound"] = false
		case "empty-outbound":
			row["outbound"] = ""
		case "invalid-outbound":
			row["outbound"] = "not/a/tag"
		}
		if rowSchema.Validate(row) == nil {
			t.Fatal("OpenAPI accepted ambiguous/invalid row", kind)
		}
		if _, _, e := compileRow(row); e == nil {
			t.Fatal("codec/compiler accepted ambiguous/invalid row", kind)
		}
	}
	unknown := map[string]any{"outbound": "unresolved", "required": true, "profile": firstProfile}
	if rowSchema.Validate(unknown) != nil {
		t.Fatal("shape schema inferred graph authority")
	}
	if _, _, e := compileRow(unknown); e == nil {
		t.Fatal("shape-valid row inferred an actual outbound")
	}
	rowWire, _ := json.Marshal(map[string]any{"outbound": "entry", "required": true, "profile": firstProfile})
	fractional := bytes.Replace(rowWire, []byte(`"revision":1`), []byte(`"revision":1.0`), 1)
	var decoded OutboundCheckPlan
	if bytes.Equal(fractional, rowWire) || json.Unmarshal(fractional, &decoded) == nil {
		t.Fatal("codec discarded exact integer-token guard")
	}
	// Standard JSON Schema may regard1.0 as an integer. The typed codec above,
	// not a fabricated JSON Schema claim, enforces the lexical wire boundary.
}
