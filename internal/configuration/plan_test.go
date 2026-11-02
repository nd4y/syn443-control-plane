package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func planBase() NetworkPlan {
	graph := graphBase()
	graph.Final = "exit"
	return NetworkPlan{SchemaVersion: 1, Graph: graph, Network: networkBase(),
		Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.invalid/generate_204", Required: true}}}}
}

func TestPortableNetworkPlanComposesGraphDNSRoutingAndIndependentActivation(t *testing.T) {
	plan := planBase()
	plan.Network.DNSServers = map[string]DNSServer{"secure": {Transport: "https", Address: "resolver.example.invalid", Port: 443, ServerName: "resolver.example.invalid", Path: "/dns-query", Outbound: "tunnel"}}
	plan.Network.DNSFinal = "secure"
	plan.Network.Rules = []RouteRule{{HostMatch: HostMatch{Domains: []string{"service.example.invalid"}}, ID: "service", Networks: []string{"tcp"}, Ports: []PortRange{{443, 443}}, Action: "route", Outbound: "tunnel"}}
	raw, _ := json.Marshal(plan)
	decoded, e := DecodeNetworkPlan(raw)
	if e != nil || !reflect.DeepEqual(plan, decoded) {
		t.Fatal("portable plan roundtrip", e)
	}
	compiled, e := CompileNetworkPlan(context.Background(), decoded, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(compiled.EngineConfig)
	if compiled.ContentHash != hex.EncodeToString(hash[:]) || len(compiled.RequiredEngineFeatures) == 0 || !reflect.DeepEqual(compiled.Activation, plan.Activation) {
		t.Fatal("compiled handoff lost hash/activation/features")
	}
	var output map[string]json.RawMessage
	if json.Unmarshal(compiled.EngineConfig, &output) != nil || len(output) != 3 || output["outbounds"] == nil || output["route"] == nil || output["dns"] == nil {
		t.Fatal("unexpected native root")
	}
	if !bytes.Contains(compiled.EngineConfig, []byte(`"detour":"tunnel"`)) {
		t.Fatal("DNS lost its actual proxy path")
	}
	for _, forbidden := range []string{"schemaVersion", "sourceId", "activation", "setup_key", "inbounds"} {
		if bytes.Contains(compiled.EngineConfig, []byte(`"`+forbidden+`"`)) {
			t.Fatal("portable/privileged data reached native output", forbidden)
		}
	}
	before := append([]byte(nil), compiled.EngineConfig...)
	decoded.Graph.Final = "direct"
	decoded.Activation.Checks[0].Target = "https://changed.example.invalid"
	decoded.Network.Rules[0].Domains[0] = "changed.example.invalid"
	if !bytes.Equal(before, compiled.EngineConfig) || compiled.Activation.Checks[0].Target != plan.Activation.Checks[0].Target {
		t.Fatal("caller mutation altered compiled publication")
	}
	if strings.Contains(compiled.String(), "example.invalid") || strings.Contains(plan.GoString(), "example.invalid") || strings.Contains(compiled.GoString(), "example.invalid") || strings.Contains(plan.String(), "example.invalid") {
		t.Fatal("diagnostics exposed portable config")
	}
}

func TestNetworkPlanRejectsInvalidGraphsNetworkRequirementsGatesAndCancellation(t *testing.T) {
	for _, change := range []func(*NetworkPlan){
		func(p *NetworkPlan) { p.SchemaVersion = 2 },
		func(p *NetworkPlan) { p.Graph.Final = "missing" },
		func(p *NetworkPlan) { p.Network.DNSFinal = "missing" },
		func(p *NetworkPlan) { p.Graph.Final = "tunnel" }, // HTTP first hop cannot carry required UDP.
		func(p *NetworkPlan) { p.Activation.TimeoutSeconds = 29 },
		func(p *NetworkPlan) { p.Activation.TimeoutSeconds = 121 },
		func(p *NetworkPlan) { p.Activation.Checks[0].Required = false },
		func(p *NetworkPlan) { p.Activation.Checks[0].Target = "http://health.example.invalid" },
	} {
		plan := planBase()
		change(&plan)
		if _, e := CompileNetworkPlan(context.Background(), plan, defaultGraphResolver()); e == nil {
			t.Fatal("invalid portable plan compiled")
		}
	}
	if _, e := CompileNetworkPlan(nil, planBase(), defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
		t.Fatal("nil context", e)
	}
	if _, e := CompileNetworkPlan(context.Background(), planBase(), nil); !errors.Is(e, ErrInvalid) {
		t.Fatal("missing independent resolver", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := CompileNetworkPlan(ctx, planBase(), defaultGraphResolver()); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled input returned a plan", e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if _, e := CompileNetworkPlan(ctx, planBase(), func(ref ProfileReference) (subscriptions.Profile, error) {
		profile, e := defaultGraphResolver()(ref)
		cancel()
		return profile, e
	}); !errors.Is(e, context.Canceled) {
		t.Fatal("late source result bypassed cancellation", e)
	}
	if _, e := CompileNetworkPlan(context.Background(), planBase(), func(ProfileReference) (subscriptions.Profile, error) { return subscriptions.Profile{}, ErrLocked }); e == nil {
		t.Fatal("source authority error ignored")
	}
}

func TestNetworkPlanClosedShapeAndLayerMergeDoNotGrantPublicationAuthority(t *testing.T) {
	plan := planBase()
	raw, _ := json.Marshal(plan)
	for _, bad := range [][]byte{nil, []byte("null"), []byte("{}"), bytes.Repeat([]byte("x"), 262145),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1.0`), 1),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"native":{"outbounds":[]}}`)...),
		bytes.Replace(raw, []byte(`"requiredNetworks":["tcp","udp"]`), []byte(`"requiredNetworks":null`), 1)} {
		if _, e := DecodeNetworkPlan(bad); e == nil {
			t.Fatal("unbounded or ambiguous plan accepted")
		}
	}
	fields := map[string]json.RawMessage{}
	json.Unmarshal(raw, &fields)
	base := Layer{ID: "base", Kind: "template", Revision: 1, Permissions: []Permission{{Path: "/network/dnsStrategy", Mode: "free"}}}
	for _, name := range []string{"schemaVersion", "graph", "network", "activation"} {
		base.Changes = append(base.Changes, Change{Path: "/" + name, Operation: "set", Value: fields[name]})
	}
	device := Layer{ID: "device-a", Kind: "device", Revision: 3, Changes: []Change{{Path: "/network/dnsStrategy", Operation: "set", Value: json.RawMessage(`"ipv4_only"`)}}}
	effective, e := Merge(context.Background(), []Layer{device, base}, func(raw json.RawMessage) error { _, e := DecodeNetworkPlan(raw); return e })
	if e != nil {
		t.Fatal("portable layer merge", e)
	}
	merged, e := DecodeNetworkPlan(effective.Document)
	if e != nil || merged.Network.DNSStrategy != "ipv4_only" || effective.Fields["/network/dnsStrategy"].LayerID != device.ID {
		t.Fatal("effective plan/provenance mismatch", e)
	}
	if _, e = CompileNetworkPlan(context.Background(), merged, defaultGraphResolver()); e != nil {
		t.Fatal("valid effective plan did not compile", e)
	}
}

func FuzzNetworkPlan(f *testing.F) {
	raw, _ := json.Marshal(planBase())
	f.Add(raw)
	f.Add([]byte(`{"schemaVersion":1,"graph":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		plan, e := DecodeNetworkPlan(raw)
		if e == nil && (plan.SchemaVersion != 1 || plan.Activation.Validate() != nil) {
			t.Fatal("invalid bounded plan accepted")
		}
	})
}
