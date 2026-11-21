package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestPreparedHTTPSStatusBindsExactPredicateToDeviceCapability(t *testing.T) {
	prepared, p, now := configuredPreparation(t)
	graph, err := configuration.CompileGraph(configuration.Graph{Profiles: map[string]configuration.ProfileReference{}, Chains: map[string]configuration.Chain{}, Balancers: map[string]configuration.Balancer{}, Final: "direct"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	check := configuration.OutboundCheck{Method: "https_status", Target: "https://service.example.invalid/health", HTTPMethod: "HEAD", ExpectedStatus: 202}
	prepared.EngineConfig, err = configuration.CompileNetwork(graph, configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4",
		RouteChecks: []configuration.OutboundCheckPlan{{Outbound: "direct", Required: true, Checks: []configuration.OutboundCheck{check}}}})
	if err != nil {
		t.Fatal(err)
	}
	prepared.RequiredCapabilities = []string{"route.health.v1", policy.RouteHTTPSStatus}
	base := append(slices.Clone(p.RequiredCapabilities), "route.health.v1")
	before, _ := json.Marshal(p)
	if err := applyPreparedConfiguration(&p, prepared, base, now); !errors.Is(err, ErrDenied) {
		t.Fatal("unavailable primitive was issued", err)
	}
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatal("denial changed the previous assignment")
	}
	if err := applyPreparedConfiguration(&p, prepared, append(base, policy.RouteHTTPSStatus), now); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.RequiredCapabilities, policy.RouteHTTPSStatus) || p.Validate(now) != nil {
		t.Fatal("invalid qualified assignment")
	}
	p.RequiredCapabilities = slices.DeleteFunc(slices.Clone(p.RequiredCapabilities), func(c string) bool { return c == policy.RouteHTTPSStatus })
	if p.Validate(now) == nil {
		t.Fatal("wire predicate survived removing the signed capability")
	}
}
