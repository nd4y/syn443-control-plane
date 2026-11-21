//go:build postgres

package deviceprovisioning

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestSQLNetworkAuthorityIssuesOnlyNegotiatedHTTPSStatus(t *testing.T) {
	n := newNetworkFixture(t)
	n.approved.Layers[0].Changes[2].Value = json.RawMessage(`{"schemaVersion":1,"requiredNetworks":["tcp"],"dnsFinal":"system","dnsStrategy":"prefer_ipv4","routeChecks":[{"outbound":"proxy","required":true,"checks":[{"method":"https_status","target":"https://service.example.invalid/ready","http_method":"HEAD","expected_status":202}]}]}`)
	n.authority.Layers = networkLayersFunc(func(_ context.Context, target enrollment.ConfigurationTarget, _ time.Time) (*ApprovedNetworkLayers, error) {
		approved := *n.approved
		approved.Target = target
		return &approved, nil
	})
	target := n.target
	target.Capabilities = append(slices.Clone(target.Capabilities), "route.health.v1")
	ctx := context.Background()
	if _, err := n.authority.Prepare(ctx, target, n.f.now); !errors.Is(err, enrollment.ErrDenied) {
		t.Fatal("substituted legacy capability", err)
	}
	target.Capabilities = append(target.Capabilities, policy.RouteHTTPSStatus)
	prepared, err := n.authority.Prepare(ctx, target, n.f.now)
	if err != nil || !slices.Contains(prepared.RequiredCapabilities, policy.RouteHTTPSStatus) {
		t.Fatal("missing negotiated predicate", err)
	}
	var engine struct {
		Checks []configuration.OutboundCheckPlan `json:"route_checks"`
	}
	if json.Unmarshal(prepared.EngineConfig, &engine) != nil || len(engine.Checks) != 1 || len(engine.Checks[0].Checks) != 1 {
		t.Fatal("invalid issued probe")
	}
	check := engine.Checks[0].Checks[0]
	if check.Method != "https_status" || check.HTTPMethod != "HEAD" || check.ExpectedStatus != 202 {
		t.Fatal("issued predicate differs")
	}
	tx, err := fixtureSigner.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = prepared.Fence.Lock(ctx, tx, n.f.now); err != nil {
		t.Fatal("SQL authority fence failed", err)
	}
}
