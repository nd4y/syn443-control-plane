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

func TestSQLExitCountryRequiresNegotiatedPrimitiveAndPreservesBothPredicates(t *testing.T) {
	n := newNetworkFixture(t)
	n.approved.Layers[0].Changes[2].Value = json.RawMessage(`{"schemaVersion":1,"requiredNetworks":["tcp"],"dnsFinal":"system","dnsStrategy":"prefer_ipv4","routeChecks":[{"outbound":"proxy","required":true,"checks":[{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"NON_RU"},{"method":"https_exit_ip","target":"https://health.example.invalid/address","expected_ip":"192.0.2.9"}]}]}`)
	n.authority.Layers = networkLayersFunc(func(_ context.Context, target enrollment.ConfigurationTarget, _ time.Time) (*ApprovedNetworkLayers, error) {
		approved := *n.approved
		approved.Target = target
		return &approved, nil
	})
	ctx := context.Background()
	target := n.target
	target.Capabilities = append(append([]string(nil), target.Capabilities...), "route.health.v1", policy.RouteExitIP)
	if _, err := n.authority.Prepare(ctx, target, n.f.now); !errors.Is(err, enrollment.ErrDenied) {
		t.Fatal("country probe was published using fixed-IP support alone", err)
	}
	target.Capabilities = append(target.Capabilities, policy.RouteExitCountry)
	prepared, err := n.authority.Prepare(ctx, target, n.f.now)
	if err != nil || prepared == nil || !slices.Contains(prepared.RequiredCapabilities, policy.RouteExitCountry) || !slices.Contains(prepared.RequiredCapabilities, policy.RouteExitIP) {
		t.Fatal("both probe capabilities must accompany the exact engine config", err)
	}
	if len(prepared.RequiredCapabilities) != 6 {
		t.Fatal("country capabilities duplicated or unrelated capability added")
	}
	var engine struct {
		Checks []configuration.OutboundCheckPlan `json:"route_checks"`
	}
	if json.Unmarshal(prepared.EngineConfig, &engine) != nil || len(engine.Checks) != 1 || len(engine.Checks[0].Checks) != 2 || engine.Checks[0].Checks[0].ExpectedExitClass != "NON_RU" || engine.Checks[0].Checks[1].ExpectedIP != "192.0.2.9" {
		t.Fatal("prepared check predicates changed")
	}
	target.Capabilities = slices.DeleteFunc(append([]string(nil), target.Capabilities...), func(c string) bool { return c == policy.RouteExitIP })
	if _, err := n.authority.Prepare(ctx, target, n.f.now); !errors.Is(err, enrollment.ErrDenied) {
		t.Fatal("country primitive silently substituted fixed-IP capability", err)
	}
	tx, err := fixtureSigner.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := prepared.Fence.Lock(ctx, tx, n.f.now); err != nil {
		t.Fatal("publication lost live SQL authority fence", err)
	}
}
