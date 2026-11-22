//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func publishedConfiguration(t *testing.T, f *fixture, device string) (int64, []byte, string) {
	t.Helper()
	var revision int64
	var cipher []byte
	if err := fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, device).Scan(&revision, &cipher); err != nil {
		t.Fatal(err)
	}
	plain, err := f.worker.Open(cipher, "publication/v1/"+device+"/"+fmt.Sprint(revision))
	if err != nil {
		t.Fatal(err)
	}
	return revision, cipher, string(plain)
}
func TestSQLPublisherUsesActualTargetCompiledDocumentAndFinalConfigurationFences(t *testing.T) {
	f := newFixture(t, 2)
	deviceKey := key(t)
	session, _, _ := f.register(t, deviceKey)
	thumb, _ := identity.PublicJWK(&deviceKey.PublicKey).Thumbprint()
	prepared, _, _ := configuredPreparation(t)
	fence := &fixtureConfigurationFence{}
	prepared.Fence = fence
	publisher := f.publisher()
	publisher.Configurations = fixtureConfigurationAuthority(func(ctx context.Context, target ConfigurationTarget, now time.Time) (*PreparedConfiguration, error) {
		if ctx.Err() != nil || target.Device != session.DeviceID || target.Owner != Owner(f.grant.Issuer, f.grant.Subject) || target.Thumbprint != thumb || target.GrantHash != f.grant.Hash() || target.CurrentRevision != 0 || len(target.Capabilities) != 3 || !now.Equal(f.now) {
			t.Fatal("publisher trusted substituted configuration target")
		}
		return prepared, nil
	})
	if err := publisher.publish(context.Background(), session.DeviceID, f.now); err != nil {
		t.Fatal(err)
	}
	revision, cipher, bundle := publishedConfiguration(t, f, session.DeviceID)
	if revision != 1 || fence.calls != 2 {
		t.Fatal("configuration did not receive both transactional fences")
	}
	payload, err := policy.VerifyBound(bundle, f.api.Roots, session.DeviceID, thumb, f.now)
	digest := sha256.Sum256(prepared.EngineConfig)
	if err != nil || payload.ContentHash != fmt.Sprintf("%x", digest) || payload.OfflineUntilMs != prepared.UntilMs {
		t.Fatal("actual compiled publication not signed/bounded", err)
	}
	// A source/config authority outage cannot silently publish the account's
	// static template or replace the existing encrypted last-known-good policy.
	publisher.Configurations = fixtureConfigurationAuthority(func(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error) {
		return nil, ErrUnavailable
	})
	if err = publisher.publish(context.Background(), session.DeviceID, f.now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("authority outage fell back", err)
	}
	after, retained, _ := publishedConfiguration(t, f, session.DeviceID)
	if after != revision || string(retained) != string(cipher) {
		t.Fatal("outage replaced authorized publication")
	}
}

func TestSQLPublisherSignsApprovedFailoverProgramForActualEnrolledKey(t *testing.T) {
	f := newFixture(t, 2)
	deviceKey := key(t)
	capabilities := []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", "route.failover.v1", policy.RouteDecision, policy.DecisionBundleCapability}
	session, _, _ := f.registerWithCapabilities(t, deviceKey, capabilities)
	thumb, _ := identity.PublicJWK(&deviceKey.PublicKey).Thumbprint()
	members := []string{"entry", "reserve"}
	graph, err := configuration.CompileGraph(configuration.Graph{
		Profiles:  map[string]configuration.ProfileReference{"entry": {SourceID: "source", ProfileID: "entry"}, "reserve": {SourceID: "source", ProfileID: "reserve"}},
		Balancers: map[string]configuration.Balancer{"internal": {Type: "selector", Members: members, Default: "entry"}}, Final: "entry",
	}, func(ref configuration.ProfileReference) (subscriptions.Profile, error) {
		raw, err := json.Marshal(map[string]any{"type": "http", "tag": ref.ProfileID, "server": ref.ProfileID + ".example.invalid", "server_port": 443})
		return subscriptions.Profile{ID: ref.ProfileID, Kind: "http", Outbound: raw}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	program := policy.FailoverProgram{Revision: 7, Confirmations: 4, MinSwitchIntervalMs: 120000}
	settings := configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4",
		Rules:         []configuration.RouteRule{{ID: "home", HostMatch: configuration.HostMatch{Domains: []string{"node.home.example.invalid"}}, Networks: []string{"tcp"}, Action: "route", Outbound: "internal"}},
		RouteFailover: &configuration.RouteFailoverPlan{Selector: "internal", NetworkMode: "wifi", Intent: "INTERNAL", DecisionRevision: policy.ConfirmedFailoverAlgorithm, DecisionProgram: &program}}
	for _, tag := range []string{"internal", "entry", "reserve"} {
		settings.RouteChecks = append(settings.RouteChecks, configuration.OutboundCheckPlan{Outbound: tag, Required: tag == "internal", Checks: []configuration.OutboundCheck{{Method: "tcp", Target: "node.home.example.invalid:22"}}})
	}
	engine, err := configuration.CompileNetwork(graph, settings)
	if err != nil {
		t.Fatal(err)
	}
	prepared, _, _ := configuredPreparation(t)
	prepared.EngineConfig = engine
	prepared.AlgorithmRevision = policy.ConfirmedFailoverAlgorithm
	prepared.DecisionProgram = &program
	prepared.RequiredCapabilities = slices.Clone(capabilities[3:6])
	fence := &fixtureConfigurationFence{}
	prepared.Fence = fence
	publisher := f.publisher()
	publisher.Configurations = fixtureConfigurationAuthority(func(_ context.Context, target ConfigurationTarget, _ time.Time) (*PreparedConfiguration, error) {
		if target.Device != session.DeviceID || target.Thumbprint != thumb || !slices.Contains(target.Capabilities, policy.DecisionBundleCapability) {
			t.Fatal("wrong authenticated target")
		}
		return prepared, nil
	})
	if err = publisher.publish(context.Background(), session.DeviceID, f.now); err != nil {
		t.Fatal(err)
	}
	revision, _, bundle := publishedConfiguration(t, f, session.DeviceID)
	payload, err := policy.VerifyBound(bundle, f.api.Roots, session.DeviceID, thumb, f.now)
	if err != nil || revision != 1 || fence.calls != 2 || payload.DecisionBundle == "" || !slices.Contains(payload.RequiredCapabilities, policy.DecisionBundleCapability) {
		t.Fatal("bound publication or transactional fence missing", err)
	}
}

func TestSQLPublisherConfigurationRevokeLateExpiryAndCancellationKeepLastGood(t *testing.T) {
	for _, failure := range []string{"initial-fence", "commit-fence", "late-expiry", "cancel", "missing"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t, 1)
			session, _, _ := f.register(t, key(t))
			publisher := f.publisher()
			if err := publisher.publish(context.Background(), session.DeviceID, f.now); err != nil {
				t.Fatal(err)
			}
			revision, cipher, _ := publishedConfiguration(t, f, session.DeviceID)
			prepared, _, _ := configuredPreparation(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fence := &fixtureConfigurationFence{}
			fence.lock = func(context.Context, *sql.Tx, time.Time) error {
				if failure == "initial-fence" || failure == "commit-fence" && fence.calls == 2 {
					return ErrConflict
				}
				if failure == "late-expiry" && fence.calls == 1 {
					time.Sleep(2100 * time.Millisecond)
				}
				return nil
			}
			prepared.Fence = fence
			if failure == "late-expiry" {
				prepared.UntilMs = f.now.UnixMilli() + 2000
			}
			publisher.Configurations = fixtureConfigurationAuthority(func(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error) {
				if failure == "missing" {
					return nil, nil
				}
				if failure == "cancel" {
					cancel()
				}
				return prepared, nil
			})
			if err := publisher.publish(ctx, session.DeviceID, f.now); err == nil {
				t.Fatal("invalid/late configuration committed")
			}
			after, retained, _ := publishedConfiguration(t, f, session.DeviceID)
			if after != revision || string(retained) != string(cipher) {
				t.Fatal("rejected configuration replaced last good")
			}
		})
	}
}

func TestSQLDeviceDownloadsKeyBoundHomeProofOnlyAfterApprovedCapabilityChange(t *testing.T) {
	proof := syntheticHomeProof()
	prepared, _, _ := compiledAdaptivePreparationWithHomeProof(t, &proof)
	current := requireSQLAssignedNetworkPolicy(t, prepared, policy.HomeWiFiProof)
	var root struct {
		Home policy.HomeProof `json:"home_proof"`
	}
	if json.Unmarshal(mustDecodeAdaptiveEngine(t, current.EngineConfigB64), &root) != nil || root.Home != proof {
		t.Fatal("home endpoint or key changed during publication")
	}
}

func TestSQLDeviceDownloadsManagedModeOnlyAfterApprovedCapabilityChange(t *testing.T) {
	expected := policy.NetworkModePolicy{PreferredMode: "WIFI", UserModes: []string{"WIFI"}, MaxOverrideMinutes: 60}
	prepared, _, _ := compiledAdaptivePreparationWithNetwork(t, nil, &expected)
	current := requireSQLAssignedNetworkPolicy(t, prepared, policy.NetworkModeSelection)
	var root struct {
		Mode policy.NetworkModePolicy `json:"network_mode"`
	}
	if json.Unmarshal(mustDecodeAdaptiveEngine(t, current.EngineConfigB64), &root) != nil ||
		root.Mode.PreferredMode != expected.PreferredMode || root.Mode.MaxOverrideMinutes != 60 || !slices.Equal(root.Mode.UserModes, expected.UserModes) {
		t.Fatal("mode preference or user limits changed during issuance")
	}
}

func requireSQLAssignedNetworkPolicy(t *testing.T, prepared *PreparedConfiguration, feature string) policy.Payload {
	t.Helper()
	c := newCapabilityFixture(t)
	c.publisher.Configurations = fixtureConfigurationAuthority(func(_ context.Context, target ConfigurationTarget, _ time.Time) (*PreparedConfiguration, error) {
		if target.Device != c.session.DeviceID {
			t.Fatal("wrong recipient in authority")
		}
		return prepared, nil
	})
	readPolicy := func() policy.Payload {
		t.Helper()
		res := c.f.call(t, c.key, "GET", "/v1/device/policy", c.session.AccessToken, c.session.Nonce, nil)
		expect(t, res, 200)
		jkt, err := identity.PublicJWK(&c.key.PublicKey).Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		doc, err := policy.VerifyBound(res.Body.String(), c.f.api.Roots, c.session.DeviceID, jkt, c.f.now.Add(time.Second))
		if err != nil {
			t.Fatal("device could not verify fetched policy", err)
		}
		return doc
	}
	before := readPolicy()
	approve := func(caps []string, request string) {
		t.Helper()
		c.call(t, "POST", capabilityBody(t, request, c.snapshot(t), caps...), 200)
		if err := c.publisher.ApproveCapabilitiesOnce(t.Context(), c.f.now); err != nil {
			t.Fatal(err)
		}
	}
	approve([]string{"route.health.v1", policy.RouteDecision, policy.RouteAdaptiveTCP, policy.RouteExitCountry}, "synthetic adaptive client")
	if err := c.publisher.publish(t.Context(), c.session.DeviceID, c.f.now); !errors.Is(err, ErrDenied) {
		t.Fatal("publisher did not reject a device missing independent network capability", err)
	}
	if old := readPolicy(); old.Revision != before.Revision || old.ContentHash != before.ContentHash {
		t.Fatal("incompatible client lost last usable policy")
	}
	approve([]string{feature}, "synthetic network feature client")
	accepted := c.snapshot(t)
	if !slices.Contains(accepted.Capabilities, feature) {
		t.Fatal("capability did not pass independent approval")
	}
	candidate := before
	if err := applyPreparedConfiguration(&candidate, prepared, accepted.Capabilities, c.f.now); err != nil {
		t.Fatal("approved prepared configuration rejected before signing", err)
	}

	if err := c.publisher.RunOnce(t.Context(), c.f.now); err != nil {
		t.Fatal(err)
	}
	current := readPolicy()
	if current.Revision != before.Revision+1 || !slices.Contains(current.RequiredCapabilities, feature) ||
		!bytes.Equal(mustDecodeAdaptiveEngine(t, current.EngineConfigB64), prepared.EngineConfig) {
		var code string
		if err := fixtureOwner.QueryRow(`SELECT publication_error FROM identity_devices WHERE id=$1`, c.session.DeviceID).Scan(&code); err != nil {
			t.Fatal(err)
		}
		retryErr := c.publisher.publish(t.Context(), c.session.DeviceID, c.f.now)
		t.Fatalf("signed policy mismatch: previousRevision=%d newRevision=%d capabilityPresent=%t bytesMatch=%t workerCode=%q isolatedPublishError=%v",
			before.Revision, current.Revision, slices.Contains(current.RequiredCapabilities, feature), bytes.Equal(mustDecodeAdaptiveEngine(t, current.EngineConfigB64), prepared.EngineConfig), code, retryErr)
	}
	return current
}
