//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func TestSQLPortableNetBirdPublicationRequiresBrokerAndKeepsIdentityAcrossEmergencyTransport(t *testing.T) {
	f, p, brokers := brokerPolicyFixture(t)
	a := f.binding.Address
	plan := configuration.NetworkPlan{SchemaVersion: 1,
		Graph: configuration.Graph{Final: "direct", NetBird: &configuration.NetBirdNode{Tag: "home", OverlayID: a.OverlayID, ResourceID: a.ResourceID, NetworkID: a.NetworkID, IdentityEpoch: a.IdentityEpoch, ManagementURL: a.ManagementURL, Mode: "direct"},
			Profiles: map[string]configuration.ProfileReference{"entry": {SourceID: "synthetic", ProfileID: "entry_profile"}}, Chains: map[string]configuration.Chain{}, Balancers: map[string]configuration.Balancer{}},
		Network: configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp", "udp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4",
			DNSServers: map[string]configuration.DNSServer{"home-dns": {Transport: "netbird", Outbound: "home"}},
			DNSRules:   []configuration.DNSRule{{ID: "home-name", HostMatch: configuration.HostMatch{DomainSuffixes: []string{"home.example.invalid"}}, Server: "home-dns"}},
			Rules:      []configuration.RouteRule{{ID: "home-ip", IPPrefixes: []string{"100.64.0.0/10"}, Action: "route", Outbound: "home"}}},
		Activation: f.grant.Template.Activation}
	p.Configurations = fixtureConfigurationAuthority(func(ctx context.Context, target ConfigurationTarget, now time.Time) (*PreparedConfiguration, error) {
		if target.Device != f.session.DeviceID || target.Thumbprint != f.binding.KeyThumbprint {
			t.Fatal("recipient/key substitution")
		}
		compiled, e := configuration.CompileNetworkPlan(ctx, plan, func(ref configuration.ProfileReference) (subscriptions.Profile, error) {
			if ref.SourceID != "synthetic" || ref.ProfileID != "entry_profile" {
				return subscriptions.Profile{}, ErrDenied
			}
			return subscriptions.Profile{ID: ref.ProfileID, Kind: "vless", Outbound: json.RawMessage(`{"type":"vless","tag":"entry_profile","server":"entry.example.invalid","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"server_name":"entry.example.invalid"}}`)}, nil
		})
		if e != nil {
			return nil, e
		}
		return &PreparedConfiguration{EngineConfig: compiled.EngineConfig, Activation: compiled.Activation, RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "overlay.credentials.v1"}, UntilMs: now.Add(time.Hour).UnixMilli(), Fence: &fixtureConfigurationFence{}}, nil
	})
	if e := p.publish(context.Background(), f.session.DeviceID, f.now); e != nil {
		t.Fatal("portable direct publication", e)
	}
	head := currentBrokerHead(t, brokers, f.request.Namespace)
	revision, cipher, _ := publishedConfiguration(t, f.fixture, f.session.DeviceID)
	p.Brokers = nil
	if e := p.publish(context.Background(), f.session.DeviceID, f.now.Add(time.Second)); !errors.Is(e, ErrDenied) {
		t.Fatal("managed compiler output signed without independent broker", e)
	}
	retained, after, _ := publishedConfiguration(t, f.fixture, f.session.DeviceID)
	if retained != revision || !bytes.Equal(cipher, after) {
		t.Fatal("missing broker replaced last known good")
	}
	p.Brokers = brokers
	plan.Graph.NetBird.Mode = "vless"
	plan.Graph.NetBird.Detour = "entry"
	if e := p.publish(context.Background(), f.session.DeviceID, f.now.Add(2*time.Second)); e != nil {
		t.Fatal("portable emergency publication", e)
	}
	if next := currentBrokerHead(t, brokers, f.request.Namespace); !sameBrokerReference(head, next) {
		t.Fatal("transport switch allocated a new overlay identity/key")
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_broker`).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate broker admission", e, count)
	}
	_, _, bundle := publishedConfiguration(t, f.fixture, f.session.DeviceID)
	// Read the already verified SQL publication through the existing fixture
	// verifier, then inspect only its server-owned addressed native metadata.
	payload, e := policy.VerifyBound(bundle, f.api.Roots, f.session.DeviceID, f.binding.KeyThumbprint, f.now.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := base64.RawURLEncoding.DecodeString(payload.EngineConfigB64)
	if e != nil || !bytes.Contains(raw, []byte(`"connection_mode":"vless"`)) || !bytes.Contains(raw, []byte(`"outbound":"home"`)) || bytes.Contains(raw, []byte(`"setup_key"`)) {
		t.Fatal("portable DNS/transport/credential handoff", e)
	}
}
