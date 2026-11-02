package enrollment

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

type fixtureConfigurationAuthority func(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error)

func (f fixtureConfigurationAuthority) Prepare(ctx context.Context, target ConfigurationTarget, now time.Time) (*PreparedConfiguration, error) {
	return f(ctx, target, now)
}

type fixtureConfigurationFence struct {
	calls int
	lock  func(context.Context, *sql.Tx, time.Time) error
}

func (f *fixtureConfigurationFence) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	f.calls++
	if f.lock != nil {
		return f.lock(ctx, tx, now)
	}
	return nil
}

func compiledFixtureNetwork(t *testing.T) json.RawMessage {
	t.Helper()
	graph, err := configuration.CompileGraph(configuration.Graph{Profiles: map[string]configuration.ProfileReference{"egress": {SourceID: "source", ProfileID: "source_profile"}}, Final: "egress"}, func(ref configuration.ProfileReference) (subscriptions.Profile, error) {
		if ref.SourceID != "source" || ref.ProfileID != "source_profile" {
			return subscriptions.Profile{}, configuration.ErrInvalid
		}
		return subscriptions.Profile{ID: ref.ProfileID, Kind: "http", Outbound: json.RawMessage(`{"type":"http","tag":"source_profile","server":"proxy.example.invalid","server_port":443}`)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := configuration.CompileNetwork(graph, configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func configuredPayload() (policy.Payload, time.Time) {
	now := time.Unix(1800000000, 0)
	p := policy.Payload{SchemaVersion: 2, Operation: "configure", Revision: 3, SecurityEpoch: 2, TargetDevice: "synthetic-device", KeyThumbprint: identity.Hash([]byte("synthetic key")), Audience: "syn443-device", IssuedAtMs: now.UnixMilli(), NotBeforeMs: now.UnixMilli(), RefreshAfterMs: now.UnixMilli() + 30000, OfflineUntilMs: now.UnixMilli() + 3600000, RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}, AlgorithmRevision: "m1-local-v1"}
	return p, now
}
func configuredPreparation(t *testing.T) (*PreparedConfiguration, policy.Payload, time.Time) {
	t.Helper()
	p, now := configuredPayload()
	return &PreparedConfiguration{EngineConfig: compiledFixtureNetwork(t), Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "public", Type: "https_204", Target: "https://health.example.invalid/generate_204", Required: true}}}, UntilMs: now.UnixMilli() + 60000, Fence: &fixtureConfigurationFence{}}, p, now
}

func TestPreparedConfigurationCannotChangeRecipientOrExtendGrantLease(t *testing.T) {
	prepared, p, now := configuredPreparation(t)
	original := p
	prepared.RequiredCapabilities = []string{"engine-config.v1"}
	if err := applyPreparedConfiguration(&p, prepared, p.RequiredCapabilities, now); err != nil {
		t.Fatal(err)
	}
	if p.TargetDevice != original.TargetDevice || p.KeyThumbprint != original.KeyThumbprint || p.Revision != original.Revision || p.Audience != original.Audience || p.SecurityEpoch != original.SecurityEpoch || p.AlgorithmRevision != original.AlgorithmRevision || p.OfflineUntilMs != prepared.UntilMs {
		t.Fatal("configuration escaped recipient or lease")
	}
	raw, err := base64.RawURLEncoding.DecodeString(p.EngineConfigB64)
	if err != nil || string(raw) != string(prepared.EngineConfig) || p.Validate(now) != nil || len(p.RequiredCapabilities) != 3 {
		t.Fatal("compiled document not bound")
	}
	prepared.Activation.Checks[0].Target = "https://changed.example.invalid"
	if p.Activation.Checks[0].Target == prepared.Activation.Checks[0].Target {
		t.Fatal("publisher retained mutable gate input")
	}
	prepared, p, now = configuredPreparation(t)
	prepared.UntilMs = p.OfflineUntilMs + 300000
	if applyPreparedConfiguration(&p, prepared, p.RequiredCapabilities, now) != nil || p.OfflineUntilMs != now.UnixMilli()+3600000 {
		t.Fatal("source preparation extended grant lease")
	}
}

func TestPreparedConfigurationRejectsUnfencedUnsupportedAndNativeAuthorityInputs(t *testing.T) {
	for index, change := range []func(*PreparedConfiguration){
		func(p *PreparedConfiguration) { p.Fence = nil }, func(p *PreparedConfiguration) { p.UntilMs = 0 }, func(p *PreparedConfiguration) { p.EngineConfig = nil }, func(p *PreparedConfiguration) { p.EngineConfig = json.RawMessage(strings.Repeat("x", 262145)) },
		func(p *PreparedConfiguration) { p.EngineConfig = json.RawMessage(`null`) }, func(p *PreparedConfiguration) { p.EngineConfig = json.RawMessage(`{}`) }, func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[],"route":{"final":"x"}}`)
		},
		func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"x"}],"route":{"final":"x"},"inbounds":[]}`)
		},
		func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"exec","tag":"x"}],"route":{"final":"x"}}`)
		},
		func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"x"},{"type":"direct","tag":"x"}],"route":{"final":"x"}}`)
		},
		func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"netbird","tag":"x","setup_key":"forbidden"}],"route":{"final":"x"}}`)
		},
		func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"netbird","tag":"x","state_directory":"/foreign"}],"route":{"final":"x"}}`)
		},
		func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"netbird","tag":"x","managed_namespace":"forbidden"}],"route":{"final":"x"}}`)
		},
		func(p *PreparedConfiguration) {
			p.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"netbird","tag":"x","credential_pending":true}],"route":{"final":"x"}}`)
		},
		func(p *PreparedConfiguration) { p.RequiredCapabilities = []string{"unsupported"} }, func(p *PreparedConfiguration) {
			p.RequiredCapabilities = []string{"engine-config.v1", "engine-config.v1"}
		}, func(p *PreparedConfiguration) { p.RequiredCapabilities = make([]string, 17) },
		func(p *PreparedConfiguration) { p.Activation.Checks = nil }, func(p *PreparedConfiguration) { p.Activation.TimeoutSeconds = 121 },
	} {
		t.Run(time.Duration(index).String(), func(t *testing.T) {
			prepared, p, now := configuredPreparation(t)
			change(prepared)
			if applyPreparedConfiguration(&p, prepared, p.RequiredCapabilities, now) == nil {
				t.Fatal("invalid prepared configuration signed")
			}
		})
	}
	p, now := configuredPayload()
	if !errors.Is(applyPreparedConfiguration(&p, nil, p.RequiredCapabilities, now), ErrDenied) {
		t.Fatal("missing authority fell back")
	}
	for _, raw := range []string{`{"outbounds":[{"type":"direct","tag":null}],"route":{"final":"x"}}`, `{"outbounds":[{"type":"direct","tag":"x"}],"route":{"final":"missing"}}`, `{"outbounds":null}`, `{"outbounds":[{"type":"direct","tag":"x","tag":"y"}],"route":{"final":"y"}}`} {
		if validatePreparedNetwork([]byte(raw)) == nil {
			t.Fatal("ambiguous graph accepted")
		}
	}
}
