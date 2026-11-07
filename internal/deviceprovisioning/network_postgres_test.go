//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

type networkLayersFunc func(context.Context, enrollment.ConfigurationTarget, time.Time) (*ApprovedNetworkLayers, error)

func (f networkLayersFunc) PrepareLayers(ctx context.Context, target enrollment.ConfigurationTarget, now time.Time) (*ApprovedNetworkLayers, error) {
	return f(ctx, target, now)
}

type networkFenceFunc func(context.Context, *sql.Tx, time.Time) error

func (f networkFenceFunc) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	return f(ctx, tx, now)
}

type networkFixture struct {
	f         *fixture
	api       *catalog.Store
	actor     catalog.Actor
	source    catalog.Source
	ref       configuration.ProfileReference
	authority *NetworkAuthority
	target    enrollment.ConfigurationTarget
	approved  *ApprovedNetworkLayers
	publisher enrollment.Publisher
}

func newNetworkFixture(t *testing.T) networkFixture {
	t.Helper()
	f := newFixture(t)
	bridge, _, _ := f.bridge(t)
	state := f.approved(t)
	if e := bridge.Prepare(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	ready, e := f.signer.Ready(context.Background(), state.ID, f.verification(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	key := bytes.Repeat([]byte{81}, 32)
	api, e := catalog.NewStore(fixtureControl, key)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := catalog.NewStore(fixtureSourceWorker, key)
	if e != nil {
		t.Fatal(e)
	}
	reader, e := catalog.NewStore(fixtureSigner, key)
	if e != nil {
		t.Fatal(e)
	}
	actor := catalog.Actor{ID: identity.Hash([]byte(f.v.p.Issuer + "\x00" + f.v.p.Subject)), SessionUntil: f.now.Unix() + 7200, MFAUntil: f.now.Unix() + 300}
	source, e := api.PutSource(context.Background(), actor, catalog.Source{ID: "source-a", Owner: f.owner, Name: "Synthetic source", Mode: "manual", Format: "uri", Enabled: true, ValidUntil: f.now.Unix() + 7200, RefreshSeconds: 3600, MaxStaleSeconds: 3600, NetworkModes: []string{"wifi"}}, catalog.SecretPatch{Operation: "keep"}, "create-network", f.now)
	if e != nil {
		t.Fatal(e)
	}
	job, e := api.Queue(context.Background(), actor, source.ID, source.Revision, "import-network", []byte("http://proxy.example.invalid:443"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	claimed, e := worker.Claim(context.Background(), f.now)
	if e != nil || claimed.ID != job.ID {
		t.Fatal("source job", e)
	}
	input, salt, _, raw, e := worker.JobInput(context.Background(), claimed, f.now)
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := subscriptions.Import(input.ID, salt, input.Format, raw)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := worker.Complete(context.Background(), claimed, profiles, subscriptions.Quota{}, subscriptions.Cache{}, f.now)
	if e != nil || snapshot.State != "active" {
		t.Fatal("working source", e)
	}
	ref := configuration.ProfileReference{SourceID: source.ID, ProfileID: profiles[0].ID}
	plan := configuration.NetworkPlan{SchemaVersion: 1,
		Graph:      configuration.Graph{Profiles: map[string]configuration.ProfileReference{"proxy": ref, "alias": ref}, Chains: map[string]configuration.Chain{}, Balancers: map[string]configuration.Balancer{}, Final: "proxy"},
		Network:    configuration.NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4"},
		Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.invalid/generate_204", Required: true}}}}
	object, _ := json.Marshal(plan)
	var fields map[string]json.RawMessage
	if json.Unmarshal(object, &fields) != nil {
		t.Fatal("plan fixture")
	}
	changes := []configuration.Change{}
	for _, name := range []string{"schemaVersion", "graph", "network", "activation"} {
		changes = append(changes, configuration.Change{Path: "/" + name, Operation: "set", Value: fields[name]})
	}
	target := enrollment.ConfigurationTarget{Device: ready.Device, Owner: ready.Owner, Thumbprint: ready.Thumbprint, GrantHash: ready.GrantHash, Capabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}}
	approved := &ApprovedNetworkLayers{Target: target, Layers: []configuration.Layer{{ID: "template-a", Kind: "template", Revision: 1, Changes: changes}}, Mode: "wifi", UntilMs: f.now.Add(2 * time.Hour).UnixMilli(), Fence: networkFenceFunc(func(context.Context, *sql.Tx, time.Time) error { return nil })}
	authority := &NetworkAuthority{Sources: reader, Layers: networkLayersFunc(func(_ context.Context, received enrollment.ConfigurationTarget, _ time.Time) (*ApprovedNetworkLayers, error) {
		if !sameNetworkTarget(target, received) {
			t.Fatal("actual publication recipient changed")
		}
		return approved, nil
	})}
	publisher := enrollment.Publisher{Store: bridge.Identity, Verifier: f.v, Grants: bridge.Grants, Key: f.key, KeyID: "fixture-root", Origin: "https://api.example.invalid", InvitationApproval: bridge, Configurations: authority}
	return networkFixture{f, api, actor, source, ref, authority, target, approved, publisher}
}

func TestSQLNetworkAuthorityCompilesApprovedLayersAuthorizedSnapshotsAndSignsActualDevice(t *testing.T) {
	n := newNetworkFixture(t)
	calls := 0
	n.approved.Fence = networkFenceFunc(func(ctx context.Context, tx *sql.Tx, now time.Time) error {
		calls++
		var owner string
		if e := tx.QueryRowContext(ctx, `SELECT owner FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&owner); e != nil || owner != n.target.Owner {
			t.Fatal("independent transaction/recipient", e)
		}
		return nil
	})
	prepared, e := n.authority.Prepare(context.Background(), n.target, n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	if prepared.UntilMs != n.f.now.Add(time.Hour).UnixMilli() || !bytes.Contains(prepared.EngineConfig, []byte("proxy.example.invalid")) || bytes.Contains(prepared.EngineConfig, []byte("sourceId")) {
		t.Fatal("snapshot lease/compilation boundary")
	}
	if e = n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	var revision int64
	var cipher []byte
	if e = fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&revision, &cipher); e != nil || revision != 1 || calls != 2 {
		t.Fatal("publication/final fences", e, revision, calls)
	}
	plain, e := n.publisher.Store.Open(cipher, "publication/v1/"+n.target.Device+"/"+fmt.Sprint(revision))
	if e != nil {
		t.Fatal(e)
	}
	verified, e := policy.VerifyBound(string(plain), map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}, n.target.Device, n.target.Thumbprint, n.f.now)
	if e != nil || verified.OfflineUntilMs != prepared.UntilMs {
		t.Fatal("signed policy identity/lease", e)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(verified.EngineConfigB64)
	if !bytes.Equal(raw, prepared.EngineConfig) || verified.Activation.Checks[0].Target != "https://health.example.invalid/generate_204" {
		t.Fatal("publisher substituted template or health")
	}
	// Raw layer, target and snapshot data never appear through default diagnostics.
	if strings.Contains(fmt.Sprintf("%v %#v", n.approved, n.approved), n.target.Device) {
		t.Fatal("approval diagnostics")
	}
	// A no-subscription direct policy still goes through approval and the same
	// independent role guard; absence of sources is not a template fallback.
	n.approved.Layers[0].Changes[1].Value = json.RawMessage(`{"profiles":{},"chains":{},"balancers":{},"final":"direct"}`)
	direct, e := n.authority.Prepare(context.Background(), n.target, n.f.now)
	if e != nil {
		t.Fatal("approved direct config", e)
	}
	tx, e := fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = direct.Fence.Lock(context.Background(), tx, n.f.now); e != nil {
		t.Fatal(e)
	}
}

func TestSQLManagedRouteHealthRequiresAdvertisedDeviceCapability(t *testing.T) {
	n := newNetworkFixture(t)
	n.approved.Layers[0].Changes[2].Value = json.RawMessage(`{
 "schemaVersion":1,"requiredNetworks":["tcp"],"dnsFinal":"system","dnsStrategy":"prefer_ipv4",
 "routeChecks":[{"outbound":"proxy","required":true,"checks":[{"method":"tcp","target":"home.example.invalid:22"}]}]}`)
	n.authority.Layers = networkLayersFunc(func(_ context.Context, received enrollment.ConfigurationTarget, _ time.Time) (*ApprovedNetworkLayers, error) {
		approved := *n.approved
		approved.Target = received
		return &approved, nil
	})
	ctx := context.Background()
	if _, err := n.authority.Prepare(ctx, n.target, n.f.now); !errors.Is(err, enrollment.ErrDenied) {
		t.Fatal("checks published to a client without declared support", err)
	}
	target := n.target
	target.Capabilities = append(append([]string{}, target.Capabilities...), "route.health.v1")
	prepared, err := n.authority.Prepare(ctx, target, n.f.now)
	if err != nil || prepared == nil || !slices.Contains(prepared.RequiredCapabilities, "route.health.v1") {
		t.Fatal("route checks or capability missing from prepared policy", err)
	}
	var engine struct {
		Checks []configuration.OutboundCheckPlan `json:"route_checks"`
	}
	if err := json.Unmarshal(prepared.EngineConfig, &engine); err != nil || len(engine.Checks) != 1 ||
		engine.Checks[0].Outbound != "proxy" || !engine.Checks[0].Required ||
		len(engine.Checks[0].Checks) != 1 || engine.Checks[0].Checks[0].Target != "home.example.invalid:22" {
		t.Fatal("per-outbound health checks were changed before signing", err)
	}
}

func TestSQLNetworkAuthorityRejectsForeignUnapprovedAndUnavailableInputs(t *testing.T) {
	n := newNetworkFixture(t)
	for _, change := range []string{"nil", "fence", "owner", "device", "key", "grant", "revision", "capability", "expired", "far-future", "mode", "plan", "profile", "locked", "outage", "cancelled", "role"} {
		t.Run(change, func(t *testing.T) {
			copy := *n.approved
			encoded, _ := json.Marshal(n.approved.Layers)
			if json.Unmarshal(encoded, &copy.Layers) != nil {
				t.Fatal("fixture copy")
			}
			copy.Target.Capabilities = append([]string(nil), copy.Target.Capabilities...)
			a := *n.authority
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.Layers = networkLayersFunc(func(context.Context, enrollment.ConfigurationTarget, time.Time) (*ApprovedNetworkLayers, error) {
				if change == "outage" {
					return nil, enrollment.ErrUnavailable
				}
				if change == "nil" {
					return nil, nil
				}
				return &copy, nil
			})
			switch change {
			case "fence":
				copy.Fence = nil
			case "owner":
				copy.Target.Owner = "other-owner"
			case "device":
				copy.Target.Device = "other-device"
			case "key":
				copy.Target.Thumbprint = "other-key"
			case "grant":
				copy.Target.GrantHash = "other-grant"
			case "revision":
				copy.Target.CurrentRevision++
			case "capability":
				copy.Target.Capabilities[0] = "future.v1"
			case "expired":
				copy.UntilMs = n.f.now.UnixMilli()
			case "far-future":
				copy.UntilMs = n.f.now.Add(8 * 24 * time.Hour).UnixMilli()
			case "mode":
				copy.Mode = "invented"
			case "plan":
				copy.Layers[0].Changes[0].Value = json.RawMessage(`2`)
			case "profile":
				copy.Layers[0].Changes[1].Value = json.RawMessage(`{"profiles":{"proxy":{"sourceId":"source-a","profileId":"unknown"}},"chains":{},"balancers":{},"final":"proxy"}`)
			case "locked":
				copy.Layers[0].Permissions = []configuration.Permission{{Path: "/graph/final", Mode: "locked"}}
				copy.Layers = append(copy.Layers, configuration.Layer{ID: "device-a", Kind: "device", Revision: 1, Changes: []configuration.Change{{Path: "/graph/final", Operation: "set", Value: json.RawMessage(`"direct"`)}}})
			case "cancelled":
				cancel()
			case "role":
				a.Sources = n.api
			}
			if value, err := a.Prepare(ctx, n.target, n.f.now); err == nil || value != nil {
				t.Fatal("unapproved input published", change)
			}
		})
	}
	for _, a := range []*NetworkAuthority{nil, {}, {Layers: n.authority.Layers}, {Sources: n.authority.Sources}} {
		if _, e := a.Prepare(context.Background(), n.target, n.f.now); e == nil {
			t.Fatal("missing authority accepted")
		}
	}
	if _, e := n.authority.Prepare(nil, n.target, n.f.now); e == nil {
		t.Fatal("nil context accepted")
	}
}

func TestSQLNetworkAuthorityFinalLayerSourceAndExpiryFencesRetainUnsignedDevice(t *testing.T) {
	for _, change := range []string{"layer", "disabled", "share", "expiry", "cancel"} {
		t.Run(change, func(t *testing.T) {
			n := newNetworkFixture(t)
			prepared, e := n.authority.Prepare(context.Background(), n.target, n.f.now)
			if e != nil {
				t.Fatal(e)
			}
			now := n.f.now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "layer":
				prepared.Fence.(*networkFence).layers = networkFenceFunc(func(context.Context, *sql.Tx, time.Time) error { return enrollment.ErrDenied })
			case "disabled":
				if _, e = fixtureOwner.Exec(`UPDATE catalog_sources SET enabled=false WHERE id=$1`, n.source.ID); e != nil {
					t.Fatal(e)
				}
			case "share":
				if _, e = n.api.SetShares(context.Background(), n.actor, n.source.ID, n.source.Revision, catalog.Shares{Recipients: []catalog.Recipient{{Kind: "device", ID: "unrelated"}}}, "change-share-head", n.f.now); e != nil {
					t.Fatal(e)
				}
			case "expiry":
				now = now.Add(time.Hour)
			case "cancel":
				cancel()
			}
			tx, e := fixtureSigner.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if e = prepared.Fence.Lock(ctx, tx, now); e == nil {
				t.Fatal("late change ignored", change)
			}
			if change == "cancel" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation changed class", e)
			}
			var revision int64
			if e = fixtureOwner.QueryRow(`SELECT revision FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&revision); e != nil || revision != 0 {
				t.Fatal("fence altered publication", e)
			}
		})
	}
}
