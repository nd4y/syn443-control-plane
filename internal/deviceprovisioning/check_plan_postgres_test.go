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
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

// Synthetic owner-approved history is deliberately separate from enrollment.
// It does not claim normal clients advertise or live devices approved v2.
func seedCheckPlanAvailability(t *testing.T, n *networkFixture) {
	t.Helper()
	var original []byte
	if e := fixtureOwner.QueryRow(`SELECT request_body FROM identity_devices WHERE id=$1 AND approved`, n.target.Device).Scan(&original); e != nil {
		t.Fatal(e)
	}
	var request enrollment.Request
	if identity.Decode(original, &request, true) != nil {
		t.Fatal("original request fixture")
	}
	base := append([]string(nil), request.Capabilities...)
	slices.Sort(base)
	baseRaw, _ := json.Marshal(base)
	caps := append([]string(nil), base...)
	for _, v := range []string{"route.health.v1", policy.RouteCheckPlanV2, policy.RouteExitCountry, policy.RouteExitIP} {
		if !slices.Contains(caps, v) {
			caps = append(caps, v)
		}
	}
	slices.Sort(caps)
	raw, _ := json.Marshal(caps)
	tx, e := fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO identity_capability_versions(device,revision,previous_hash,body_hash,capabilities,original_request_hash,request_hash,proof_hash,approved_ms) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8)`, n.target.Device, identity.Hash(baseRaw), identity.Hash(raw), raw, identity.Hash(original), identity.Hash([]byte("synthetic-check-plan-request")), identity.Hash([]byte("synthetic-check-plan-proof")), n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(`INSERT INTO identity_capability_heads(device,revision,body_hash) VALUES($1,1,$2)`, n.target.Device, identity.Hash(raw)); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(`UPDATE identity_devices SET refresh_after=0,retry_after=0 WHERE id=$1`, n.target.Device); e != nil {
		t.Fatal(e)
	}
	if tx.Commit() != nil {
		t.Fatal("capability fixture commit")
	}
	state, e := enrollment.EffectiveCapabilities(context.Background(), fixtureSigner, n.target.Device, request.Capabilities)
	if e != nil || state.Version != 1 || !slices.Equal(state.Capabilities, caps) {
		t.Fatal("actual immutable availability history not read", e)
	}
	n.target.Capabilities = append([]string(nil), state.Capabilities...)
	var retained []byte
	if e = fixtureOwner.QueryRow(`SELECT request_body FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&retained); e != nil || !bytes.Equal(original, retained) {
		t.Fatal("availability rewrote approved enrollment", e)
	}
}
func newCheckPlanNetworkFixture(t *testing.T) networkFixture {
	t.Helper()
	n := newNetworkFixture(t)
	if e := n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	if e := fixtureOwner.QueryRow(`SELECT revision FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&n.target.CurrentRevision); e != nil || n.target.CurrentRevision != 1 {
		t.Fatal("actual baseline missing", e)
	}
	seedCheckPlanAvailability(t, &n)
	n.approved.Layers[0].Changes[2].Value = json.RawMessage(`{"schemaVersion":1,"requiredNetworks":["tcp"],"dnsFinal":"system","dnsStrategy":"prefer_ipv4","routeChecks":[{"outbound":"proxy","required":true,"profile":{"schemaVersion":2,"id":"health","revision":1,"deadlineMs":12000,"leaves":[{"id":"country","check":{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU"}},{"id":"ip","check":{"method":"https_exit_ip","target":"https://ip.example.invalid/","expected_ip":"192.0.2.9"}},{"id":"tls","check":{"method":"tls","target":"https://tls.example.invalid/"}},{"id":"tcp","check":{"method":"tcp","target":"a.example.invalid:443"}}],"gates":["country","ip","tls"],"stages":[{"leaf":"tcp"}]}}]}`)
	n.authority.Layers = networkLayersFunc(func(_ context.Context, actual enrollment.ConfigurationTarget, _ time.Time) (*ApprovedNetworkLayers, error) {
		if actual.Device != n.target.Device || actual.Owner != n.target.Owner || actual.Thumbprint != n.target.Thumbprint || actual.GrantHash != n.target.GrantHash {
			return nil, enrollment.ErrDenied
		}
		owned := *n.approved
		owned.Target = actual
		owned.Target.Capabilities = append([]string(nil), actual.Capabilities...)
		return &owned, nil
	})
	return n
}
func retainedCheckPlanPublication(t *testing.T, n networkFixture) (int64, []byte) {
	t.Helper()
	var revision int64
	var body []byte
	if e := fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&revision, &body); e != nil {
		t.Fatal(e)
	}
	return revision, body
}

func TestSQLCheckPlanV2ActualPublisherSignsOnlyAddressedApprovedCapabilityAndOwnedProgram(t *testing.T) {
	n := newCheckPlanNetworkFixture(t)
	calls := 0
	n.approved.Fence = networkFenceFunc(func(ctx context.Context, tx *sql.Tx, _ time.Time) error {
		calls++
		var key string
		if e := tx.QueryRowContext(ctx, `SELECT jkt FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&key); e != nil || key != n.target.Thumbprint {
			return enrollment.ErrDenied
		}
		return nil
	})
	prepared, e := n.authority.Prepare(context.Background(), n.target, n.f.now)
	if e != nil || !slices.Contains(prepared.RequiredCapabilities, policy.RouteCheckPlanV2) || !slices.Contains(prepared.RequiredCapabilities, policy.RouteExitCountry) || !slices.Contains(prepared.RequiredCapabilities, policy.RouteExitIP) {
		t.Fatal("nested leaves lost capability requirements", e)
	}
	calls = 0
	if e = n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	revision, cipher := retainedCheckPlanPublication(t, n)
	if revision != 2 || calls != 2 {
		t.Fatal("initial/final real SQL fence missing", revision, calls)
	}
	plain, e := n.publisher.Store.Open(cipher, "publication/v1/"+n.target.Device+"/"+fmt.Sprint(revision))
	if e != nil {
		t.Fatal(e)
	}
	verified, e := policy.VerifyBound(string(plain), map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}, n.target.Device, n.target.Thumbprint, n.f.now)
	if e != nil || !slices.Contains(verified.RequiredCapabilities, policy.RouteCheckPlanV2) {
		t.Fatal("actual signed envelope missing v2 fence", e)
	}
	engine, e := base64.RawURLEncoding.Strict().DecodeString(verified.EngineConfigB64)
	if e != nil || !bytes.Equal(engine, prepared.EngineConfig) || !bytes.Contains(engine, []byte(`"profile":`)) || bytes.Contains(engine, []byte(`"checks":`)) {
		t.Fatal("actual signed profile flattened or substituted")
	}
	if _, e := policy.VerifyBound(string(plain), map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}, n.target.Device, identity.Hash([]byte("other-fixture-key")), n.f.now); e == nil {
		t.Fatal("profile crossed recipient-key boundary")
	}
}

func TestSQLCheckPlanV2OldAndDowngradedCapabilityTargetsCannotFlattenOrFallBack(t *testing.T) {
	n := newCheckPlanNetworkFixture(t)
	revision, before := retainedCheckPlanPublication(t, n)
	for _, cap := range []string{policy.RouteCheckPlanV2, "route.health.v1", policy.RouteExitCountry, policy.RouteExitIP} {
		old := n.target
		old.Capabilities = slices.DeleteFunc(append([]string(nil), old.Capabilities...), func(v string) bool { return v == cap })
		if prepared, e := n.authority.Prepare(context.Background(), old, n.f.now); !errors.Is(e, enrollment.ErrDenied) || prepared != nil {
			t.Fatal("unsupported addressed client got fallback/flattened policy", cap, e)
		}
	}
	for _, mutate := range []func(*enrollment.ConfigurationTarget){func(v *enrollment.ConfigurationTarget) { v.Thumbprint = identity.Hash([]byte("other-key")) }, func(v *enrollment.ConfigurationTarget) { v.Owner = "other-owner" }, func(v *enrollment.ConfigurationTarget) { v.GrantHash = identity.Hash([]byte("other-grant")) }} {
		other := n.target
		mutate(&other)
		if prepared, e := n.authority.Prepare(context.Background(), other, n.f.now); !errors.Is(e, enrollment.ErrDenied) || prepared != nil {
			t.Fatal("profile authority inferred from foreign target", e)
		}
	}
	afterRevision, after := retainedCheckPlanPublication(t, n)
	if revision != 1 || afterRevision != revision || !bytes.Equal(before, after) {
		t.Fatal("denied preparation changed baseline publication")
	}
}

func TestSQLCheckPlanV2FinalSourceLayerExpiryAndCancellationFencesPreserveBaseline(t *testing.T) {
	for _, change := range []string{"source", "layer", "expiry", "cancel"} {
		t.Run(change, func(t *testing.T) {
			n := newCheckPlanNetworkFixture(t)
			revision, before := retainedCheckPlanPublication(t, n)
			prepared, e := n.authority.Prepare(context.Background(), n.target, n.f.now)
			if e != nil {
				t.Fatal(e)
			}
			now := n.f.now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "source":
				if _, e = fixtureOwner.Exec(`UPDATE catalog_sources SET enabled=false WHERE id=$1`, n.source.ID); e != nil {
					t.Fatal(e)
				}
			case "layer":
				prepared.Fence.(*networkFence).layers = networkFenceFunc(func(context.Context, *sql.Tx, time.Time) error { return enrollment.ErrDenied })
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
				t.Fatal("late change passed profile final fence")
			}
			if change == "cancel" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation class changed", e)
			}
			_ = tx.Rollback()
			if change == "source" {
				if fallback, e := n.authority.Prepare(context.Background(), n.target, n.f.now); !errors.Is(e, catalog.ErrDenied) || fallback != nil {
					t.Fatal("revoked profile source fell back", e)
				}
			}
			afterRevision, after := retainedCheckPlanPublication(t, n)
			if afterRevision != revision || !bytes.Equal(before, after) {
				t.Fatal("failed final fence changed signed baseline")
			}
		})
	}
}

func TestSQLCheckPlanV2PublisherWaitsForConcurrentSourceRevokeWithoutIssuingProgram(t *testing.T) {
	n := newCheckPlanNetworkFixture(t)
	revision, before := retainedCheckPlanPublication(t, n)
	hold, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer hold.Rollback()
	if _, e = hold.Exec(`SELECT id FROM catalog_sources WHERE id=$1 FOR UPDATE`, n.source.ID); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- n.publisher.RunOnce(ctx, n.f.now) }()
	running := true
	defer func() {
		cancel()
		_ = hold.Rollback()
		if running {
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Error("owned publisher failed to retire after lock release")
			}
		}
	}()
	blocked := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if e = fixtureOwner.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='syn443_identity_publisher' AND wait_event_type='Lock' AND query LIKE '%catalog_sources%FOR SHARE%')`).Scan(&blocked); e != nil {
			t.Fatal(e)
		}
		if blocked {
			break
		}
		select {
		case e := <-finished:
			running = false
			t.Fatal("publisher did not wait for actual source row", e)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("real PostgreSQL source wait not observed")
	}
	if _, e = hold.Exec(`UPDATE catalog_sources SET enabled=false WHERE id=$1`, n.source.ID); e != nil {
		t.Fatal(e)
	}
	if e = hold.Commit(); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-finished:
		running = false
		if e != nil {
			t.Fatal("publisher retry bookkeeping", e)
		}
	case <-ctx.Done():
		t.Fatal("publisher did not finish after real lock owner released")
	}
	afterRevision, after := retainedCheckPlanPublication(t, n)
	if afterRevision != revision || !bytes.Equal(before, after) {
		t.Fatal("concurrent revoke issued a profile or erased baseline")
	}
}
