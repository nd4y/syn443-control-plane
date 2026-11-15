//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

func configurationWorkFixture(t *testing.T) (networkFixture, *ConfigurationControl, LayerProposal, *configurationWorkStore) {
	t.Helper()
	n, c, p := configurationControlFixture(t)
	store, e := enrollment.NewStore(fixtureSigner, bytes.Repeat([]byte{91}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return n, c, p, &configurationWorkStore{Store: store, Verifier: c.Verifier, Origin: c.Origin, AssuranceACR: c.AssuranceACR}
}

func queueConfigurationWork(t *testing.T, n networkFixture, c *ConfigurationControl, p LayerProposal, operation string) ConfigurationRequestView {
	t.Helper()
	raw, token, proof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte(operation)), configurationPreviewInput{p})
	v, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	return v.(ConfigurationRequestView)
}

func TestConfigurationWorkOriginalReceiptAndAtomicResult(t *testing.T) {
	n, c, p, s := configurationWorkFixture(t)
	q := queueConfigurationWork(t, n, c, p, "synthetic work")
	w, e := s.claim(context.Background(), n.f.now)
	if e != nil || w.id != q.ID || w.attempts != 1 || w.lease == "" {
		t.Fatal("claim", e)
	}
	envelope, until, e := s.verify(context.Background(), w, n.f.now)
	if e != nil || envelope.Action != "configuration.preview.request" || until <= n.f.now.Unix() {
		t.Fatal("independent verification", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", w, w), w.id) {
		t.Fatal("work diagnostic leaked identity")
	}
	// This is a transaction marker, deliberately NOT a signed preview producer.
	effect := func(_ context.Context, tx *sql.Tx, _ time.Time, original invitation.Envelope) (json.RawMessage, error) {
		if original.RequestID != envelope.RequestID {
			t.Fatal("original request changed")
		}
		_, e := tx.Exec(`UPDATE identity_devices SET refresh_after=17 WHERE id=$1`, n.target.Device)
		return json.RawMessage(`{"fixtureOnly":true}`), e
	}
	if e = s.commit(context.Background(), w, n.f.now, effect); e != nil {
		t.Fatal(e)
	}
	var state string
	var result []byte
	var marker int64
	if e = fixtureOwner.QueryRow(`SELECT state,result FROM managed_configuration_requests WHERE id=$1`, w.id).Scan(&state, &result); e != nil || state != "ready" || string(result) != `{"fixtureOnly":true}` {
		t.Fatal("queue receipt", e)
	}
	if e = fixtureOwner.QueryRow(`SELECT refresh_after FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&marker); e != nil || marker != 17 {
		t.Fatal("effect missing", e)
	}
	called := false
	if e = s.commit(context.Background(), w, n.f.now, func(context.Context, *sql.Tx, time.Time, invitation.Envelope) (json.RawMessage, error) {
		called = true
		return result, nil
	}); e == nil || called {
		t.Fatal("late duplicate effect")
	}
	for _, table := range []string{"managed_configuration_previews", "managed_configuration_heads"} {
		var count int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("queue plumbing invented approval", table, e)
		}
	}
}

func TestConfigurationWorkRejectsForgedReceiptScopeAndStolenLease(t *testing.T) {
	n, c, p, s := configurationWorkFixture(t)
	queueConfigurationWork(t, n, c, p, "synthetic tamper work")
	w, e := s.claim(context.Background(), n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"id", "actor", "request", "action", "target", "kind", "hash", "cipher", "deadline", "lease", "attempts", "lease-until"} {
		t.Run(kind, func(t *testing.T) {
			bad := w
			switch kind {
			case "id":
				bad.id = identity.Hash([]byte("foreign work"))
			case "actor":
				bad.actor = identity.Hash([]byte("foreign actor"))
			case "request":
				bad.request = identity.Hash([]byte("foreign operation"))
			case "action":
				bad.action = "configuration.publish"
			case "target":
				bad.target = "foreign-device"
			case "kind":
				bad.kind = "group"
			case "hash":
				bad.hash = configurationHash([]byte("different body"))
			case "cipher":
				bad.receipt = append([]byte(nil), w.receipt...)
				bad.receipt[0] ^= 1
			case "deadline":
				bad.deadline++
			case "lease":
				bad.lease = "different-lease"
			case "attempts":
				bad.attempts++
			case "lease-until":
				bad.leaseUntil++
			}
			called := false
			err := s.commit(context.Background(), bad, n.f.now, func(context.Context, *sql.Tx, time.Time, invitation.Envelope) (json.RawMessage, error) {
				called = true
				return json.RawMessage(`{}`), nil
			})
			if err == nil || called {
				t.Fatal("forged work reached effect", kind, err)
			}
		})
	}
	prior := n.f.v.p
	n.f.v.p.Scope = "syn443.device"
	if _, _, e = s.verify(context.Background(), w, n.f.now); e == nil {
		t.Fatal("publisher trusted API scope")
	}
	n.f.v.p = prior
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	called := false
	if e = s.commit(context.Background(), w, n.f.now, func(context.Context, *sql.Tx, time.Time, invitation.Envelope) (json.RawMessage, error) {
		called = true
		return json.RawMessage(`{}`), nil
	}); e == nil || called {
		t.Fatal("revoked ACL reached effect")
	}
}

func TestConfigurationWorkLeasesRetryBoundsAndConcurrentAdmission(t *testing.T) {
	n, c, p, s := configurationWorkFixture(t)
	if w, e := s.claim(context.Background(), n.f.now); e != nil || w.id != "" {
		t.Fatal("empty queue", e)
	}
	for i := 0; i < 6; i++ {
		queueConfigurationWork(t, n, c, p, fmt.Sprint("synthetic parallel work", i))
	}
	var wg sync.WaitGroup
	works := make(chan configurationWork, 4)
	failures := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w, e := s.claim(context.Background(), n.f.now); works <- w; failures <- e }()
	}
	wg.Wait()
	close(works)
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	seen := map[string]bool{}
	var old configurationWork
	for w := range works {
		if w.id == "" || seen[w.id] {
			t.Fatal("duplicate claim")
		}
		seen[w.id] = true
		old = w
	}
	if w, e := s.claim(context.Background(), n.f.now); e != nil || w.id != "" {
		t.Fatal("concurrency limit", e)
	}
	// Advancing the fixture clock permits at most three leases per operation.
	for _, offset := range []time.Duration{21, 42, 63, 84, 105, 126, 147, 168, 189} {
		if _, e := s.claim(context.Background(), n.f.now.Add(offset*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	var attempts int
	var state string
	if e := fixtureOwner.QueryRow(`SELECT attempts,state FROM managed_configuration_requests WHERE id=$1`, old.id).Scan(&attempts, &state); e != nil || attempts > 3 || state != "expired" {
		t.Fatal("retry/deadline bound", attempts, state, e)
	}
	called := false
	if e := s.commit(context.Background(), old, n.f.now, func(context.Context, *sql.Tx, time.Time, invitation.Envelope) (json.RawMessage, error) {
		called = true
		return json.RawMessage(`{}`), nil
	}); e == nil || called {
		t.Fatal("stale lease reached effect")
	}
}

func TestConfigurationWorkRollsBackFailedCancelledMalformedAndExpiredEffects(t *testing.T) {
	n, c, p, s := configurationWorkFixture(t)
	queueConfigurationWork(t, n, c, p, "synthetic rollback work")
	w, e := s.claim(context.Background(), n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"error", "empty", "invalid", "oversized", "cancel", "session-expiry"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			oldPrincipal := n.f.v.p
			defer func() { n.f.v.p = oldPrincipal }()
			if kind == "session-expiry" {
				n.f.v.p.Expires = n.f.now.Unix() + 1
			}
			err := s.commit(ctx, w, n.f.now, func(ctx context.Context, tx *sql.Tx, _ time.Time, _ invitation.Envelope) (json.RawMessage, error) {
				if _, e := tx.ExecContext(ctx, `UPDATE identity_devices SET refresh_after=999 WHERE id=$1`, n.target.Device); e != nil {
					return nil, e
				}
				switch kind {
				case "error":
					return nil, enrollment.ErrConflict
				case "empty":
					return nil, nil
				case "invalid":
					return json.RawMessage(`{`), nil
				case "oversized":
					return json.RawMessage(`"` + strings.Repeat("x", 100001) + `"`), nil
				case "cancel":
					cancel()
				case "session-expiry":
					time.Sleep(1100 * time.Millisecond)
				}
				return json.RawMessage(`{}`), nil
			})
			if err == nil {
				t.Fatal("unsafe effect committed", kind)
			}
			var marker int64
			var state string
			if e := fixtureOwner.QueryRow(`SELECT refresh_after FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&marker); e != nil || marker == 999 {
				t.Fatal("effect escaped rollback", e)
			}
			if e := fixtureOwner.QueryRow(`SELECT state FROM managed_configuration_requests WHERE id=$1`, w.id).Scan(&state); e != nil || state != "running" {
				t.Fatal("failed work terminalized", e)
			}
		})
	}
	var missing *configurationWorkStore
	if _, e = missing.claim(context.Background(), n.f.now); e == nil {
		t.Fatal("nil store")
	}
	if e = missing.commit(context.Background(), w, n.f.now, nil); e == nil {
		t.Fatal("nil callback")
	}
	if _, _, e = s.verify(nil, w, n.f.now); e == nil {
		t.Fatal("nil context")
	}
	if _, e = s.claim(nil, n.f.now); e == nil {
		t.Fatal("nil claim context")
	}
	wrong := *s
	wrong.Store = c.Store
	if _, e = wrong.claim(context.Background(), n.f.now); e == nil {
		t.Fatal("API claimed publisher work")
	}
	if e = wrong.commit(context.Background(), w, n.f.now, func(context.Context, *sql.Tx, time.Time, invitation.Envelope) (json.RawMessage, error) {
		return nil, errors.New("forbidden")
	}); e == nil {
		t.Fatal("API completed publisher work")
	}
}

func TestConfigurationWorkLeaseExpiresWhileWaitingForActualRowLock(t *testing.T) {
	n, c, p, s := configurationWorkFixture(t)
	queueConfigurationWork(t, n, c, p, "synthetic lock expiry work")
	w, e := s.claim(context.Background(), n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	w.leaseUntil = n.f.now.Add(time.Second).UnixMilli()
	if _, e = fixtureOwner.Exec(`UPDATE managed_configuration_requests SET lease_until_ms=$2 WHERE id=$1`, w.id, w.leaseUntil); e != nil {
		t.Fatal(e)
	}
	block, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer block.Rollback()
	if _, e = block.Exec(`SELECT id FROM managed_configuration_requests WHERE id=$1 FOR UPDATE`, w.id); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	called := false
	go func() {
		done <- s.commit(context.Background(), w, n.f.now, func(context.Context, *sql.Tx, time.Time, invitation.Envelope) (json.RawMessage, error) {
			called = true
			return json.RawMessage(`{}`), nil
		})
	}()
	observed := false
	for i := 0; i < 100; i++ {
		var waiting int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE usename='syn443_identity_publisher' AND wait_event_type='Lock' AND query LIKE 'SELECT lease,state,actor,%'`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting > 0 {
			observed = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !observed {
		block.Rollback()
		<-done
		t.Fatal("publisher did not reach the actual guarded row lock")
	}
	time.Sleep(1100 * time.Millisecond)
	if e = block.Rollback(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e == nil || called {
		t.Fatal("expired waiter entered effect", e)
	}
}
