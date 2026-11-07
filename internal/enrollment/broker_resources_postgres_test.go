//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func resourceCatalogFixture(t *testing.T) (*fixture, *BrokerResourceCatalog, *BrokerResourceCatalog) {
	t.Helper()
	f := newFixture(t, 1)
	key := bytes.Repeat([]byte{61}, 32)
	owner, e := NewBrokerResourceCatalog(fixtureOwner, key, false)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := NewBrokerResourceCatalog(fixtureBroker, key, false)
	if e != nil {
		t.Fatal(e)
	}
	return f, owner, worker
}

func putPinnedResourceVersions(t *testing.T, f *brokerFixture) (BrokerResource, BrokerResource, *BrokerResourceCatalog, *BrokerResourceCatalog) {
	t.Helper()
	ctx := context.Background()
	key := bytes.Repeat([]byte{61}, 32)
	owner, e := NewBrokerResourceCatalog(fixtureOwner, key, false)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := NewBrokerResourceCatalog(fixtureBroker, key, false)
	if e != nil {
		t.Fatal(e)
	}
	first := brokerResourceExample()
	first.ResourceID = f.scope.Binding.Address.ResourceID
	first.ManagementOrigin = f.scope.Binding.Address.ManagementURL
	first.NetworkID = f.scope.Binding.Address.NetworkID
	first.AccountID = f.scope.Account
	first.Groups = append([]string(nil), f.scope.Groups...)
	if e = owner.Put(ctx, first, 0, f.now); e != nil {
		t.Fatal(e)
	}
	next := first
	next.Revision = 2
	next.Token = "synthetic-replacement-management-token"
	if e = owner.Put(ctx, next, 1, f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	return first, next, owner, worker
}

func TestBrokerResourceRetirementWaitsForTerminalPinsAndPreservesHistory(t *testing.T) {
	f := newBrokerFixture(t)
	ctx := context.Background()
	first, next, owner, worker := putPinnedResourceVersions(t, f)
	at := f.now.Add(time.Minute)
	for _, db := range []*sql.DB{fixtureAPI, fixturePublisher, fixtureBroker} {
		if e := RetireBrokerResourceVersion(ctx, db, first.ResourceID, 1, 2, at); !errors.Is(e, ErrDenied) {
			t.Fatal("runtime role acquired retirement", e)
		}
	}
	if e := RetireBrokerResourceVersion(ctx, fixtureOwner, first.ResourceID, 2, 3, at); !errors.Is(e, ErrConflict) {
		t.Fatal("retired the current head", e)
	}
	if e := RetireBrokerResourceVersion(ctx, fixtureOwner, first.ResourceID, 1, 3, at); !errors.Is(e, ErrConflict) {
		t.Fatal("unexpected head authorized retirement", e)
	}
	var hash string
	var created int64
	if e := fixtureOwner.QueryRow(`SELECT body_hash,created_ms FROM identity_overlay_resource_versions WHERE resource=$1 AND revision=1`, first.ResourceID).Scan(&hash, &created); e != nil {
		t.Fatal(e)
	}
	f.reserve(t)
	if e := RetireBrokerResourceVersion(ctx, fixtureOwner, first.ResourceID, 1, 2, at); !errors.Is(e, ErrConflict) {
		t.Fatal("erased a credential with a live broker pin", e)
	}
	_, close, e := worker.Resolve(ctx, f.scope)
	if e != nil {
		t.Fatal("pinned credential unavailable", e)
	}
	close()
	if _, e = fixturePublisher.Exec(`UPDATE identity_overlay_broker SET retire=true WHERE device=$1`, f.session.DeviceID); e != nil {
		t.Fatal(e)
	}
	f.run(t)
	if f.state(t) != "retired" {
		t.Fatal("broker pin did not become terminal")
	}
	if e = RetireBrokerResourceVersion(ctx, fixtureOwner, first.ResourceID, 1, 2, at); e != nil {
		t.Fatal("terminal pin prevented erasure", e)
	}
	if e = RetireBrokerResourceVersion(ctx, fixtureOwner, first.ResourceID, 1, 2, at.Add(time.Second)); e != nil {
		t.Fatal("retirement readback not idempotent", e)
	}
	var absent bool
	var retired, gotCreated int64
	var gotHash string
	if e = fixtureOwner.QueryRow(`SELECT body IS NULL,retired_ms,body_hash,created_ms FROM identity_overlay_resource_versions WHERE resource=$1 AND revision=1`, first.ResourceID).Scan(&absent, &retired, &gotHash, &gotCreated); e != nil || !absent || retired != at.UnixMilli() || gotHash != hash || gotCreated != created {
		t.Fatal("retirement did not retain immutable history", e)
	}
	if _, _, e = worker.Resolve(ctx, f.scope); !errors.Is(e, ErrDenied) {
		t.Fatal("retired credential remained usable", e)
	}
	_, close, e = worker.Resolve(ctx, resourceScopeExample(next))
	if e != nil {
		t.Fatal("new credential changed", e)
	}
	close()
	if e = owner.Put(ctx, first, 0, at); !errors.Is(e, ErrConflict) {
		t.Fatal("late import reactivated a retired credential", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_overlay_resource_versions SET retired_ms=0 WHERE resource=$1 AND revision=1`, first.ResourceID); e == nil {
		t.Fatal("retirement marker could be reverted")
	}
}

func TestBrokerResourceRetirementBlocksNewReservationAndSharesTheWriteFence(t *testing.T) {
	f := newBrokerFixture(t)
	ctx := context.Background()
	first, _, _, _ := putPinnedResourceVersions(t, f)
	if e := RetireBrokerResourceVersion(ctx, fixtureOwner, first.ResourceID, 1, 2, f.now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	tx, e := fixturePublisher.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	e = f.overlayFixture.worker.ReserveOverlayBroker(ctx, tx, f.scope, &fixtureConfigurationFence{}, f.clock)
	var constraint *pgconn.PgError
	if !errors.As(e, &constraint) || constraint.Code != "23514" || constraint.Message != "overlay resource retired" {
		t.Fatal("retired resource accepted a new broker reservation", e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	var reservations int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_broker`).Scan(&reservations); e != nil || reservations != 0 {
		t.Fatal("rejected reservation leaked durable state", e)
	}
	current, e := fixturePublisher.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Rollback()
	scope := f.scope
	scope.ResourceRevision = 2
	if e = f.overlayFixture.worker.ReserveOverlayBroker(ctx, current, scope, &fixtureConfigurationFence{}, f.clock); e != nil {
		t.Fatal("current resource rejected", e)
	}
	probe, e := fixtureOwner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer probe.Rollback()
	var exclusive bool
	if e = probe.QueryRow(`SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "overlay-resource/"+first.ResourceID).Scan(&exclusive); e != nil || exclusive {
		t.Fatal("open reservation did not hold the resource retirement fence", e)
	}
	if e = current.Commit(); e != nil {
		t.Fatal(e)
	}
}

func TestBrokerResourceCatalogImmutableRotationAndPinnedCleanupAuthority(t *testing.T) {
	f, owner, worker := resourceCatalogFixture(t)
	ctx := context.Background()
	r := brokerResourceExample()
	if e := owner.Put(ctx, r, 0, f.now); e != nil {
		t.Fatal(e)
	}
	next := r
	next.Revision = 2
	next.Token = "synthetic-replacement-management-token"
	if e := owner.Put(ctx, next, 1, f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	// A late acknowledgement of version1 must not undo version2 or require an
	// old PAT in process bootstrap. Both exact versions remain resolvable.
	if e := owner.Put(ctx, r, 0, f.now.Add(2*time.Second)); e != nil {
		t.Fatal("lost owner acknowledgement", e)
	}
	for _, resource := range []BrokerResource{r, next} {
		provider, close, e := worker.Resolve(ctx, resourceScopeExample(resource))
		if e != nil {
			t.Fatal("pinned resource", e)
		}
		id, account := provider.Authority()
		close()
		if id != r.ResourceID || account != r.AccountID {
			t.Fatal("foreign provider authority")
		}
	}
	changed := r
	changed.Token = next.Token
	if e := owner.Put(ctx, changed, 0, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("immutable PAT overwritten", e)
	}
	skipped := next
	skipped.Revision = 4
	if e := owner.Put(ctx, skipped, 3, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("resource revision skipped", e)
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_resource_versions`).Scan(&count); e != nil || count != 2 {
		t.Fatal(count, e)
	}
	var body []byte
	if e := fixtureBroker.QueryRow(`SELECT body FROM identity_overlay_resource_versions WHERE resource=$1 AND revision=1`, r.ResourceID).Scan(&body); e != nil || bytes.Contains(body, []byte(r.Token)) {
		t.Fatal("PAT not encrypted", e)
	}
	for _, db := range []*sql.DB{fixtureAPI, fixturePublisher} {
		rows, e := db.Query(`SELECT body FROM identity_overlay_resource_versions`)
		if e == nil {
			rows.Close()
			t.Fatal("identity API/publisher read management PAT history")
		}
	}
	for _, query := range []string{`UPDATE identity_overlay_resource_versions SET body=body`, `DELETE FROM identity_overlay_resource_versions`} {
		if _, e := fixtureOwner.Exec(query); e == nil {
			t.Fatal("immutable resource trigger bypassed")
		}
	}
	if e := worker.Put(ctx, next, 1, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("provider worker acquired owner mutation", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", worker, worker), r.Token) {
		t.Fatal("catalog diagnostics exposed credential")
	}
}

func TestBrokerResourceCatalogRequiresExactScopeCipherAndProcessRole(t *testing.T) {
	f, owner, worker := resourceCatalogFixture(t)
	ctx := context.Background()
	r := brokerResourceExample()
	if e := owner.Put(ctx, r, 0, f.now); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*BrokerScope){
		func(s *BrokerScope) { s.ResourceRevision++ },
		func(s *BrokerScope) { s.Account = "another-account" },
		func(s *BrokerScope) { s.Binding.Address.NetworkID = "another-network" },
		func(s *BrokerScope) { s.Groups = []string{"another-group"} },
	} {
		scope := resourceScopeExample(r)
		mutate(&scope)
		if _, _, e := worker.Resolve(ctx, scope); !errors.Is(e, ErrDenied) {
			t.Fatal("foreign resource scope", e)
		}
	}
	bad, e := NewBrokerResourceCatalog(fixtureBroker, bytes.Repeat([]byte{62}, 32), false)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = bad.Resolve(ctx, resourceScopeExample(r)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wrong resource key accepted", e)
	}
	if _, _, e = owner.Resolve(ctx, resourceScopeExample(r)); !errors.Is(e, ErrDenied) {
		t.Fatal("owner credential used as runtime role", e)
	}
	if _, e = fixtureOwner.Exec(`GRANT TRUNCATE ON identity_overlay_resource_versions TO syn443_overlay_worker`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := fixtureOwner.Exec(`REVOKE TRUNCATE ON identity_overlay_resource_versions FROM syn443_overlay_worker`); e != nil {
			t.Error(e)
		}
	})
	if e = worker.RuntimeRole(ctx); !errors.Is(e, ErrDenied) {
		t.Fatal("destructive privilege contamination accepted", e)
	}
}

func TestBrokerResourceCatalogInvalidInputsAndCancellation(t *testing.T) {
	f, owner, worker := resourceCatalogFixture(t)
	r := brokerResourceExample()
	if _, e := NewBrokerResourceCatalog(nil, make([]byte, 32), false); e == nil {
		t.Fatal("missing database")
	}
	if _, e := NewBrokerResourceCatalog(fixtureOwner, make([]byte, 31), false); e == nil {
		t.Fatal("invalid key")
	}
	for _, previous := range []int64{-1, 1, 9007199254740991} {
		if e := owner.Put(context.Background(), r, previous, f.now); e == nil {
			t.Fatal("invalid CAS metadata")
		}
	}
	bad := r
	bad.Token = ""
	if e := owner.Put(context.Background(), bad, 0, f.now); e == nil {
		t.Fatal("invalid provider definition")
	}
	if e := owner.Put(nil, r, 0, f.now); e == nil {
		t.Fatal("missing context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := owner.Put(ctx, r, 0, f.now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("cancelled owner effect", e)
	}
	if _, _, e := worker.Resolve(ctx, resourceScopeExample(r)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("cancelled provider resolution", e)
	}
	if _, _, e := worker.Resolve(nil, resourceScopeExample(r)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("nil provider context", e)
	}
	var absent *BrokerResourceCatalog
	if e := absent.RuntimeRole(context.Background()); !errors.Is(e, ErrDenied) {
		t.Fatal("missing catalog role")
	}
	closed, e := sql.Open("pgx", fixtureBrokerDSN)
	if e != nil {
		t.Fatal(e)
	}
	closed.Close()
	broken, e := NewBrokerResourceCatalog(closed, bytes.Repeat([]byte{61}, 32), false)
	if e != nil {
		t.Fatal(e)
	}
	if e = broken.Put(context.Background(), r, 0, f.now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("closed SQL owner connection", e)
	}
	if _, _, e = broken.Resolve(context.Background(), resourceScopeExample(r)); e == nil {
		t.Fatal("closed SQL resolver connection")
	}
}
