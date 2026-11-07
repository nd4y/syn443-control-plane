//go:build postgres

package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func selectionFixture(t *testing.T) (*Store, *Store, *Store, Actor, Source, Snapshot, ProfileReference, time.Time) {
	t.Helper()
	api, worker, actor, now := databaseFixture(t)
	source := mustSource(t, api, actor, sourceExample(now), "create-selection-source", now)
	job, profiles := manualWork(t, api, worker, actor, source, "import-selection-source", "http://proxy.example.invalid:443", now)
	snapshot, e := worker.Complete(context.Background(), job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
	if e != nil || snapshot.State != "active" {
		t.Fatal("selection fixture", e)
	}
	reader := *api
	reader.DB = fixturePublisher
	return api, worker, &reader, actor, source, snapshot, ProfileReference{source.ID, profiles[0].ID}, now
}
func lockSelection(t *testing.T, p *PreparedSelection, now time.Time) error {
	t.Helper()
	tx, e := fixturePublisher.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = p.Lock(context.Background(), tx, now); e != nil {
		return e
	}
	return tx.Commit()
}
func TestSQLSignerSourceSelectionScopesCopiesAndReadOnlyRole(t *testing.T) {
	api, _, reader, actor, source, snapshot, ref, now := selectionFixture(t)
	ctx := context.Background()
	if reader.PublicationRole(ctx) != nil || api.PublicationRole(ctx) == nil {
		t.Fatal("independent reader role guard")
	}
	for _, statement := range []string{`SELECT secrets FROM catalog_sources`, `SELECT secrets FROM catalog_resources`, `SELECT * FROM catalog_jobs`, `UPDATE catalog_sources SET enabled=false`, `INSERT INTO catalog_source_grants VALUES('forged','user','forged')`, `SELECT * FROM catalog_acl`} {
		if _, e := fixturePublisher.Exec(statement); e == nil {
			t.Fatal("signer gained fetch/admin mutation authority")
		}
	}
	target := SelectionTarget{source.Owner, "device-a"}
	prepared, e := reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+604800, now)
	if e != nil {
		t.Fatal(e)
	}
	if prepared.ValidUntil() != snapshot.ValidUntil || len(prepared.Dependencies()) != 1 || prepared.Dependencies()[0].SnapshotHash != snapshot.Hash {
		t.Fatal("immutable dependency or lease clamp")
	}
	profile, ok := prepared.Profile(ref)
	if !ok || len(profile.Outbound) == 0 {
		t.Fatal("selected profile missing")
	}
	profile.Outbound[0] = '!'
	again, _ := prepared.Profile(ref)
	if again.Outbound[0] != '{' {
		t.Fatal("caller mutated prepared profile")
	}
	dependencies := prepared.Dependencies()
	dependencies[0].SnapshotHash = "forged"
	if prepared.Dependencies()[0].SnapshotHash != snapshot.Hash {
		t.Fatal("caller mutated signer fence")
	}
	if _, ok = prepared.Profile(ProfileReference{source.ID, "missing"}); ok {
		t.Fatal("unrequested profile exposed")
	}
	if e = lockSelection(t, prepared, now); e != nil {
		t.Fatal("unchanged source rejected", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", prepared, prepared, target, target), source.Owner) {
		t.Fatal("selection diagnostics reveal identity")
	}
	for _, other := range []SelectionTarget{{"user-b", "device-b"}, {source.Owner, ""}} {
		if _, e = reader.PrepareSelection(ctx, other, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); e == nil {
			t.Fatal("foreign/invalid recipient accepted")
		}
	}
	shares, e := api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Recipients: []Recipient{{Kind: "user", ID: "user-b"}}}, "share-selection", now)
	if e != nil {
		t.Fatal(e)
	}
	target = SelectionTarget{"user-b", "device-b"}
	shared, e := reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now)
	if e != nil {
		t.Fatal("explicit recipient denied", e)
	}
	if _, e = api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Revision: shares.Revision}, "revoke-selection-share", now); e != nil {
		t.Fatal(e)
	}
	if e = lockSelection(t, shared, now); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked share passed final signer fence", e)
	}
	if _, e = api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Revision: 2, Recipients: []Recipient{{Kind: "device", ID: target.Device}}}, "share-selection-device", now); e != nil {
		t.Fatal(e)
	}
	if _, e = reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); e != nil {
		t.Fatal("explicit device denied", e)
	}
	if _, e = reader.PrepareSelection(ctx, SelectionTarget{"user-b", "other-device"}, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); !errors.Is(e, ErrDenied) {
		t.Fatal("device grant widened", e)
	}
}
func TestSQLSourceSelectionRejectsChangesBetweenCompileAndFinalCommit(t *testing.T) {
	for _, change := range []string{"metadata", "snapshot", "disabled", "revoked", "quota", "expired", "share-version"} {
		t.Run(change, func(t *testing.T) {
			api, worker, reader, actor, source, _, ref, now := selectionFixture(t)
			ctx := context.Background()
			prepared, e := reader.PrepareSelection(ctx, SelectionTarget{source.Owner, "device-a"}, []ProfileReference{ref}, "wifi", now.Unix()+3600, now)
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "metadata":
				source.Name = "Changed source metadata"
				mustSource(t, api, actor, source, "change-selection-metadata", now)
			case "disabled":
				source.Enabled = false
				mustSource(t, api, actor, source, "disable-selection-source", now)
			case "revoked", "quota":
				access := "revoked"
				if change == "quota" {
					access = "quota_exhausted"
				}
				if _, e = fixtureOwner.Exec(`UPDATE catalog_sources SET state='pending',access_state=$2 WHERE id=$1`, source.ID, access); e != nil {
					t.Fatal(e)
				}
			case "expired":
				now = time.Unix(prepared.ValidUntil(), 0)
			case "share-version":
				if _, e = api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Recipients: []Recipient{{Kind: "user", ID: "user-b"}}}, "share-version-change", now); e != nil {
					t.Fatal(e)
				}
			case "snapshot":
				job, profiles := manualWork(t, api, worker, actor, source, "next-selection-snapshot", "http://proxy.example.invalid:443#renamed", now.Add(time.Second))
				if _, e = worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now.Add(time.Second)); e != nil {
					t.Fatal(e)
				}
			}
			if e = lockSelection(t, prepared, now); e == nil {
				t.Fatal("stale/unauthorized inputs passed final signer fence")
			}
		})
	}
}
func TestSQLSourceSelectionRetainsPermittedLastGoodOnlyWithinCurrentBounds(t *testing.T) {
	api, _, reader, actor, source, _, ref, now := selectionFixture(t)
	ctx := context.Background()
	target := SelectionTarget{source.Owner, "device-a"}
	// A transient refresh error is not an access grant and does not delete a
	// previously authorized snapshot. Hard access_state still fences every read.
	if _, e := fixtureOwner.Exec(`UPDATE catalog_sources SET state='refresh_failed' WHERE id=$1`, source.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); e != nil {
		t.Fatal("authorized last good lost", e)
	}
	source.MaxStaleSeconds = 300
	mustSource(t, api, actor, source, "tighten-selection-stale", now)
	p, e := reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now)
	if e != nil || p.ValidUntil() != now.Unix()+300 {
		t.Fatal("metadata extended source freshness", e)
	}
	if _, e = reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now.Add(300*time.Second)); !errors.Is(e, ErrDenied) {
		t.Fatal("stale snapshot renewed", e)
	}
}
func TestSQLSourceSelectionDoesNotTrustStoredProfileIDOrCiphertext(t *testing.T) {
	for _, change := range []string{"ciphertext", "profile-id", "invalid-outbound", "budget"} {
		t.Run(change, func(t *testing.T) {
			_, _, reader, _, source, snapshot, ref, now := selectionFixture(t)
			ctx := context.Background()
			var protected []byte
			if e := fixtureOwner.QueryRow(`SELECT profiles FROM catalog_snapshots WHERE id=$1`, snapshot.ID).Scan(&protected); e != nil {
				t.Fatal(e)
			}
			if change == "ciphertext" {
				protected[len(protected)-1] ^= 1
			} else {
				raw, e := reader.open(protected, aad("snapshot", source.ID+"/"+snapshot.ID, snapshot.SourceRevision))
				if e != nil {
					t.Fatal(e)
				}
				var profiles []StoredProfile
				if json.Unmarshal(raw, &profiles) != nil {
					t.Fatal("fixture profiles")
				}
				if change == "profile-id" {
					var node map[string]any
					_ = json.Unmarshal(profiles[0].Outbound, &node)
					node["server"] = "changed.example.invalid"
					profiles[0].Outbound, _ = json.Marshal(node)
				}
				if change == "invalid-outbound" {
					profiles[0].Outbound = json.RawMessage(`{"type":"direct","tag":"forged"}`)
				}
				if change == "budget" {
					profiles[0].Name = strings.Repeat("x", 17*1024*1024)
				}
				raw, _ = json.Marshal(profiles)
				snapshot.Hash = reader.hash(raw)
				protected, e = reader.seal(raw, aad("snapshot", source.ID+"/"+snapshot.ID, snapshot.SourceRevision))
				if e != nil {
					t.Fatal(e)
				}
			}
			// Owned fixture corruption intentionally bypasses only the immutable-row
			// trigger; runtime roles never have this privilege. Restore it before read.
			tx, e := fixtureOwner.Begin()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(`ALTER TABLE catalog_snapshots DISABLE TRIGGER catalog_snapshot_guard`); e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(`UPDATE catalog_snapshots SET profiles=$2,content_hash=$3 WHERE id=$1`, snapshot.ID, protected, snapshot.Hash); e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(`ALTER TABLE catalog_snapshots ENABLE TRIGGER catalog_snapshot_guard`); e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			if _, e = reader.PrepareSelection(ctx, SelectionTarget{source.Owner, "device-a"}, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); e == nil {
				t.Fatal("forged or oversized snapshot selected")
			}
		})
	}
}
func TestSQLSourceSelectionResourceRotationAndDeviceSourceCannotWidenRecipients(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	reader := *api
	reader.DB = fixturePublisher
	resource, e := api.PutResource(ctx, actor, resourceExample(), resourceSecret("https://panel.example.invalid"), "", "selection-panel", now)
	if e != nil {
		t.Fatal(e)
	}
	draft := sourceExample(now)
	draft.Mode = "resource"
	draft.ResourceID = resource.ID
	draft.ExternalUserID = "42"
	source := mustSource(t, api, actor, draft, "selection-panel-source", now)
	if _, e = api.Queue(ctx, actor, source.ID, source.Revision, "selection-resource-fetch", nil, now); e != nil {
		t.Fatal(e)
	}
	job, e := worker.Claim(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	_, salt, _, _, e := worker.JobInput(ctx, job, now)
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := subscriptions.Import(source.ID, salt, "uri", []byte("http://resource-proxy.example.invalid:443"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now); e != nil {
		t.Fatal(e)
	}
	ref := ProfileReference{source.ID, profiles[0].ID}
	target := SelectionTarget{source.Owner, "device-a"}
	prepared, e := reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now)
	if e != nil {
		t.Fatal(e)
	}
	r, impact, e := api.GetResource(ctx, actor, resource.ID, now)
	if e != nil {
		t.Fatal(e)
	}
	r = resourceDraft(r)
	r.Enabled = false
	if _, e = api.PutResource(ctx, actor, r, SecretPatch{Operation: "keep"}, impact.Hash, "disable-selection-resource", now); e != nil {
		t.Fatal(e)
	}
	if e = lockSelection(t, prepared, now); e == nil {
		t.Fatal("disabled provider resource passed signer fence")
	}
	device := sourceExample(now)
	device.ID = "device-source"
	device.Mode = "device"
	device.FetchDeviceID = "selection-device"
	device, e = api.PutSource(ctx, actor, device, SecretPatch{Operation: "replace", Value: []byte(`{"url":"https://subscription.example.invalid"}`)}, "selection-device-source", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reader.PrepareSelection(ctx, SelectionTarget{"foreign-user", "foreign-device"}, []ProfileReference{{device.ID, "untrusted-profile"}}, "wifi", now.Unix()+3600, now); !errors.Is(e, ErrDenied) {
		t.Fatal("personal device source shared", e)
	}
}
func TestSQLSourceSelectionCancellationAndStorageOutageFailClosed(t *testing.T) {
	_, _, reader, _, source, _, ref, now := selectionFixture(t)
	ctx := context.Background()
	target := SelectionTarget{source.Owner, "device-a"}
	prepared, e := reader.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now)
	if e != nil {
		t.Fatal(e)
	}
	hold, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer hold.Rollback()
	if _, e = hold.Exec(`SELECT id FROM catalog_sources WHERE id=$1 FOR UPDATE`, source.ID); e != nil {
		t.Fatal(e)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	tx, e := fixturePublisher.BeginTx(short, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = prepared.Lock(short, tx, now); e == nil {
		t.Fatal("blocked final source lock ignored cancellation")
	}
	if e = hold.Rollback(); e != nil {
		t.Fatal(e)
	}
	lost, e := sql.Open("pgx", "postgres://127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if e != nil {
		t.Fatal(e)
	}
	defer lost.Close()
	broken := *reader
	broken.DB = lost
	if broken.PublicationRole(ctx) == nil {
		t.Fatal("outage accepted as reader role")
	}
	if _, e = broken.PrepareSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("storage outage returned usable selection", e)
	}
	var absent *PreparedSelection
	if absent.Lock(ctx, nil, now) == nil {
		t.Fatal("absent source fence accepted")
	}
	if prepared.Lock(ctx, nil, now) == nil {
		t.Fatal("nil publication transaction accepted")
	}
}
