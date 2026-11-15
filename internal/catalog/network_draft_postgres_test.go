//go:build postgres

package catalog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNetworkDraftPersistenceCASLostReplyAndImmutableTarget(t *testing.T) {
	api, _, actor, now := databaseFixture(t)
	ctx := context.Background()
	initial := draftExample()
	saved, e := api.PutNetworkDraft(ctx, actor, initial, "save-a", now)
	if e != nil || saved.Revision != 1 || saved.SavedAt != now.Unix() {
		t.Fatal("draft save", e)
	}
	read, e := api.GetNetworkDraft(ctx, actor, initial.ID, now)
	if e != nil || !reflect.DeepEqual(saved, read) {
		t.Fatal("draft readback", e)
	}
	var ciphertext []byte
	if e = fixtureOwner.QueryRow(`SELECT body FROM catalog_network_drafts WHERE actor=$1 AND id=$2`, actor.ID, initial.ID).Scan(&ciphertext); e != nil || bytes.Contains(ciphertext, []byte("private-health.example.invalid")) {
		t.Fatal("draft stored in cleartext", e)
	}
	replay, e := api.PutNetworkDraft(ctx, actor, initial, "save-a", now)
	if e != nil || !reflect.DeepEqual(replay, saved) {
		t.Fatal("lost reply changed operation", e)
	}
	edit := saved
	edit.SavedAt = 0
	edit.Plan.Network.DNSStrategy = "ipv4_only"
	edit.BaseRevision, edit.BaseHash = 5, strings.Repeat("a", 64)
	updated, e := api.PutNetworkDraft(ctx, actor, edit, "save-b", now)
	if e != nil || updated.Revision != 2 {
		t.Fatal("expected revision edit", e)
	}
	if _, e = api.PutNetworkDraft(ctx, actor, initial, "stale-save", now); !errors.Is(e, ErrConflict) {
		t.Fatal("stale overwrite", e)
	}
	if _, e = api.PutNetworkDraft(ctx, actor, edit, "save-a", now); !errors.Is(e, ErrConflict) {
		t.Fatal("operation body reuse", e)
	}
	edit = updated
	edit.SavedAt = 0
	edit.TargetID = "another-device"
	if _, e = api.PutNetworkDraft(ctx, actor, edit, "scope-change", now); !errors.Is(e, ErrConflict) {
		t.Fatal("target migration", e)
	}
	if _, e = api.PutNetworkDraft(ctx, actor, initial, "save-a", now); e != nil {
		t.Fatal("old immutable receipt lost", e)
	}
	current, e := api.GetNetworkDraft(ctx, actor, initial.ID, now)
	if e != nil || !reflect.DeepEqual(current, updated) {
		t.Fatal("old receipt overwrote current draft", e)
	}
	var audit int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_audit WHERE action='configuration.draft.put'`).Scan(&audit); e != nil || audit != 2 {
		t.Fatal("idempotent audit count", e)
	}
}

func TestNetworkDraftPrivateActorLiveACLAndRestrictedRoles(t *testing.T) {
	api, _, actor, now := databaseFixture(t)
	ctx := context.Background()
	draft := draftExample()
	if _, e := api.PutNetworkDraft(ctx, actor, draft, "save-a", now); e != nil {
		t.Fatal(e)
	}
	other := actor
	other.ID = "another-admin"
	if _, e := fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'*','*','*',$2)`, other.ID, now.Add(time.Hour).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e := api.GetNetworkDraft(ctx, other, draft.ID, now); !errors.Is(e, ErrDenied) {
		t.Fatal("another administrator read a private draft", e)
	}
	if _, e := api.PutNetworkDraft(ctx, other, draft, "own-save", now); e != nil {
		t.Fatal("independent actor draft", e)
	}
	copy := draft
	copy.Revision, copy.SavedAt = 2, now.Unix()
	raw, _ := json.Marshal(copy)
	protected, e := api.seal(raw, draftAAD(actor.ID, draft.ID, 2))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE catalog_network_drafts SET revision=revision+1,body=$1 WHERE actor=$2`, protected, other.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := api.GetNetworkDraft(ctx, other, draft.ID, now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("cross actor/revision ciphertext accepted", e)
	}
	for _, db := range []*sql.DB{fixtureWorker, fixturePublisher} {
		if _, e := db.Exec(`SELECT body FROM catalog_network_drafts`); e == nil {
			t.Fatal("non-API runtime can read unapproved drafts")
		}
	}
	if _, e := fixtureAPI.Exec(`UPDATE catalog_network_drafts SET revision=revision+1,target_id='another-device' WHERE actor=$1`, actor.ID); e == nil {
		t.Fatal("SQL scope invariant bypassed")
	}
	if _, e := fixtureAPI.Exec(`DELETE FROM catalog_network_drafts WHERE actor=$1`, actor.ID); e == nil {
		t.Fatal("API deleted a version fence")
	}
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := api.GetNetworkDraft(ctx, actor, draft.ID, now); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked ACL read draft", e)
	}
	if _, e := api.PutNetworkDraft(ctx, actor, draft, "save-a", now); !errors.Is(e, ErrDenied) {
		t.Fatal("replay bypassed revoked ACL", e)
	}
}

func TestNetworkDraftOperationStorageHasABoundedPerActorBudget(t *testing.T) {
	api, _, actor, now := databaseFixture(t)
	if _, e := fixtureOwner.Exec(`INSERT INTO catalog_operations(actor,request_id,action,target,body_hash,response,expires) SELECT $1,'seed-'||n,'configuration.draft.put','draft-a','synthetic-hash',decode('00','hex'),$2 FROM generate_series(1,256) n`, actor.ID, now.Add(time.Hour).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e := api.PutNetworkDraft(context.Background(), actor, draftExample(), "bounded-save", now); !errors.Is(e, ErrQuota) {
		t.Fatal("unbounded operation storage", e)
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_network_drafts`).Scan(&count); e != nil || count != 0 {
		t.Fatal("quota left a partial draft", e)
	}
}

func TestNetworkDraftQuotaCorruptionUnavailableAndInputBoundaries(t *testing.T) {
	api, _, actor, now := databaseFixture(t)
	ctx := context.Background()
	for i := 0; i < 64; i++ {
		draft := draftExample()
		draft.ID = fmt.Sprintf("draft-%02d", i)
		if _, e := api.PutNetworkDraft(ctx, actor, draft, draft.ID, now); e != nil {
			t.Fatal("bounded draft capacity", e)
		}
	}
	if _, e := api.PutNetworkDraft(ctx, actor, draftExample(), "overflow", now); !errors.Is(e, ErrQuota) {
		t.Fatal("unbounded draft count", e)
	}
	bad := draftExample()
	bad.SavedAt = now.Unix()
	if _, e := api.PutNetworkDraft(ctx, actor, bad, "invalid", now); !errors.Is(e, ErrInvalid) {
		t.Fatal("caller set server timestamp", e)
	}
	bad = draftExample()
	bad.Revision = 9007199254740991
	if _, e := api.PutNetworkDraft(ctx, actor, bad, "invalid", now); !errors.Is(e, ErrInvalid) {
		t.Fatal("revision overflow", e)
	}
	bad.Revision = 4
	if _, e := api.PutNetworkDraft(ctx, actor, bad, "missing-base", now); !errors.Is(e, ErrConflict) {
		t.Fatal("missing expected revision", e)
	}
	if _, e := api.GetNetworkDraft(ctx, actor, "../other", now); !errors.Is(e, ErrInvalid) {
		t.Fatal("invalid read identifier", e)
	}
	if _, e := api.GetNetworkDraft(ctx, actor, "missing", now); !errors.Is(e, ErrDenied) {
		t.Fatal("unknown private draft disclosed", e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := api.GetNetworkDraft(cancelled, actor, "draft-00", now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unavailable transaction produced a read", e)
	}
	if _, e := api.PutNetworkDraft(cancelled, actor, draftExample(), "cancelled", now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unavailable transaction acknowledged save", e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE catalog_network_drafts SET revision=revision+1 WHERE actor=$1 AND id='draft-00'`, actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := api.GetNetworkDraft(ctx, actor, "draft-00", now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("revision/AAD corruption accepted", e)
	}
}

func TestNetworkDraftFinalFenceRejectsSessionOrACLExpiryAfterLockWait(t *testing.T) {
	for _, reason := range []string{"session", "acl"} {
		t.Run(reason, func(t *testing.T) {
			api, _, actor, now := databaseFixture(t)
			if reason == "session" {
				actor.SessionUntil = now.Add(time.Second).Unix()
			} else if _, e := fixtureOwner.Exec(`UPDATE catalog_acl SET expires=$1`, now.Add(time.Second).Unix()); e != nil {
				t.Fatal(e)
			}
			blocker, e := fixtureOwner.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer blocker.Rollback()
			if _, e = blocker.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "catalog-drafts/"+actor.ID); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, e := api.PutNetworkDraft(ctx, actor, draftExample(), "late-save", now); result <- e }()
			deadline := time.Now().Add(time.Second)
			for {
				var waiting bool
				if e = fixtureOwner.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)`).Scan(&waiting); e != nil {
					t.Fatal(e)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("save never reached owned lock wait")
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(1100 * time.Millisecond)
			if e = blocker.Rollback(); e != nil {
				t.Fatal(e)
			}
			if e = <-result; !errors.Is(e, ErrDenied) {
				t.Fatal("late save extended authority", e)
			}
			var count int
			if e = fixtureOwner.QueryRow(`SELECT (SELECT count(*) FROM catalog_network_drafts)+(SELECT count(*) FROM catalog_operations)+(SELECT count(*) FROM catalog_audit)`).Scan(&count); e != nil || count != 0 {
				t.Fatal("expired save left durable effects", e)
			}
		})
	}
}
