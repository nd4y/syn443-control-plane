//go:build postgres

package deviceprovisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func discardCall(t *testing.T, n networkFixture, c *ConfigurationControl, operation string, input ConfigurationDraftDiscard) (ConfigurationDraftDiscarded, error) {
	t.Helper()
	raw, token, proof := configurationCall(t, n, c, "configuration.layers.draft.discard", identity.Hash([]byte(operation)), input)
	v, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		return ConfigurationDraftDiscarded{}, e
	}
	return v.(ConfigurationDraftDiscarded), nil
}

func TestPrivateDraftDiscardCASReplayTombstoneAndNoPublication(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	d := ConfigurationDraft{ID: p.DraftID, Proposal: p}
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "save before discard", map[string]any{"draft": d}); e != nil {
		t.Fatal(e)
	}
	input := ConfigurationDraftDiscard{ID: p.DraftID, Revision: 1, TargetKind: p.TargetKind, TargetID: p.TargetID}
	want := ConfigurationDraftDiscarded{ID: p.DraftID, Revision: 1, Discarded: true}
	for i := 0; i < 2; i++ {
		got, e := discardCall(t, n, c, "discard same operation", input)
		if e != nil || got != want {
			t.Fatal("discard/replay", e)
		}
	}
	if got, e := discardCall(t, n, c, "discard another request", input); e != nil || got != want {
		t.Fatal("idempotent target", e)
	}
	if _, e := draftCall(t, n, c, "configuration.layers.draft.get", "get discarded", map[string]string{"id": d.ID}); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("discarded proposal readable", e)
	}
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "save before discard", map[string]any{"draft": d}); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("old save reply resurrected draft", e)
	}
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "reuse discarded id", map[string]any{"draft": d}); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("tombstone reused", e)
	}
	list, e := c.draftInventory(context.Background(), n.actor.ID, p.TargetKind, p.TargetID, n.f.now.Unix()+60, n.f.now)
	if e != nil || len(list.Drafts) != 0 {
		t.Fatal("discarded draft listed", e)
	}
	var protected []byte
	var hash string
	if e = fixtureOwner.QueryRow(`SELECT body,body_hash FROM managed_configuration_drafts WHERE actor=$1 AND id=$2`, n.actor.ID, d.ID).Scan(&protected, &hash); e != nil {
		t.Fatal(e)
	}
	plain, e := c.Store.Open(protected, configurationDraftAAD(n.actor.ID, d.ID, 1))
	var stored ConfigurationDraftDiscarded
	if e != nil || identity.DecodeConfiguration(plain, &stored) != nil || stored != want || configurationHash(plain) != hash {
		t.Fatal("proposal not replaced with encrypted receipt", e)
	}
	for _, table := range []string{"managed_configuration_previews", "managed_configuration_versions", "managed_configuration_heads", "managed_configuration_requests", "managed_configuration_assignments"} {
		var count int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("discard changed authority", table, e)
		}
	}
	input.Revision = 2
	if _, e = discardCall(t, n, c, "discard same operation", input); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("changed revision", e)
	}
	// The terminal revision is removable without incrementing beyond safe JSON integers.
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms) VALUES($1,'maximum-draft',$2,$3,9007199254740991,'hash',decode(repeat('00',30),'hex'),$4,$5)`, n.actor.ID, p.TargetKind, p.TargetID, n.f.now.UnixMilli(), n.f.now.Add(time.Hour).UnixMilli()); e != nil {
		t.Fatal(e)
	}
	input.ID = "maximum-draft"
	input.Revision = 9007199254740991
	if _, e = discardCall(t, n, c, "discard maximum revision", input); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE managed_configuration_drafts SET discarded=false,revision=revision+1 WHERE actor=$1 AND id=$2`, n.actor.ID, d.ID); e == nil {
		t.Fatal("SQL resurrected tombstone")
	}
	if fmt.Sprint(input) != "PrivateDraftDiscard([redacted])" || fmt.Sprintf("%#v", want) != "PrivateDraftDiscarded([redacted])" || fmt.Sprint(want) != "PrivateDraftDiscarded([redacted])" || fmt.Sprintf("%#v", input) != "PrivateDraftDiscard([redacted])" {
		t.Fatal("unsafe diagnostic formatting")
	}
}

func TestPrivateDraftDiscardScopeExpiryQuotaAndReceiptIntegrity(t *testing.T) {
	for _, name := range []string{"stale", "target", "actor", "missing", "expired", "revoked", "quota", "changed-operation", "corrupt-receipt"} {
		t.Run(name, func(t *testing.T) {
			n, c, p := configurationControlFixture(t)
			if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "seed discard guards", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
				t.Fatal(e)
			}
			input := ConfigurationDraftDiscard{ID: p.DraftID, Revision: 1, TargetKind: p.TargetKind, TargetID: p.TargetID}
			actor, until := n.actor.ID, n.f.now.Unix()+60
			want := enrollment.ErrDenied
			op, hash := "guarded-discard", "first-body"
			switch name {
			case "stale":
				input.Revision = 2
				want = enrollment.ErrConflict
			case "target":
				input.TargetID = "foreign-device"
				want = enrollment.ErrConflict
			case "actor":
				actor = "foreign-actor"
			case "missing":
				input.ID = "missing-draft"
			case "expired":
				until = n.f.now.Unix()
			case "revoked":
				if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, actor); e != nil {
					t.Fatal(e)
				}
			case "quota":
				if _, e := fixtureOwner.Exec(`INSERT INTO managed_configuration_draft_ops(actor,request_id,body_hash,response,expires_ms) SELECT $1,'quota-'||n,'hash',decode(repeat('00',30),'hex'),$2 FROM generate_series(1,256)n`, actor, n.f.now.Add(time.Hour).UnixMilli()); e != nil {
					t.Fatal(e)
				}
			case "changed-operation", "corrupt-receipt":
				if _, e := c.discardDraft(context.Background(), actor, op, hash, input, until, n.f.now); e != nil {
					t.Fatal(e)
				}
				if name == "changed-operation" {
					hash = "different-body"
					want = enrollment.ErrConflict
				} else {
					if _, e := fixtureOwner.Exec(`UPDATE managed_configuration_draft_ops SET response=decode(repeat('00',30),'hex') WHERE actor=$1 AND request_id=$2`, actor, op); e != nil {
						t.Fatal(e)
					}
					want = enrollment.ErrUnavailable
				}
			}
			if _, e := c.discardDraft(context.Background(), actor, op, hash, input, until, n.f.now); !errors.Is(e, want) {
				t.Fatal(name, e)
			}
		})
	}
}

func TestPrivateDraftDiscardStorageCancellationMalformedAndConcurrentCAS(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	input := ConfigurationDraftDiscard{ID: p.DraftID, Revision: 1, TargetKind: p.TargetKind, TargetID: p.TargetID}
	for _, bad := range []ConfigurationDraftDiscard{{}, {ID: input.ID, Revision: 0, TargetKind: input.TargetKind, TargetID: input.TargetID}, {ID: input.ID, Revision: 9007199254740992, TargetKind: input.TargetKind, TargetID: input.TargetID}} {
		if _, e := c.discardDraft(context.Background(), n.actor.ID, "invalid", "hash", bad, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal(e)
		}
	}
	if _, e := c.discardDraft(nil, n.actor.ID, "nil", "hash", input, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.discardDraft(ctx, n.actor.ID, "cancelled", "hash", input, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "seed race", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := c.discardDraft(context.Background(), n.actor.ID, fmt.Sprint("race-", i), fmt.Sprint("hash-", i), input, n.f.now.Unix()+60, n.f.now)
			errorsCh <- e
		}(i)
	}
	wg.Wait()
	close(errorsCh)
	for e := range errorsCh {
		if e != nil {
			t.Fatal("idempotent concurrent discard", e)
		}
	}
}

func TestPrivateDraftDiscardRechecksAuthorityAfterActorLockWait(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "seed delayed discard", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
		t.Fatal(e)
	}
	lock, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback()
	if _, e = lock.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "configuration-private-drafts/"+n.actor.ID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := c.discardDraft(context.Background(), n.actor.ID, "delayed-discard", "body", ConfigurationDraftDiscard{ID: p.DraftID, Revision: 1, TargetKind: p.TargetKind, TargetID: p.TargetID}, n.f.now.Unix()+1, n.f.now)
		done <- e
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var waiting int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT pg_advisory_xact_lock%'`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("discard did not reach owned actor lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(1100 * time.Millisecond)
	lock.Rollback()
	select {
	case e = <-done:
		if !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("expired authority discarded copy", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("discard deadline")
	}
	var discarded bool
	if e = fixtureOwner.QueryRow(`SELECT discarded FROM managed_configuration_drafts WHERE actor=$1 AND id=$2`, n.actor.ID, p.DraftID).Scan(&discarded); e != nil || discarded {
		t.Fatal("expired mutation committed", e)
	}
}

func TestPrivateDraftDiscardSQLFailuresStayUnavailableAndRollBack(t *testing.T) {
	for _, scope := range [][2]string{{"SELECT", "managed_configuration_drafts"}, {"DELETE", "managed_configuration_draft_ops"}, {"UPDATE", "managed_configuration_drafts"}, {"INSERT", "managed_configuration_draft_ops"}} {
		t.Run(scope[0]+scope[1], func(t *testing.T) {
			n, c, p := configurationControlFixture(t)
			if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "seed storage-failure discard", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
				t.Fatal(e)
			}
			if _, e := fixtureOwner.Exec(`REVOKE ` + scope[0] + ` ON ` + scope[1] + ` FROM syn443_control_api`); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				if _, e := fixtureOwner.Exec(`GRANT ` + scope[0] + ` ON ` + scope[1] + ` TO syn443_control_api`); e != nil {
					t.Error(e)
				}
			})
			if _, e := c.discardDraft(context.Background(), n.actor.ID, "storage-discard", "body", ConfigurationDraftDiscard{ID: p.DraftID, Revision: 1, TargetKind: p.TargetKind, TargetID: p.TargetID}, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
				t.Fatal("storage error became success or denial", e)
			}
			var discarded bool
			if e := fixtureOwner.QueryRow(`SELECT discarded FROM managed_configuration_drafts WHERE actor=$1 AND id=$2`, n.actor.ID, p.DraftID).Scan(&discarded); e != nil || discarded {
				t.Fatal("failed transaction committed discard", e)
			}
		})
	}
}
