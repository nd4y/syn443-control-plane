//go:build postgres

package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func listPrivateDrafts(t *testing.T, n networkFixture, c *ConfigurationControl, kind, target string) (ConfigurationDraftInventory, error) {
	t.Helper()
	raw, token, proof := configurationCall(t, n, c, "configuration.layers.drafts.list", identity.Hash([]byte("private draft inventory")), map[string]string{"targetKind": kind, "targetId": target})
	value, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		return ConfigurationDraftInventory{}, e
	}
	return value.(ConfigurationDraftInventory), nil
}

func TestPrivateDraftInventoryIsActorTargetBoundedOrderedAndContainsNoBody(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	empty, e := listPrivateDrafts(t, n, c, p.TargetKind, p.TargetID)
	if e != nil || empty.Drafts == nil || len(empty.Drafts) != 0 {
		t.Fatal("empty private inventory", e)
	}
	for _, id := range []string{"draft-z", "draft-a"} {
		proposal := p
		proposal.DraftID = id
		if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "save "+id, map[string]any{"draft": ConfigurationDraft{ID: id, Proposal: proposal}}); e != nil {
			t.Fatal(e)
		}
	}
	// Equal timestamps have a stable ID order. Metadata listing deliberately
	// does not decrypt bodies; the separate get path checks their AEAD binding.
	if _, e = fixtureOwner.Exec(`UPDATE managed_configuration_drafts SET revision=revision+1,saved_ms=$2 WHERE actor=$1`, n.actor.ID, n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms)
 SELECT $2,'foreign-actor',target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms FROM managed_configuration_drafts WHERE actor=$1 LIMIT 1`, n.actor.ID, identity.Hash([]byte("another private editor"))); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms)
 SELECT actor,'another-target',target_kind,'another-device',revision,body_hash,body,saved_ms,expires_ms FROM managed_configuration_drafts WHERE actor=$1 LIMIT 1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms)
 SELECT actor,'expired',target_kind,target_id,revision,body_hash,body,$2::bigint-2,$2::bigint-1 FROM managed_configuration_drafts WHERE actor=$1 LIMIT 1`, n.actor.ID, n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	view, e := listPrivateDrafts(t, n, c, p.TargetKind, p.TargetID)
	if e != nil || view.TargetKind != p.TargetKind || view.TargetID != p.TargetID || len(view.Drafts) != 2 || view.Drafts[0].ID != "draft-a" || view.Drafts[1].ID != "draft-z" || view.Drafts[0].Revision != 2 {
		t.Fatal("private inventory binding/order", e)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "proposal") || strings.Contains(string(raw), "body") || strings.Contains(string(raw), "bundles") {
		t.Fatal("inventory exposed draft content")
	}
	if strings.Contains(fmt.Sprint(view), p.TargetID) || strings.Contains(fmt.Sprintf("%#v", view.Drafts[0]), "draft-a") {
		t.Fatal("private inventory logging is not redacted")
	}
	for _, table := range []string{"managed_configuration_requests", "managed_configuration_previews", "managed_configuration_versions", "managed_configuration_heads"} {
		var count int
		if e := fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("listing changed configuration authority", e)
		}
	}
}

func TestPrivateDraftInventoryRejectsExpiredAuthorityWithdrawalAndInvalidScope(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "save scoped list", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
		t.Fatal(e)
	}
	for _, scope := range [][2]string{{"unknown", p.TargetID}, {"device", "bad/id"}, {"device", ""}} {
		if _, e := listPrivateDrafts(t, n, c, scope[0], scope[1]); !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("invalid list scope", e)
		}
	}
	if _, e := c.draftInventory(context.Background(), n.actor.ID, p.TargetKind, p.TargetID, n.f.now.Unix(), n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("expired authority", e)
	}
	if _, e := c.draftInventory(context.Background(), identity.Hash([]byte("foreign list caller")), p.TargetKind, p.TargetID, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("foreign actor obtained inventory", e)
	}
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := listPrivateDrafts(t, n, c, p.TargetKind, p.TargetID); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("withdrawn rights retained list", e)
	}
}

func TestPrivateDraftInventoryReturnsAllCopiesAtItsExactBound(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "full list seed", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms) SELECT actor,'allowed-'||n,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms FROM managed_configuration_drafts CROSS JOIN generate_series(1,63)n WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	view, e := listPrivateDrafts(t, n, c, p.TargetKind, p.TargetID)
	if e != nil || len(view.Drafts) != 64 {
		t.Fatal("bounded inventory silently dropped a copy", e)
	}
}

func TestPrivateDraftInventoryFailsClosedForStorageFaultsAndQuotaContamination(t *testing.T) {
	for _, kind := range []string{"quota", "metadata", "privilege", "closed", "cancelled", "nil-context", "nil-store"} {
		t.Run(kind, func(t *testing.T) {
			n, c, p := configurationControlFixture(t)
			ctx := context.Background()
			if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "list storage seed", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
				t.Fatal(e)
			}
			var e error
			switch kind {
			case "quota":
				_, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms) SELECT actor,'overflow-'||n,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms FROM managed_configuration_drafts CROSS JOIN generate_series(1,64)n WHERE actor=$1`, n.actor.ID)
			case "metadata":
				_, e = fixtureOwner.Exec(`UPDATE managed_configuration_drafts SET revision=revision+1,saved_ms=-1 WHERE actor=$1`, n.actor.ID)
			case "privilege":
				_, e = fixtureOwner.Exec(`REVOKE SELECT ON managed_configuration_drafts FROM syn443_control_api`)
				t.Cleanup(func() {
					if _, err := fixtureOwner.Exec(`GRANT SELECT ON managed_configuration_drafts TO syn443_control_api`); err != nil {
						t.Error(err)
					}
				})
			case "closed":
				db, err := sql.Open("pgx", "")
				if err != nil {
					t.Fatal(err)
				}
				db.Close()
				store, err := enrollment.NewStore(db, make([]byte, 32))
				if err != nil {
					t.Fatal(err)
				}
				c.Store = store
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			case "nil-store":
				c.Store = nil
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = c.draftInventory(ctx, n.actor.ID, p.TargetKind, p.TargetID, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
				t.Fatal("storage failure became a successful empty list", e)
			}
		})
	}
}

func TestPrivateDraftInventoryRechecksAuthorityAfterAReadLockWait(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "delayed list seed", map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}}); e != nil {
		t.Fatal(e)
	}
	lock, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback()
	if _, e = lock.Exec(`SELECT id FROM managed_configuration_drafts WHERE actor=$1 FOR UPDATE`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := c.draftInventory(context.Background(), n.actor.ID, p.TargetKind, p.TargetID, n.f.now.Unix()+1, n.f.now)
		done <- e
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var waiting int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id,revision,saved_ms,expires_ms FROM managed_configuration_drafts%'`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture list did not reach the owned row lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(1100 * time.Millisecond)
	lock.Rollback()
	select {
	case e = <-done:
		if !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("expired authority returned metadata", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bounded list did not settle")
	}
}
