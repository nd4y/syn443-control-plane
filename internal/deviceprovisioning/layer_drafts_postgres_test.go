//go:build postgres

package deviceprovisioning

import (
	"bytes"
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

func draftCall(t *testing.T, n networkFixture, c *ConfigurationControl, action, operation string, payload any) (ConfigurationDraft, error) {
	t.Helper()
	raw, token, proof := configurationCall(t, n, c, action, identity.Hash([]byte(operation)), payload)
	v, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		return ConfigurationDraft{}, e
	}
	return v.(ConfigurationDraft), nil
}

func TestPrivateLayerDraftBoundedStorageExpiryAndConcurrentEditors(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	d := ConfigurationDraft{ID: p.DraftID, Proposal: p}
	// Distinct operation IDs racing the same expected revision may commit only
	// once; a slow editor must reload instead of silently overwriting the winner.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw, _ := json.Marshal(d)
			_, e := c.putDraft(context.Background(), n.actor.ID, identity.Hash([]byte(fmt.Sprint("concurrent", i))), configurationHash(raw), d, n.f.now.Unix()+60, n.f.now)
			results <- e
		}(i)
	}
	wg.Wait()
	close(results)
	ok, conflicts := 0, 0
	for e := range results {
		if e == nil {
			ok++
		} else if errors.Is(e, enrollment.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatal("concurrent draft CAS", ok, conflicts)
	}
	if _, e := fixtureOwner.Exec(`INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms) SELECT $1,'synthetic-'||n,'device',$2,1,'hash',decode(repeat('00',30),'hex'),$3,$4 FROM generate_series(1,63)n`, n.actor.ID, p.TargetID, n.f.now.UnixMilli(), n.f.now.Add(time.Hour).UnixMilli()); e != nil {
		t.Fatal(e)
	}
	d.ID = "new-draft"
	d.Proposal.DraftID = d.ID
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "draft storage full", map[string]any{"draft": d}); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("unbounded draft bodies", e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE managed_configuration_drafts SET revision=revision+1,saved_ms=$2-2,expires_ms=$2-1 WHERE actor=$1 AND id LIKE 'synthetic-%'`, n.actor.ID, n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE managed_configuration_draft_ops SET expires_ms=$2-1 WHERE actor=$1`, n.actor.ID, n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "draft expired capacity reclaimed", map[string]any{"draft": d}); e != nil {
		t.Fatal(e)
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_drafts WHERE actor=$1`, n.actor.ID).Scan(&count); e != nil || count != 2 {
		t.Fatal("expired draft storage not reclaimed", count, e)
	}
	if _, e := c.getDraft(context.Background(), n.actor.ID, d.ID, n.f.now.Add(32*24*time.Hour).Unix(), n.f.now.Add(31*24*time.Hour)); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("expired private draft remained readable", e)
	}
}

func TestPrivateLayerDraftInvalidMetadataAndCancellation(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	base := ConfigurationDraft{ID: p.DraftID, Proposal: p}
	for _, mutate := range []func(*ConfigurationDraft){
		func(d *ConfigurationDraft) { d.ID = "bad/id" },
		func(d *ConfigurationDraft) { d.Revision = -1 },
		func(d *ConfigurationDraft) { d.Revision = 9007199254740991 },
		func(d *ConfigurationDraft) { d.SavedAtMs = 1 },
		func(d *ConfigurationDraft) { d.Proposal.DraftRevision++ },
		func(d *ConfigurationDraft) { d.Proposal.TargetKind = "other" },
	} {
		d := base
		mutate(&d)
		if _, e := c.putDraft(context.Background(), n.actor.ID, "unused", "unused", d, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("invalid draft metadata", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.putDraft(ctx, n.actor.ID, "unused", "unused", base, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal("cancelled save", e)
	}
	if _, e := c.getDraft(ctx, n.actor.ID, base.ID, n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal("cancelled read", e)
	}
}

func TestPrivateLayerDraftCASLostReplyAndNoApprovalSideEffect(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	ctx := context.Background()
	d := ConfigurationDraft{ID: p.DraftID, Proposal: p}
	input := map[string]any{"draft": d}
	first, e := draftCall(t, n, c, "configuration.layers.draft.put", "draft create", input)
	if e != nil || first.Revision != 1 || first.Proposal.DraftRevision != 1 || first.SavedAtMs <= 0 {
		t.Fatal("draft create", e)
	}
	again, e := draftCall(t, n, c, "configuration.layers.draft.put", "draft create", input)
	if e != nil || again.Revision != 1 || again.SavedAtMs != first.SavedAtMs {
		t.Fatal("lost reply duplicated edit", e)
	}
	loaded, e := draftCall(t, n, c, "configuration.layers.draft.get", "draft load", map[string]string{"id": d.ID})
	if e != nil || loaded.Revision != 1 || loaded.Proposal.TargetID != p.TargetID {
		t.Fatal("draft load", e)
	}
	d.Revision = 1
	d.Proposal.DraftRevision = 2
	second, e := draftCall(t, n, c, "configuration.layers.draft.put", "draft second", map[string]any{"draft": d})
	if e != nil || second.Revision != 2 {
		t.Fatal("draft second", e)
	}
	if _, e = draftCall(t, n, c, "configuration.layers.draft.put", "draft create", map[string]any{"draft": d}); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("operation changed body", e)
	}
	if _, e = draftCall(t, n, c, "configuration.layers.draft.put", "stale draft revision", input); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("stale revision overwrote edit", e)
	}
	old, e := draftCall(t, n, c, "configuration.layers.draft.put", "draft create", input)
	if e != nil || old.Revision != 1 {
		t.Fatal("original result not retained", e)
	}
	for _, table := range []string{"managed_configuration_previews", "managed_configuration_versions", "managed_configuration_heads", "managed_configuration_requests"} {
		var count int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("saving draft became approval", table, e)
		}
	}
	var body []byte
	if e = fixtureOwner.QueryRow(`SELECT body FROM managed_configuration_drafts WHERE actor=$1 AND id=$2`, n.actor.ID, d.ID).Scan(&body); e != nil || bytes.Contains(body, []byte(p.TargetID)) {
		t.Fatal("private draft not encrypted", e)
	}
	if e = ConfigurationRuntimeRole(ctx, fixtureSigner, true); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureSigner.Exec(`SELECT body FROM managed_configuration_drafts`); e == nil {
		t.Fatal("publisher read mutable private draft")
	}
	if _, e = fixtureOwner.Exec(`GRANT SELECT ON managed_configuration_drafts TO syn443_identity_publisher`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := fixtureOwner.Exec(`REVOKE SELECT ON managed_configuration_drafts FROM syn443_identity_publisher`); e != nil {
			t.Error(e)
		}
	})
	if e = ConfigurationRuntimeRole(ctx, fixtureSigner, true); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("private-draft role contamination accepted", e)
	}
}

func TestPrivateLayerDraftRequiresScopeIntegrityAndStableTarget(t *testing.T) {
	for _, kind := range []string{"unknown", "cipher", "scope", "actor", "target", "expired-session", "malformed", "expired-proposal"} {
		t.Run(kind, func(t *testing.T) {
			n, c, p := configurationControlFixture(t)
			d := ConfigurationDraft{ID: p.DraftID, Proposal: p}
			if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "guarded draft", map[string]any{"draft": d}); e != nil {
				t.Fatal(e)
			}
			var e error
			switch kind {
			case "unknown":
				_, e = c.getDraft(context.Background(), n.actor.ID, "missing", n.f.now.Unix()+60, n.f.now)
			case "cipher":
				bad, err := enrollment.NewStore(fixtureControl, bytes.Repeat([]byte{92}, 32))
				if err != nil {
					t.Fatal(err)
				}
				c.Store = bad
				_, e = c.getDraft(context.Background(), n.actor.ID, d.ID, n.f.now.Unix()+60, n.f.now)
			case "scope":
				if _, err := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); err != nil {
					t.Fatal(err)
				}
				_, e = c.getDraft(context.Background(), n.actor.ID, d.ID, n.f.now.Unix()+60, n.f.now)
			case "actor":
				_, e = c.getDraft(context.Background(), identity.Hash([]byte("another actor")), d.ID, n.f.now.Unix()+60, n.f.now)
			case "target":
				d.Revision = 1
				d.Proposal.DraftRevision = 2
				d.Proposal.TargetID = "other-device"
				_, e = draftCall(t, n, c, "configuration.layers.draft.put", "changed draft target", map[string]any{"draft": d})
			case "expired-session":
				_, e = c.getDraft(context.Background(), n.actor.ID, d.ID, n.f.now.Unix(), n.f.now)
			case "malformed":
				d.Revision = 1
				d.Proposal.DraftRevision = 2
				d.Proposal.Bundles = nil
				_, e = draftCall(t, n, c, "configuration.layers.draft.put", "malformed draft", map[string]any{"draft": d})
			case "expired-proposal":
				d.Revision = 1
				d.Proposal.DraftRevision = 2
				d.Proposal.ApprovalUntilMs = n.f.now.UnixMilli()
				_, e = draftCall(t, n, c, "configuration.layers.draft.put", "expired draft", map[string]any{"draft": d})
			}
			if e == nil {
				t.Fatal("private draft boundary accepted", kind)
			}
		})
	}
}

func TestPrivateDraftReplaySurvivesProposalExpiryAndQuotaIsBounded(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	p.ApprovalUntilMs = n.f.now.Add(time.Second).UnixMilli()
	d := ConfigurationDraft{ID: p.DraftID, Proposal: p}
	raw, token, proof := configurationCall(t, n, c, "configuration.layers.draft.put", identity.Hash([]byte("short proposal")), map[string]any{"draft": d})
	first, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	bodyHash := configurationHash(raw)
	request := identity.Hash([]byte("short proposal"))
	again, e := c.putDraft(context.Background(), n.actor.ID, request, bodyHash, d, n.f.now.Unix()+120, n.f.now.Add(2*time.Second))
	if e != nil || again.Revision != first.(ConfigurationDraft).Revision {
		t.Fatal("lost saved reply expired with proposed approval", e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_draft_ops(actor,request_id,body_hash,response,expires_ms) SELECT $1,'synthetic-'||n,'hash',decode(repeat('00',30),'hex'),$2 FROM generate_series(1,255)n`, n.actor.ID, n.f.now.Add(time.Hour).UnixMilli()); e != nil {
		t.Fatal(e)
	}
	p.ApprovalUntilMs = n.f.now.Add(time.Hour).UnixMilli()
	d.Proposal = p
	d.ID = "another-draft"
	d.Proposal.DraftID = d.ID
	if _, e = draftCall(t, n, c, "configuration.layers.draft.put", "over operation quota", map[string]any{"draft": d}); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("unbounded operation receipts", e)
	}
	encoded, _ := json.Marshal(d)
	if len(encoded) == 0 || fmt.Sprint(d) != "ConfigurationDraft([redacted])" {
		t.Fatal("draft diagnostics")
	}
}
