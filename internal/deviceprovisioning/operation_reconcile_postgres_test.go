//go:build postgres

package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func reconcileCall(t *testing.T, n networkFixture, c *ConfigurationControl, original []byte, intent string) (ConfigurationOperationOutcome, error) {
	t.Helper()
	raw, e := json.Marshal(configurationReconcileInput{Version: 1, RequestID: identity.Hash([]byte("reconcile-" + intent + string(original))), Intent: intent, OriginalBody64: base64.RawURLEncoding.EncodeToString(original)})
	if e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("synthetic-control-token-", 2)
	proof := signed(t, n.f.key, c.Origin+configurationReconcilePath, token, "", raw, n.f.now)
	return c.reconcile(context.Background(), token, proof, raw, n.f.now)
}

func seedLegacyOperation(t *testing.T, n networkFixture, c *ConfigurationControl, p LayerProposal, label string) []byte {
	t.Helper()
	raw, _, _ := operationOriginal(t, n, c, p, label, 1)
	tx, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = oldDraftSQL(context.Background(), tx, c, n.actor.ID, identity.Hash([]byte(label)), configurationHash(raw), ConfigurationDraft{ID: p.DraftID, Revision: 1, Proposal: p, SavedAtMs: n.f.now.UnixMilli()}, n.f.now); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestSQLOperationReconcileVersionOneAbsenceStaysUnknownWithoutFencingOrQuota(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, _, _ := operationOriginal(t, n, c, p, "legacy-absence", 1)
	for _, intent := range []string{"lookup", "seal_if_absent"} {
		v, e := reconcileCall(t, n, c, raw, intent)
		if e != nil || v.Outcome != "UNKNOWN" || v.EffectID != "" {
			t.Fatal(v, e)
		}
	}
	if operationCount(t, "managed_configuration_operations") != 0 {
		t.Fatal("invented legacy absence proof")
	}
}

func TestSQLOperationReconcileVersionTwoLookupIsNotNoEffectUntilAtomicSeal(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "fenced-absence", 2)
	if v, e := reconcileCall(t, n, c, raw, "lookup"); e != nil || v.Outcome != "UNKNOWN" {
		t.Fatal(v, e)
	}
	first, e := reconcileCall(t, n, c, raw, "seal_if_absent")
	if e != nil || first.Outcome != "NO_EFFECT" || first.BodyHash != configurationHash(raw) || first.Actor != n.actor.ID || first.EffectID != "" {
		t.Fatal(first, e)
	}
	again, e := reconcileCall(t, n, c, raw, "lookup")
	if e != nil || again.Outcome != "NO_EFFECT" || again.RecordedAtMS != first.RecordedAtMS {
		t.Fatal("lost seal reply changed identity", again, e)
	}
	if _, e = c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("late original escaped seal", e)
	}
	if operationCount(t, "managed_configuration_drafts") != 0 {
		t.Fatal("sealed draft effect")
	}
}

func TestSQLOperationReconcileSealFirstFencesActuallyBlockedOldSqlWriter(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, _, _ := operationOriginal(t, n, c, p, "seal-race", 2)
	ctx := context.Background()
	seal, e := fixtureControl.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer seal.Rollback()
	if e = operationLock(ctx, seal, n.actor.ID, "draft"); e != nil {
		t.Fatal(e)
	}
	o := configurationOperation{Actor: n.actor.ID, Request: identity.Hash([]byte("seal-race")), Action: "configuration.layers.draft.put", Hash: configurationHash(raw), Version: 2, Kind: p.TargetKind, Target: p.TargetID, Disposition: "no_effect"}
	if e = operationInsert(ctx, seal, o, n.f.now); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		tx, e := fixtureControl.Begin()
		if e == nil {
			defer tx.Rollback()
			e = oldDraftSQL(ctx, tx, c, n.actor.ID, o.Request, o.Hash, ConfigurationDraft{ID: p.DraftID, Revision: 1, Proposal: p, SavedAtMs: n.f.now.UnixMilli()}, n.f.now)
			if e == nil {
				e = tx.Commit()
			}
		}
		done <- e
	}()
	awaitOperationSQLWait(t)
	if e = seal.Commit(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("old late original committed")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("old owner did not exit")
	}
	if operationCount(t, "managed_configuration_drafts") != 0 || operationCount(t, "managed_configuration_draft_ops") != 0 {
		t.Fatal("old transaction partly committed")
	}
}

func TestSQLOperationReconcileOriginalFirstSeesCommitAfterActualActorLockWait(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, _, _ := operationOriginal(t, n, c, p, "original-first", 2)
	ctx := context.Background()
	tx, e := fixtureControl.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = operationLock(ctx, tx, n.actor.ID, "draft"); e != nil {
		t.Fatal(e)
	}
	o := configurationOperation{Actor: n.actor.ID, Request: identity.Hash([]byte("original-first")), Action: "configuration.layers.draft.put", Hash: configurationHash(raw), Version: 2, Kind: p.TargetKind, Target: p.TargetID, Disposition: "recorded", EffectID: p.DraftID, EffectRevision: 1}
	if e = operationInsert(ctx, tx, o, n.f.now); e != nil {
		t.Fatal(e)
	}
	if e = oldDraftSQL(ctx, tx, c, n.actor.ID, o.Request, o.Hash, ConfigurationDraft{ID: p.DraftID, Revision: 1, Proposal: p, SavedAtMs: n.f.now.UnixMilli()}, n.f.now); e != nil {
		t.Fatal(e)
	}
	type answer struct {
		v ConfigurationOperationOutcome
		e error
	}
	done := make(chan answer, 1)
	go func() { v, e := reconcileCall(t, n, c, raw, "seal_if_absent"); done <- answer{v, e} }()
	awaitOperationSQLWait(t)
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	select {
	case a := <-done:
		if a.e != nil || a.v.Outcome != "RECORDED" || a.v.EffectRevision != 1 {
			t.Fatal(a.v, a.e)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("reconcile owner did not exit")
	}
}

func TestSQLOperationReconcileCommittedLostReplyRemainsRecordedAfterRejectedReplay(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "lost-draft-ack", 1)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal(e)
	}
	// Discard makes the old put path conflict before its payload cache, exactly
	// as it did before this feature. The operation outcome is still recorded.
	if _, e := discardCall(t, n, c, "after-lost-ack", ConfigurationDraftDiscard{ID: p.DraftID, Revision: 1, TargetKind: p.TargetKind, TargetID: p.TargetID}); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal(e)
	}
	v, e := reconcileCall(t, n, c, raw, "lookup")
	if e != nil || v.Outcome != "RECORDED" || v.EffectRevision != 1 {
		t.Fatal(v, e)
	}
}

func TestSQLOperationReconcilePrunedPayloadKeepsRecordedFenceAndNeverInventsProposal(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "pruned-response", 1)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`DELETE FROM managed_configuration_draft_ops WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	v, e := reconcileCall(t, n, c, raw, "lookup")
	if e != nil || v.Outcome != "RECORDED_RESULT_UNAVAILABLE" || v.EffectRevision != 1 {
		t.Fatal(v, e)
	}
	if _, e = c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("reexecuted pruned recorded operation", e)
	}
}

func TestSQLOperationReconcileCheckedLegacyBackfillUsesSeparateReserve(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw := seedLegacyOperation(t, n, c, p, "legacy-retained")
	if v, e := reconcileCall(t, n, c, raw, "lookup"); e != nil || v.Outcome != "RECORDED" {
		t.Fatal(v, e)
	}
	if operationCount(t, "managed_configuration_operations") != 0 {
		t.Fatal("lookup consumed entry quota")
	}
	if v, e := reconcileCall(t, n, c, raw, "seal_if_absent"); e != nil || v.Outcome != "RECORDED" {
		t.Fatal(v, e)
	}
	var backfill bool
	var count int
	if e := fixtureOwner.QueryRow(`SELECT backfill FROM managed_configuration_operations`).Scan(&backfill); e != nil || !backfill {
		t.Fatal("missing checked backfill", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_operation_counters WHERE bucket LIKE 'normal/%'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("backfill spent normal reserve", e)
	}
}

func TestSQLOperationReconcileExhaustedAdmissionCannotStarveExistingRecordedLookup(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "read-reserve", 1)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE managed_configuration_operation_counters SET used=1048576 WHERE bucket='normal/total'`); e != nil {
		t.Fatal(e)
	}
	v, e := reconcileCall(t, n, c, raw, "lookup")
	if e != nil || v.Outcome != "RECORDED" {
		t.Fatal("lookup charged admission", v, e)
	}
	p.DraftID = "new-sealed-draft"
	other, _, _ := operationOriginal(t, n, c, p, "cannot-bloat", 2)
	if _, e = reconcileCall(t, n, c, other, "seal_if_absent"); !errors.Is(e, catalog.ErrQuota) {
		t.Fatal("unbounded no-effect entries", e)
	}
	if v, e = reconcileCall(t, n, c, raw, "lookup"); e != nil || v.Outcome != "RECORDED" {
		t.Fatal(v, e)
	}
}

func TestSQLOperationReconcileForeignBodyAclAndExpiredMfaCannotReadOrSeal(t *testing.T) {
	for _, mode := range []string{"hash", "acl", "mfa"} {
		n, c, p := configurationControlFixture(t)
		raw, token, proof := operationOriginal(t, n, c, p, "scope-original", 1)
		if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
			t.Fatal(e)
		}
		if mode == "hash" {
			raw = []byte(strings.Replace(string(raw), `"savedAtMs":0`, `"savedAtMs":1`, 1))
		}
		if mode == "acl" {
			if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
				t.Fatal(e)
			}
		}
		if mode == "mfa" {
			n.f.v.p.AuthTime = n.f.now.Add(-time.Hour).Unix()
		}
		if _, e := reconcileCall(t, n, c, raw, "seal_if_absent"); e == nil {
			t.Fatal("unauthorized operation resolution", mode)
		}
		if operationCount(t, "managed_configuration_operations") != 1 {
			t.Fatal("foreign operation wrote fence")
		}
	}
}

func TestSQLOperationReconcileExistingQueueRemainsRecordedWithoutCancellationOrActivation(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	raw, token, proof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("existing-queue")), configurationPreviewInput{Proposal: p})
	queued, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	v, e := reconcileCall(t, n, c, raw, "seal_if_absent")
	if e != nil || v.Outcome != "RECORDED" || v.Job == nil || v.Job.State != "queued" || v.Job.ID != queued.(ConfigurationRequestView).ID {
		t.Fatal(v, e)
	}
	work := configurationWorkStore{Store: publisher.Store, Verifier: publisher.Verifier, Origin: c.Origin, AssuranceACR: c.AssuranceACR}
	w, e := work.claim(context.Background(), n.f.now)
	if e != nil || w.id != v.Job.ID {
		t.Fatal("actual publisher did not own queue", e)
	}
	if original, _, e := work.verify(context.Background(), w, n.f.now); e != nil || original.Version != 1 {
		t.Fatal("existing v1 publisher receipt changed", e)
	}
	v, e = reconcileCall(t, n, c, raw, "lookup")
	if e != nil || v.Job == nil || v.Job.State != "running" || v.Outcome != "RECORDED" {
		t.Fatal(v, e)
	}
}

func TestSQLOperationReconcileCodecRejectsNoncanonicalBase64ClosedShapeAndNestedOperations(t *testing.T) {
	original := []byte(`{"version":2,"action":"configuration.layers.draft.put","requestId":"synthetic-codec-original-0001","payload":{}}`)
	for len(original)%3 != 1 {
		original = append(original, ' ')
	}
	canonical := base64.RawURLEncoding.EncodeToString(original)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	last := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	alternate := canonical[:len(canonical)-1] + string(alphabet[last|1])
	frame := func(code string) []byte {
		raw, _ := json.Marshal(configurationReconcileInput{Version: 1, RequestID: identity.Hash([]byte("codec")), Intent: "lookup", OriginalBody64: code})
		return raw
	}
	valid := frame(canonical)
	if _, _, body, e := decodeReconcile(valid); e != nil || string(body) != string(original) {
		t.Fatal("valid exact original rejected", e)
	}
	for _, code := range []string{canonical + "=", alternate, "AA+", "AA/", base64.RawURLEncoding.EncodeToString([]byte{0xed, 0xa0, 0x80}), base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(original), `"version":2`, `"version":3`, 1))), base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(original), `configuration.layers.draft.put`, `configuration.operation.reconcile`, 1)))} {
		if _, _, _, e := decodeReconcile(frame(code)); e == nil {
			t.Fatal("unsafe original codec accepted")
		}
	}
	for _, raw := range []string{strings.Replace(string(valid), `"version":1`, `"version":1.0`, 1), strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(valid), `"intent":"lookup"`, `"intent":null`, 1), strings.Replace(string(valid), `"intent":"lookup"`, `"intent":"seal_unknown_past"`, 1), strings.TrimSuffix(string(valid), "}") + `,"actor":"foreign"}`, strings.TrimSuffix(string(valid), "}") + `,"origi\u006ealBody64":"` + canonical + `"}`} {
		if _, _, _, e := decodeReconcile([]byte(raw)); e == nil {
			t.Fatal("unknown, duplicate or coerced recovery input")
		}
	}
}

func TestSQLOperationReconcileCodecOwnsExactOriginalAndScopedRequestBounds(t *testing.T) {
	prefix := `{"version":2,"action":"configuration.layers.draft.put","requestId":"synthetic-codec-boundary-0001","payload":{"padding":"`
	suffix := `"}}`
	original := []byte(prefix + strings.Repeat("x", 262144-len(prefix)-len(suffix)) + suffix)
	raw, _ := json.Marshal(configurationReconcileInput{Version: 1, RequestID: identity.Hash([]byte("boundary")), Intent: "lookup", OriginalBody64: base64.RawURLEncoding.EncodeToString(original)})
	padded := append(append([]byte(nil), raw...), []byte(strings.Repeat(" ", 524288-len(raw)))...)
	_, _, owned, e := decodeReconcile(padded)
	if e != nil || len(owned) != 262144 || string(owned) != string(original) {
		t.Fatal("exact scoped limits", e)
	}
	for i := range padded {
		padded[i] = 'x'
	}
	if string(owned) != string(original) {
		t.Fatal("caller changed owned original")
	}
	if _, _, _, e = decodeReconcile(append(raw, []byte(strings.Repeat(" ", 524289-len(raw)))...)); e == nil {
		t.Fatal("oversized recovery request")
	}
	oversized := []byte(prefix + strings.Repeat("x", 262145-len(prefix)-len(suffix)) + suffix)
	raw, _ = json.Marshal(configurationReconcileInput{Version: 1, RequestID: identity.Hash([]byte("boundary")), Intent: "lookup", OriginalBody64: base64.RawURLEncoding.EncodeToString(oversized)})
	if _, _, _, e = decodeReconcile(raw); e == nil {
		t.Fatal("oversized original")
	}
	input := configurationReconcileInput{OriginalBody64: "private-original"}
	if input.String() != "ConfigurationReconcileInput([redacted])" || input.GoString() != input.String() {
		t.Fatal("original body diagnostic")
	}
}

func TestSQLOperationReconcileRecordedPublishDoesNotRequireReauthorizingExpiredPreviewTicket(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	preview := prepareLayerPreview(t, n, c, p, publisher, "reconcile-publish-preview")
	raw, token, proof := configurationCall(t, n, c, "configuration.publish", identity.Hash([]byte("retained-publish")), configurationPublishInput{PreviewID: preview.PreviewID, Ticket: preview.Ticket})
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal(e)
	}
	n.f.now = n.f.now.Add(181 * time.Second)
	if _, e := configuration.VerifyPreview(context.Background(), preview.Ticket, publisher.Roots, c.Origin, n.actor.ID, n.f.now); e == nil {
		t.Fatal("old ticket did not actually expire")
	}
	// Key rotation also removes the old signing key. The recorded operation is
	// not a new approval and still needs current live actor/object authorization.
	publisher.Roots = map[string]*ecdsa.PublicKey{}
	v, e := reconcileCall(t, n, c, raw, "lookup")
	if e != nil || v.Outcome != "RECORDED" || v.TargetID != p.TargetID || v.Job == nil || v.Job.State != "queued" {
		t.Fatal(v, e)
	}
	foreign, _, _ := configurationCall(t, n, c, "configuration.publish", identity.Hash([]byte("missing-preview")), configurationPublishInput{PreviewID: identity.Hash([]byte("missing")), Ticket: strings.Repeat("x", 128)})
	foreign = []byte(strings.Replace(string(foreign), `"version":1`, `"version":2`, 1))
	if _, e = reconcileCall(t, n, c, foreign, "seal_if_absent"); e == nil {
		t.Fatal("missing preview granted target authority")
	}
}
