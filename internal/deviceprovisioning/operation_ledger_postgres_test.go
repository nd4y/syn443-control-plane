//go:build postgres

package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func operationOriginal(t *testing.T, n networkFixture, c *ConfigurationControl, p LayerProposal, label string, version int) ([]byte, string, string) {
	t.Helper()
	raw, token, _ := configurationCall(t, n, c, "configuration.layers.draft.put", identity.Hash([]byte(label)), map[string]any{"draft": ConfigurationDraft{ID: p.DraftID, Proposal: p}})
	if version == 2 {
		raw = []byte(strings.Replace(string(raw), `"version":1`, `"version":2`, 1))
	}
	return raw, token, signed(t, n.f.key, c.Origin+"/v1/control/action", token, "", raw, n.f.now)
}

func operationCount(t *testing.T, table string) int {
	t.Helper()
	allowed := map[string]bool{"managed_configuration_operations": true, "managed_configuration_drafts": true, "managed_configuration_draft_ops": true, "managed_configuration_heads": true}
	if !allowed[table] {
		t.Fatal("unknown fixture table")
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil {
		t.Fatal(e)
	}
	return count
}

func awaitOperationSQLWait(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if e := fixtureOwner.QueryRow(`SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND NOT l.granted AND a.usename='syn443_control_api'`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("actual actor advisory wait was not observed")
}

// A literal old synchronous SQL path: effect first, then native receipt. It
// deliberately does NOT call any new Go ledger helper or production test seam.
func oldDraftSQL(ctx context.Context, tx *sql.Tx, c *ConfigurationControl, actor, request, hash string, saved ConfigurationDraft, now time.Time) error {
	if _, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "configuration-private-drafts/"+actor); e != nil {
		return e
	}
	raw, e := json.Marshal(saved)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, actor, saved.ID, saved.Proposal.TargetKind, saved.Proposal.TargetID, saved.Revision, configurationHash(raw), c.Store.Seal(raw, configurationDraftAAD(actor, saved.ID, saved.Revision)), now.UnixMilli(), now.Add(30*24*time.Hour).UnixMilli()); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_draft_ops(actor,request_id,body_hash,response,expires_ms) VALUES($1,$2,$3,$4,$5)`, actor, request, hash, c.Store.Seal(raw, configurationDraftOpAAD(actor, request)), now.Add(24*time.Hour).UnixMilli())
	return e
}

func TestSQLOperationV1AndV2SuccessfulWritesRecordExactIdentityBeforeEffectCommit(t *testing.T) {
	for _, v := range []int{1, 2} {
		n, c, p := configurationControlFixture(t)
		raw, token, proof := operationOriginal(t, n, c, p, "recorded-version", v)
		if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
			t.Fatal(e)
		}
		var hash, action, kind, target, disposition string
		var version int
		var rev int64
		if e := fixtureOwner.QueryRow(`SELECT body_hash,action,target_kind,target_id,disposition,protocol_version,effect_revision FROM managed_configuration_operations`).Scan(&hash, &action, &kind, &target, &disposition, &version, &rev); e != nil {
			t.Fatal(e)
		}
		if hash != configurationHash(raw) || action != "configuration.layers.draft.put" || kind != p.TargetKind || target != p.TargetID || disposition != "recorded" || version != v || rev != 1 {
			t.Fatal("unbound committed operation")
		}
	}
}

func TestSQLOperationRecordedWithoutActualNativeEffectCannotCommit(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, _, _ := operationOriginal(t, n, c, p, "missing-effect", 2)
	tx, e := fixtureControl.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	o := configurationOperation{Actor: n.actor.ID, Request: identity.Hash([]byte("missing-effect")), Action: "configuration.layers.draft.put", Hash: configurationHash(raw), Version: 2, Kind: p.TargetKind, Target: p.TargetID, Disposition: "recorded", EffectID: p.DraftID, EffectRevision: 1}
	if e = operationLock(context.Background(), tx, o.Actor, "draft"); e != nil {
		t.Fatal(e)
	}
	if e = operationInsert(context.Background(), tx, o, n.f.now); e != nil {
		t.Fatal(e)
	}
	if tx.Commit() == nil {
		t.Fatal("recorded a nonexistent effect")
	}
	if operationCount(t, "managed_configuration_operations") != 0 {
		t.Fatal("failed transaction left evidence")
	}
}

func TestSQLOperationOldWriterWithoutSameTransactionLedgerRollsBackItsDraft(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	tx, e := fixtureControl.Begin()
	if e != nil {
		t.Fatal(e)
	}
	e = oldDraftSQL(context.Background(), tx, c, n.actor.ID, identity.Hash([]byte("old-writer")), configurationHash([]byte("old body")), ConfigurationDraft{ID: p.DraftID, Revision: 1, Proposal: p, SavedAtMs: n.f.now.UnixMilli()}, n.f.now)
	if e == nil {
		t.Fatal("old unfenced insertion accepted")
	}
	tx.Rollback()
	if operationCount(t, "managed_configuration_drafts") != 0 || operationCount(t, "managed_configuration_draft_ops") != 0 {
		t.Fatal("old effect escaped rejected receipt")
	}
}

func TestSQLOperationNativeGatewayRejectsForeignBodyAndTransactionIdentity(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "prior-transaction", 1)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal(e)
	}
	for _, hash := range []string{configurationHash(raw), configurationHash([]byte("foreign"))} {
		tx, e := fixtureControl.Begin()
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(`INSERT INTO managed_configuration_draft_ops(actor,request_id,body_hash,response,expires_ms) VALUES($1,$2,$3,decode(repeat('00',30),'hex'),$4)`, n.actor.ID, identity.Hash([]byte("prior-transaction")), hash, n.f.now.Add(time.Hour).UnixMilli())
		if e == nil {
			t.Fatal("another transaction reused recorded ownership")
		}
		tx.Rollback()
	}
}

func TestSQLOperationRuntimeRolesCannotEditEraseOrResetAdmissionCounters(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "roles", 1)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{`UPDATE managed_configuration_operations SET body_hash=repeat('0',64)`, `DELETE FROM managed_configuration_operations`, `TRUNCATE managed_configuration_operations`, `SELECT * FROM managed_configuration_operation_counters`, `UPDATE managed_configuration_operation_counters SET used=0`, `TRUNCATE managed_configuration_operation_counters`} {
		if _, e := fixtureControl.Exec(q); e == nil {
			t.Fatal("runtime broadened", q)
		}
	}
	if _, e := fixtureSigner.Exec(`SELECT * FROM managed_configuration_operations`); e == nil {
		t.Fatal("publisher obtained admin operation data")
	}
}

func TestSQLOperationNormalQuotaRejectsBeforeEffectAndRollsBackAllCounterCharges(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "quota-seed", 1)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE managed_configuration_operation_counters SET used=512 WHERE bucket LIKE 'normal/actor/%'`); e != nil {
		t.Fatal(e)
	}
	p.DraftID = "another-draft"
	raw, token, proof = operationOriginal(t, n, c, p, "quota-denied", 2)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, catalog.ErrQuota) {
		t.Fatal("missing atomic quota", e)
	}
	var used int
	if e := fixtureOwner.QueryRow(`SELECT used FROM managed_configuration_operation_counters WHERE bucket='normal/total'`).Scan(&used); e != nil || used != 1 {
		t.Fatal("partial counter charge", e, used)
	}
	if operationCount(t, "managed_configuration_drafts") != 1 || operationCount(t, "managed_configuration_operations") != 1 {
		t.Fatal("effect under exhausted quota")
	}
}

func TestSQLOperationActorGlobalDayAndHardCapsAreDistinctAtomicLimits(t *testing.T) {
	for _, key := range []string{"normal/total", "normal/day/"} {
		n, c, p := configurationControlFixture(t)
		raw, token, proof := operationOriginal(t, n, c, p, "cap-seed", 1)
		if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
			t.Fatal(e)
		}
		cap := operationNormalTotal
		if key != "normal/total" {
			cap = operationNormalGlobalDay
		}
		if _, e := fixtureOwner.Exec(`UPDATE managed_configuration_operation_counters SET used=$1 WHERE bucket LIKE $2`, cap, key+"%"); e != nil {
			t.Fatal(e)
		}
		p.DraftID = "other-cap-draft"
		raw, token, proof = operationOriginal(t, n, c, p, "cap-denied", 1)
		if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, catalog.ErrQuota) {
			t.Fatal("global cap bypass", e)
		}
		if operationCount(t, "managed_configuration_operations") != 1 {
			t.Fatal("cap inserted identity")
		}
	}
}

func TestSQLOperationExpiryWhileWaitingForFamilyLockDoesNotCommitLedgerOrEffect(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	hold, e := fixtureControl.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer hold.Rollback()
	if e = operationLock(context.Background(), hold, n.actor.ID, "draft"); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, e := c.putDraft(ctx, n.actor.ID, identity.Hash([]byte("blocked")), configurationHash([]byte("blocked")), ConfigurationDraft{ID: p.DraftID, Proposal: p}, n.f.now.Unix()+60, n.f.now)
		done <- e
	}()
	awaitOperationSQLWait(t)
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled owner committed")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("blocked SQL owner did not exit")
	}
	if operationCount(t, "managed_configuration_operations") != 0 {
		t.Fatal("cancelled ledger retained")
	}
}

func TestSQLOperationRejectedFinalAclRollsBackLedgerAlongWithDraft(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	raw, token, proof := operationOriginal(t, n, c, p, "revoked", 2)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal(e)
	}
	if operationCount(t, "managed_configuration_operations") != 0 || operationCount(t, "managed_configuration_drafts") != 0 {
		t.Fatal("revoked effect")
	}
}

func TestSQLOperationCounterHardBoundsAndDiagnosticFormattingContainNoProposal(t *testing.T) {
	if operationNormalActorDay != 512 || operationNormalGlobalDay != 32768 || operationNormalTotal != 1048576 || operationBackfillActorDay != 128 || operationBackfillGlobalDay != 8192 || operationBackfillTotal != 65536 {
		t.Fatal("owner quota contract changed")
	}
	o := configurationOperation{Actor: "private-actor", Hash: "private-body", EffectID: "private-draft"}
	if o.String() != "ConfigurationOperation([redacted])" || o.GoString() != o.String() {
		t.Fatal("private diagnostics")
	}
}
