package deviceprovisioning

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

// Private publisher plumbing. A claimed queue row is not an approval artifact.
// The actual preview/publication producer must independently resolve and compile
// its recipients/layers/dependencies inside the guarded transaction below.
type configurationWorkStore struct {
	Store                *enrollment.Store
	Verifier             invitation.Verifier
	Origin, AssuranceACR string
}

type configurationWork struct {
	id, actor, request, action, kind, target, hash, lease string
	deadline, leaseUntil                                  int64
	attempts                                              int
	receipt                                               []byte
}

func (configurationWork) String() string   { return "ConfigurationWork([redacted])" }
func (configurationWork) GoString() string { return "ConfigurationWork([redacted])" }

func (s *configurationWorkStore) claim(ctx context.Context, now time.Time) (configurationWork, error) {
	var w configurationWork
	if s == nil || s.Store == nil || ctx == nil || now.IsZero() {
		return w, enrollment.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if e := ConfigurationRuntimeRole(ctx, s.Store.DB, true); e != nil {
		return w, e
	}
	started := time.Now()
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return w, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	// Admission is serialized only for this short claim, never OIDC/network work.
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('configuration-work-admission',0))`); e != nil {
		return w, enrollment.ErrUnavailable
	}
	at := now.Add(time.Since(started)).UnixMilli()
	if _, e = tx.ExecContext(ctx, `UPDATE managed_configuration_requests SET state='expired',error_code='deadline_or_retry_limit',lease='',lease_until_ms=0 WHERE state IN('queued','running') AND (deadline_ms<=$1 OR attempts>=3 AND lease_until_ms<=$1)`, at); e != nil {
		return w, enrollment.ErrUnavailable
	}
	var running int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_configuration_requests WHERE state='running' AND lease_until_ms>$1`, at).Scan(&running); e != nil {
		return w, enrollment.ErrUnavailable
	}
	if running >= 4 {
		return w, tx.Commit()
	}
	e = tx.QueryRowContext(ctx, `SELECT id,actor,request_id,action,target_kind,target_id,body_hash,deadline_ms,attempts,receipt FROM managed_configuration_requests WHERE (state='queued' OR state='running' AND lease_until_ms<=$1) AND next_ms<=$1 AND deadline_ms>$1 AND attempts<3 ORDER BY next_ms,created_ms,id LIMIT 1 FOR UPDATE SKIP LOCKED`, at).Scan(&w.id, &w.actor, &w.request, &w.action, &w.kind, &w.target, &w.hash, &w.deadline, &w.attempts, &w.receipt)
	if e == sql.ErrNoRows {
		return w, tx.Commit()
	}
	if e != nil {
		return w, enrollment.ErrUnavailable
	}
	at = now.Add(time.Since(started)).UnixMilli()
	if at >= w.deadline {
		return configurationWork{}, enrollment.ErrDenied
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return configurationWork{}, e
	}
	w.lease = base64.RawURLEncoding.EncodeToString(nonce[:])
	w.leaseUntil = min(w.deadline, at+20000)
	w.attempts++
	if _, e = tx.ExecContext(ctx, `UPDATE managed_configuration_requests SET state='running',lease=$2,lease_until_ms=$3,attempts=$4 WHERE id=$1`, w.id, w.lease, w.leaseUntil, w.attempts); e != nil {
		return configurationWork{}, enrollment.ErrUnavailable
	}
	if e = tx.Commit(); e != nil {
		return configurationWork{}, enrollment.ErrUnavailable
	}
	return w, nil
}

func (s *configurationWorkStore) verify(ctx context.Context, w configurationWork, now time.Time) (invitation.Envelope, int64, error) {
	var envelope invitation.Envelope
	if ctx == nil || s == nil || s.Store == nil || w.id == "" || w.lease == "" || now.UnixMilli() >= min(w.deadline, w.leaseUntil) {
		return envelope, 0, enrollment.ErrDenied
	}
	plain, e := s.Store.Open(w.receipt, configurationRequestAAD(w.id))
	var receipt invitation.Receipt
	if e != nil || identity.DecodeConfiguration(plain, &receipt) != nil || configurationHash(receipt.Body) != w.hash {
		return envelope, 0, enrollment.ErrDenied
	}
	actor, envelope, until, e := verifyConfigurationReceipt(ctx, s.Verifier, receipt, s.Origin, s.AssuranceACR, now)
	if e != nil || actor != w.actor || envelope.RequestID != w.request || envelope.Action != w.action || identity.Hash([]byte(actor+"\x00"+envelope.RequestID)) != w.id || time.Unix(receipt.AcceptedAt+180, 0).UnixMilli() != w.deadline {
		return envelope, 0, enrollment.ErrDenied
	}
	if envelope.Action == "configuration.preview.request" {
		var input configurationPreviewInput
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil || input.Proposal.TargetKind != w.kind || input.Proposal.TargetID != w.target || validateProposalShape(ctx, input.Proposal, now) != nil {
			return envelope, 0, enrollment.ErrDenied
		}
	} else if envelope.Action != "configuration.publish" {
		return envelope, 0, enrollment.ErrDenied
	}
	return envelope, until, nil
}

func (s *configurationWorkStore) lock(ctx context.Context, tx *sql.Tx, w configurationWork, now time.Time) error {
	started := time.Now()
	var lease, state, actor, request, action, kind, target, hash string
	var deadline, leaseUntil int64
	var attempts int
	e := tx.QueryRowContext(ctx, `SELECT lease,state,actor,request_id,action,target_kind,target_id,body_hash,deadline_ms,lease_until_ms,attempts FROM managed_configuration_requests WHERE id=$1 FOR UPDATE`, w.id).Scan(&lease, &state, &actor, &request, &action, &kind, &target, &hash, &deadline, &leaseUntil, &attempts)
	if e != nil || state != "running" || lease == "" || lease != w.lease || leaseUntil != w.leaseUntil || deadline != w.deadline || attempts != w.attempts || actor != w.actor || request != w.request || action != w.action || kind != w.kind || target != w.target || hash != w.hash || now.Add(time.Since(started)).UnixMilli() >= min(deadline, leaseUntil) {
		return enrollment.ErrConflict
	}
	return nil
}

// The callback is package-private publisher code, not API input. Its SQL effects
// and the terminal queue receipt commit together, or all roll back. In particular
// late work cannot advance a head after lease theft, expiry, ACL loss or Stop.
func (s *configurationWorkStore) commit(ctx context.Context, w configurationWork, now time.Time, effect func(context.Context, *sql.Tx, time.Time, invitation.Envelope) (json.RawMessage, error)) error {
	if s == nil || s.Store == nil || ctx == nil || effect == nil {
		return enrollment.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e := ConfigurationRuntimeRole(ctx, s.Store.DB, true); e != nil {
		return e
	}
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	envelope, authorityUntil, e := s.verify(ctx, w, current()) // OIDC outside SQL locks.
	if e != nil {
		return e
	}
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	if e = s.lock(ctx, tx, w, current()); e != nil {
		return e
	}
	action := "configuration.preview"
	terminal := "ready"
	if w.action == "configuration.publish" {
		action, terminal = "configuration.publish", "published"
	}
	if e = layerACL(ctx, tx, w.actor, action, w.kind, w.target, current().Unix()); e != nil {
		return e
	}
	if current().Unix() >= authorityUntil {
		return enrollment.ErrDenied
	}
	result, e := effect(ctx, tx, current(), envelope)
	if e != nil {
		return e
	}
	if len(result) == 0 || len(result) > 100000 || !json.Valid(result) {
		return enrollment.ErrDenied
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if current().Unix() >= authorityUntil {
		return enrollment.ErrDenied
	}
	if e = s.lock(ctx, tx, w, current()); e != nil {
		return e
	}
	if e = layerACL(ctx, tx, w.actor, action, w.kind, w.target, current().Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE managed_configuration_requests SET state=$2,result=$3,lease='',lease_until_ms=0,error_code='' WHERE id=$1`, w.id, terminal, []byte(result)); e != nil {
		return enrollment.ErrUnavailable
	}
	return tx.Commit()
}
