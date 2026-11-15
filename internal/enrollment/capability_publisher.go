package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type capabilityWork struct {
	device, request, owner, key, grant, hash, kind, session string
	generation, accepted, deadline                          int64
	body, protected                                         []byte
}

func (capabilityWork) String() string   { return "CapabilityWork([redacted])" }
func (capabilityWork) GoString() string { return "CapabilityWork([redacted])" }

// Only read-only proof/JWT verification occurs before the final transaction.
// Concurrent workers may verify the same immutable candidate; the request and
// device row locks make approval, history/head CAS and receipt erasure atomic.
func (p *Publisher) ApproveCapabilitiesOnce(ctx context.Context, now time.Time) error {
	if ctx == nil || p == nil || p.Store == nil || p.Verifier == nil {
		return identity.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	if e := p.Store.RuntimeRole(ctx, true); e != nil {
		return e
	}
	if _, e := p.Store.DB.ExecContext(ctx, `UPDATE identity_capability_requests SET state='rejected',receipt=NULL,error_code='capability_expired' WHERE (device,request_id) IN(SELECT device,request_id FROM identity_capability_requests WHERE state='queued' AND deadline_ms<=$1 ORDER BY accepted_ms LIMIT 64)`, current().UnixMilli()); e != nil {
		return ErrUnavailable
	}
	if _, e := p.Store.DB.ExecContext(ctx, `DELETE FROM identity_capability_requests WHERE (device,request_id) IN(SELECT device,request_id FROM identity_capability_requests WHERE state<>'queued' AND receipt IS NULL AND accepted_ms<$1 ORDER BY accepted_ms LIMIT 128)`, current().Add(-24*time.Hour).UnixMilli()); e != nil {
		return ErrUnavailable
	}
	var w capabilityWork
	e := p.Store.DB.QueryRowContext(ctx, `SELECT device,request_id,owner,jkt,grant_hash,request_hash,auth_kind,session_id,session_generation,accepted_ms,deadline_ms,body,receipt FROM identity_capability_requests WHERE state='queued' ORDER BY accepted_ms,device,request_id LIMIT 1`).Scan(&w.device, &w.request, &w.owner, &w.key, &w.grant, &w.hash, &w.kind, &w.session, &w.generation, &w.accepted, &w.deadline, &w.body, &w.protected)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return ErrUnavailable
	}
	e = p.approveCapability(ctx, w, current)
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) || errors.Is(e, identity.ErrInvalid) {
		code := "capability_denied"
		if errors.Is(e, ErrConflict) {
			code = "capability_conflict"
		}
		if _, rejected := p.Store.DB.ExecContext(ctx, `UPDATE identity_capability_requests SET state='rejected',receipt=NULL,error_code=$4 WHERE device=$1 AND request_id=$2 AND request_hash=$3 AND state='queued'`, w.device, w.request, w.hash, code); rejected != nil {
			return ErrUnavailable
		}
	}
	return e
}

func (p *Publisher) approveCapability(ctx context.Context, w capabilityWork, current func() time.Time) error {
	input, e := capabilityInput(w.body)
	if e != nil || input.RequestID != w.request || identity.Hash(w.body) != w.hash || w.accepted > current().UnixMilli() || w.deadline <= current().UnixMilli() || w.deadline > w.accepted+180000 {
		return ErrDenied
	}
	encoded, e := p.Store.Open(w.protected, capabilityReceiptAAD(w.device, w.request))
	if e != nil {
		return ErrUnavailable
	}
	var receipt CapabilityReceipt
	if identity.DecodeOperatorDocument(encoded, &receipt) != nil || receipt.AcceptedAt != w.accepted/1000 || len(receipt.Token) < 24 || len(receipt.Token) > 16384 {
		return ErrDenied
	}
	path := "/v1/device/capabilities"
	if w.kind == "oidc" {
		path = "/v1/devices/capabilities"
	} else if w.kind != "device" {
		return ErrDenied
	}
	if receipt.URI != p.Origin+path {
		return ErrDenied
	}
	proof, e := identity.RequestProof(receipt.Proof, identity.ProofContext{Method: "POST", URI: receipt.URI, Token: receipt.Token, BodyHash: w.hash, Now: time.Unix(receipt.AcceptedAt, 0)})
	if e != nil || proof.Thumbprint != w.key || proof.Claims.Nonce == "" {
		return ErrDenied
	}
	grant, exists := p.Grants[w.owner]
	if !exists || grant.Hash() != w.grant || grant.Validate(current()) != nil {
		return ErrDenied
	}
	until := min(w.deadline, grant.Until*1000)
	if w.kind == "oidc" {
		// The verifier may fetch keys; no SQL transaction/authorization lock is
		// held here. Its original token remains bound to the device proof.
		principal, e := p.Verifier.Verify(ctx, receipt.Token, current())
		if e != nil {
			if errors.Is(e, identity.ErrInvalid) {
				return ErrDenied
			}
			return ErrUnavailable
		}
		if !principal.HasScope("syn443.enroll") || principal.Thumbprint != w.key || principal.Issuer != grant.Issuer || principal.Subject != grant.Subject || principal.Expires <= current().Unix() {
			return ErrDenied
		}
		until = min(until, principal.Expires*1000)
	}
	if until <= current().UnixMilli() {
		return ErrDenied
	}
	tx, e := p.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	a, e := lockAccount(ctx, tx, w.owner, current().Unix())
	if e != nil {
		if errors.Is(e, ErrDenied) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	if a.Grant != w.grant {
		return ErrDenied
	}
	until = min(until, a.Until*1000)
	var original []byte
	var owner, key string
	var active, approved bool
	e = tx.QueryRowContext(ctx, `SELECT owner,jkt,request_body,active,approved FROM identity_devices WHERE id=$1 FOR UPDATE`, w.device).Scan(&owner, &key, &original, &active, &approved)
	if e != nil && e != sql.ErrNoRows {
		return ErrUnavailable
	}
	if e == sql.ErrNoRows || owner != w.owner || key != w.key || !active || !approved {
		return ErrDenied
	}
	var state, hash string
	if e = tx.QueryRowContext(ctx, `SELECT state,request_hash FROM identity_capability_requests WHERE device=$1 AND request_id=$2 FOR UPDATE`, w.device, w.request).Scan(&state, &hash); e != nil {
		return ErrUnavailable
	}
	if state != "queued" {
		return nil
	}
	if hash != w.hash {
		return ErrDenied
	}
	if w.kind == "device" {
		var allowed bool
		if e = tx.QueryRowContext(ctx, `SELECT public.identity_capability_session_fence($1::text,$2::text,$3::bigint,$4::text,$5::text,$6::bigint)`, w.session, w.device, w.generation, identity.Hash([]byte(receipt.Token)), proof.Claims.Nonce, current().Unix()).Scan(&allowed); e != nil {
			return ErrUnavailable
		}
		if !allowed {
			return ErrDenied
		}
	}
	var enrollment Request
	if identity.Decode(original, &enrollment, true) != nil {
		return ErrDenied
	}
	thumb, e := enrollment.Key.Thumbprint()
	if e != nil || thumb != w.key {
		return ErrDenied
	}
	before, e := EffectiveCapabilities(ctx, tx, w.device, enrollment.Capabilities)
	if e != nil {
		return e
	}
	if input.PreviousHash != before.Hash {
		return ErrConflict
	}
	caps, canonical, e := canonicalCapabilities(input.Capabilities)
	if e != nil || len(caps) <= len(before.Capabilities) || before.Version >= 13 {
		return ErrDenied
	}
	for _, original := range before.Capabilities {
		if !slices.Contains(caps, original) {
			return ErrDenied
		}
	}
	next, nextHash := before.Version+1, identity.Hash(canonical)
	if _, e = tx.ExecContext(ctx, `INSERT INTO identity_capability_versions(device,revision,previous_hash,body_hash,capabilities,original_request_hash,request_hash,proof_hash,approved_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, w.device, next, before.Hash, nextHash, canonical, identity.Hash(original), w.hash, identity.Hash([]byte(receipt.Proof)), current().UnixMilli()); e != nil {
		return ErrUnavailable
	}
	r, e := tx.ExecContext(ctx, `INSERT INTO identity_capability_heads(device,revision,body_hash) VALUES($1,$2,$3) ON CONFLICT(device) DO UPDATE SET revision=excluded.revision,body_hash=excluded.body_hash WHERE identity_capability_heads.revision=$4 AND identity_capability_heads.body_hash=$5`, w.device, next, nextHash, before.Version, before.Hash)
	if e != nil {
		return ErrUnavailable
	}
	if rows, e := r.RowsAffected(); e != nil || rows != 1 {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `UPDATE identity_devices SET refresh_after=0,retry_after=0 WHERE id=$1 AND active`, w.device); e != nil {
		return ErrUnavailable
	}
	if _, e = tx.ExecContext(ctx, `UPDATE identity_capability_requests SET state='approved',receipt=NULL,result_revision=$3,result_hash=$4,error_code='' WHERE device=$1 AND request_id=$2 AND state='queued'`, w.device, w.request, next, nextHash); e != nil {
		return ErrUnavailable
	}
	if current().UnixMilli() >= until || ctx.Err() != nil {
		return ErrDenied
	}
	if tx.Commit() != nil {
		return ErrUnavailable
	}
	return nil
}
