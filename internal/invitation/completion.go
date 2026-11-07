package invitation

import (
	"context"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Complete mints exactly one ordinary key-bound session only after the
// independent publisher has committed a valid policy. A lost reply can be
// recovered with the same body/id and a new proof; rotation/revocation fences it.
func (s *Store) Complete(ctx context.Context, sessionStore *enrollment.Store, origin string, raw []byte, signed string, now time.Time) (enrollment.Session, error) {
	var request DeviceRequest
	if sessionStore == nil || sessionStore.DB != s.DB || identity.Decode(raw, &request, true) != nil || !opaque.MatchString(request.ID) || !requestID.MatchString(request.RequestID) {
		return enrollment.Session{}, ErrDenied
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return enrollment.Session{}, ErrUnavailable
	}
	defer tx.Rollback()
	owner, e := lookupOwner(ctx, tx, request.ID)
	if e != nil {
		return enrollment.Session{}, e
	}
	a, e := lockAccount(ctx, tx, owner)
	if e != nil {
		return enrollment.Session{}, e
	}
	r, e := s.read(ctx, tx, request.ID, true, now)
	if e != nil {
		return enrollment.Session{}, e
	}
	proof, e := identity.VerifyProof(signed, identity.ProofContext{Method: "POST", URI: origin + "/v1/invitations/complete", Nonce: r.Nonce, BodyHash: identity.Hash(raw), Now: now})
	if e != nil || r.Thumbprint == "" || proof.Thumbprint != r.Thumbprint || r.Revoked || !a.Enabled || a.Until <= now.Unix() || a.Grant != r.Grant {
		return enrollment.Session{}, ErrDenied
	}
	if e = replay(ctx, tx, proof, now.Unix()); e != nil {
		return enrollment.Session{}, e
	}
	hash := identity.Hash(raw)
	if r.FinalSession != "" {
		if r.FinalRequest != request.RequestID || r.FinalHash != hash {
			return enrollment.Session{}, ErrConflict
		}
	} else {
		if r.Expires <= now.Unix() {
			return enrollment.Session{}, ErrExpired
		}
		if r.State != "ready" {
			return enrollment.Session{}, ErrPending
		}
	}
	value, sid, e := sessionStore.InvitedSession(ctx, tx, owner, r.Thumbprint, r.Device, request.RequestID, hash, now)
	if e != nil {
		return enrollment.Session{}, e
	}
	if r.FinalSession != "" && r.FinalSession != sid {
		return enrollment.Session{}, ErrConflict
	}
	if r.FinalSession == "" {
		if _, e = tx.ExecContext(ctx, `UPDATE managed_invitations SET final_request=$2,final_hash=$3,final_session=$4,finalized_at=$5,version=version+1 WHERE id=$1`, r.ID, request.RequestID, hash, sid, now.Unix()); e != nil {
			return enrollment.Session{}, ErrUnavailable
		}
	}
	if e = tx.Commit(); e != nil {
		return enrollment.Session{}, ErrUnavailable
	}
	return value, nil
}

// Abandon revokes only the key/device captured by this claim. It never touches
// another account, an existing VPN or any overlay identity on the client.
func (s *Store) Abandon(ctx context.Context, origin string, raw []byte, signed string, now time.Time) error {
	var request DeviceRequest
	if identity.Decode(raw, &request, true) != nil || !opaque.MatchString(request.ID) || !requestID.MatchString(request.RequestID) {
		return ErrDenied
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	owner, e := lookupOwner(ctx, tx, request.ID)
	if e != nil {
		return e
	}
	if _, e = lockAccount(ctx, tx, owner); e != nil {
		return e
	}
	r, e := s.read(ctx, tx, request.ID, true, now)
	if e != nil {
		return e
	}
	proof, e := identity.VerifyProof(signed, identity.ProofContext{Method: "POST", URI: origin + "/v1/invitations/abandon", Nonce: r.Nonce, BodyHash: identity.Hash(raw), Now: now})
	if e != nil || r.Thumbprint == "" || proof.Thumbprint != r.Thumbprint {
		return ErrDenied
	}
	if e = replay(ctx, tx, proof, now.Unix()); e != nil {
		return e
	}
	if r.Device != "" {
		if _, e = tx.ExecContext(ctx, `UPDATE identity_devices SET active=false WHERE id=$1 AND owner=$2 AND jkt=$3`, r.Device, owner, r.Thumbprint); e != nil {
			return ErrUnavailable
		}
		if _, e = tx.ExecContext(ctx, `UPDATE identity_sessions SET active=false WHERE device=$1`, r.Device); e != nil {
			return ErrUnavailable
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE managed_invitations SET revoked=true,version=version+1 WHERE id=$1 AND NOT revoked`, r.ID); e != nil {
		return ErrUnavailable
	}
	return tx.Commit()
}
