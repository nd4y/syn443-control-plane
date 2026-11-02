package invitation

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type Claim struct {
	RequestID    string       `json:"requestId"`
	Code         string       `json:"code"`
	Key          identity.JWK `json:"key"`
	Capabilities []string     `json:"capabilities"`
}

func (Claim) String() string   { return "InvitationClaim([redacted])" }
func (Claim) GoString() string { return "InvitationClaim([redacted])" }

type KeyReceipt struct {
	Proof      string `json:"proof"`
	URI        string `json:"uri"`
	AcceptedAt int64  `json:"acceptedAt"`
}
type ClaimState struct {
	Expires  int64  `json:"expires"`
	OwnerTag string `json:"ownerTag"`
	Error    string `json:"error,omitempty"`
	ID       string `json:"id"`
	Version  int64  `json:"version"`
	State    string `json:"state"`
	PairCode string `json:"pairCode"`
	Nonce    string `json:"nonce"`
	DeviceID string `json:"deviceId"`
}

func (ClaimState) String() string   { return "InvitationClaimState([redacted])" }
func (ClaimState) GoString() string { return "InvitationClaimState([redacted])" }

type DeviceRequest struct {
	ID        string `json:"id"`
	RequestID string `json:"requestId"`
}

func (c Claim) validate() error {
	if !requestID.MatchString(c.RequestID) || !opaque.MatchString(c.Code) || len(c.Capabilities) < 3 || len(c.Capabilities) > 16 {
		return ErrDenied
	}
	if _, e := c.Key.Thumbprint(); e != nil {
		return ErrDenied
	}
	caps := map[string]bool{}
	for _, value := range c.Capabilities {
		if !capabilityID.MatchString(value) || caps[value] {
			return ErrDenied
		}
		caps[value] = true
	}
	if !caps["engine-config.v1"] || !caps["tun.lease.v1"] || !caps["policy.keybound.v2"] {
		return ErrDenied
	}
	return nil
}
func state(r record) ClaimState {
	return ClaimState{Expires: r.Expires, OwnerTag: r.OwnerTag, Error: r.Error, ID: r.ID, Version: r.Version, State: r.State, PairCode: r.PairCode, Nonce: r.Nonce, DeviceID: r.Device}
}

// Claim reserves a single key/device seat. It returns no session, policy,
// subscription or chat access before the independent publisher approves it.
func (s *Store) Claim(ctx context.Context, service, origin string, raw []byte, signed string, now time.Time) (ClaimState, error) {
	var request Claim
	if identity.Decode(raw, &request, true) != nil || request.validate() != nil {
		return ClaimState{}, ErrDenied
	}
	proof, e := identity.VerifyProof(signed, identity.ProofContext{Method: "POST", URI: origin + "/v1/invitations/claim", BodyHash: identity.Hash(raw), Now: now})
	thumb, _ := request.Key.Thumbprint()
	if e != nil || thumb != proof.Thumbprint {
		return ClaimState{}, ErrDenied
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return ClaimState{}, ErrUnavailable
	}
	defer tx.Rollback()
	var id, owner string
	if e = tx.QueryRowContext(ctx, `SELECT id,owner FROM managed_invitations WHERE code_hash=$1`, identity.Hash([]byte(request.Code))).Scan(&id, &owner); e == sql.ErrNoRows {
		return ClaimState{}, ErrDenied
	}
	if e != nil {
		return ClaimState{}, ErrUnavailable
	}
	account, e := lockAccount(ctx, tx, owner)
	if e != nil {
		return ClaimState{}, e
	}
	r, e := s.read(ctx, tx, id, true, now)
	if e != nil {
		return ClaimState{}, e
	}
	if r.ServiceID != service || !account.Enabled || account.Until <= now.Unix() || account.Grant != r.Grant || r.Revoked {
		return ClaimState{}, ErrDenied
	}
	if r.Expires <= now.Unix() {
		return ClaimState{}, ErrExpired
	}
	if e = replay(ctx, tx, proof, now.Unix()); e != nil {
		return ClaimState{}, e
	}
	hash := identity.Hash(raw)
	if r.Thumbprint != "" {
		if r.Thumbprint != thumb || r.ClaimRequest != request.RequestID || r.ClaimHash != hash {
			return ClaimState{}, ErrConflict
		}
		return state(r), tx.Commit()
	}
	var devices, pending, existing int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE owner=$1 AND active`, owner).Scan(&devices); e != nil {
		return ClaimState{}, ErrUnavailable
	}
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_invitations WHERE owner=$1 AND claim_jkt IS NOT NULL AND device IS NULL AND NOT revoked AND expires>$2`, owner, now.Unix()).Scan(&pending); e != nil {
		return ClaimState{}, ErrUnavailable
	}
	if devices+pending >= account.Limit {
		return ClaimState{}, ErrDenied
	}
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE jkt=$1`, thumb).Scan(&existing); e != nil {
		return ClaimState{}, ErrUnavailable
	}
	if existing != 0 {
		return ClaimState{}, ErrDenied
	}
	nonce, e := random()
	if e != nil {
		return ClaimState{}, e
	}
	pairCode, e := pair()
	if e != nil {
		return ClaimState{}, e
	}
	payload, e := s.seal(raw, "invitation/claim-payload/"+id)
	if e != nil {
		return ClaimState{}, e
	}
	receipt, e := protect(s, KeyReceipt{signed, origin + "/v1/invitations/claim", now.Unix()}, "invitation/claim-receipt/"+id)
	if e != nil {
		return ClaimState{}, e
	}
	_, e = tx.ExecContext(ctx, `UPDATE managed_invitations SET claim_jkt=$2,claim_request=$3,claim_hash=$4,claim_payload=$5,claim_receipt=$6,claim_nonce=$7,pair_code=$8,claimed_at=$9,version=version+1 WHERE id=$1`, id, thumb, request.RequestID, hash, payload, receipt, nonce, pairCode, now.Unix())
	if e != nil {
		return ClaimState{}, ErrUnavailable
	}
	r.Thumbprint = thumb
	r.ClaimRequest = request.RequestID
	r.ClaimHash = hash
	r.Nonce = nonce
	r.PairCode = pairCode
	r.Version++
	r.State = "pending_approval"
	return state(r), tx.Commit()
}

func (s *Store) Status(ctx context.Context, origin string, raw []byte, signed string, now time.Time) (ClaimState, error) {
	var request DeviceRequest
	if identity.Decode(raw, &request, true) != nil || !opaque.MatchString(request.ID) || !requestID.MatchString(request.RequestID) {
		return ClaimState{}, ErrDenied
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return ClaimState{}, ErrUnavailable
	}
	defer tx.Rollback()
	owner, e := lookupOwner(ctx, tx, request.ID)
	if e != nil {
		return ClaimState{}, e
	}
	account, e := lockAccount(ctx, tx, owner)
	if e != nil {
		return ClaimState{}, e
	}
	r, e := s.read(ctx, tx, request.ID, true, now)
	if e != nil {
		return ClaimState{}, e
	}
	proof, e := identity.VerifyProof(signed, identity.ProofContext{Method: "POST", URI: origin + "/v1/invitations/status", Nonce: r.Nonce, BodyHash: identity.Hash(raw), Now: now})
	if e != nil || r.Thumbprint == "" || proof.Thumbprint != r.Thumbprint {
		return ClaimState{}, ErrDenied
	}
	if e = replay(ctx, tx, proof, now.Unix()); e != nil {
		return ClaimState{}, e
	}
	if !account.Enabled || account.Until <= now.Unix() || account.Grant != r.Grant {
		r.State = "revoked"
	}
	return state(r), tx.Commit()
}

// EnrollmentRequest reconstructs only the existing public key/capability model.
// The code and key proof stay in their protected invitation receipts.
func (c Claim) EnrollmentRequest() ([]byte, error) {
	if c.validate() != nil {
		return nil, ErrDenied
	}
	return json.Marshal(struct {
		RequestID    string       `json:"requestId"`
		Key          identity.JWK `json:"key"`
		Capabilities []string     `json:"capabilities"`
	}{c.RequestID, c.Key, append([]string(nil), c.Capabilities...)})
}
