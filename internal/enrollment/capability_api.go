package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type CapabilityInput struct {
	RequestID    string   `json:"requestId"`
	PreviousHash string   `json:"previousHash"`
	Capabilities []string `json:"capabilities"`
}
type CapabilitySnapshot struct {
	CapabilityState
	AuthorityHash string `json:"authorityHash"`
}
type CapabilityRequestView struct {
	RequestID string `json:"requestId"`
	State     string `json:"state"`
	Version   int64  `json:"version"`
	Hash      string `json:"hash"`
	Error     string `json:"error,omitempty"`
}
type CapabilityReceipt struct {
	Token      string `json:"token"`
	Proof      string `json:"proof"`
	URI        string `json:"uri"`
	AcceptedAt int64  `json:"acceptedAt"`
}

func (CapabilityInput) String() string         { return "CapabilityInput([redacted])" }
func (CapabilityInput) GoString() string       { return "CapabilityInput([redacted])" }
func (CapabilitySnapshot) String() string      { return "CapabilitySnapshot([redacted])" }
func (CapabilitySnapshot) GoString() string    { return "CapabilitySnapshot([redacted])" }
func (CapabilityRequestView) String() string   { return "CapabilityRequest([redacted])" }
func (CapabilityRequestView) GoString() string { return "CapabilityRequest([redacted])" }
func (CapabilityReceipt) String() string       { return "CapabilityReceipt([redacted])" }
func (CapabilityReceipt) GoString() string     { return "CapabilityReceipt([redacted])" }
func capabilityReceiptAAD(device, request string) string {
	return "capability-request/v1/" + device + "/" + request
}

func capabilityInput(raw []byte) (CapabilityInput, error) {
	var input CapabilityInput
	if len(raw) > 8192 || identity.Decode(raw, &input, true) != nil || !idPattern.MatchString(input.RequestID) || len(input.PreviousHash) != 43 || !idPattern.MatchString(input.PreviousHash) {
		return input, identity.ErrInvalid
	}
	if _, _, e := canonicalCapabilities(input.Capabilities); e != nil {
		return input, e
	}
	return input, nil
}

// queueCapability runs under live account/device/session locks owned by the
// appropriate authentication path. It stores original input, never approval.
func (s *Store) queueCapability(ctx context.Context, tx *sql.Tx, a account, device, jkt, kind, session string, generation int64, original []byte, raw []byte, receipt CapabilityReceipt, until int64, now time.Time) (any, error) {
	var request Request
	if identity.Decode(original, &request, true) != nil {
		return nil, ErrDenied
	}
	state, e := EffectiveCapabilities(ctx, tx, device, request.Capabilities)
	if e != nil {
		return nil, e
	}
	if len(raw) == 0 {
		return CapabilitySnapshot{CapabilityState: state, AuthorityHash: identity.Hash([]byte(device + "/" + a.Owner + "/" + jkt + "/" + a.Grant))}, nil
	}
	input, e := capabilityInput(raw)
	if e != nil {
		return nil, e
	}
	var savedHash, savedKind, savedGrant string
	view := CapabilityRequestView{RequestID: input.RequestID}
	e = tx.QueryRowContext(ctx, `SELECT request_hash,auth_kind,grant_hash,state,result_revision,result_hash,error_code FROM identity_capability_requests WHERE device=$1 AND request_id=$2`, device, input.RequestID).Scan(&savedHash, &savedKind, &savedGrant, &view.State, &view.Version, &view.Hash, &view.Error)
	if e == nil {
		if savedHash != identity.Hash(raw) || savedKind != kind {
			return nil, ErrConflict
		}
		if savedGrant != a.Grant {
			return nil, ErrDenied
		}
		return view, nil
	}
	if e != sql.ErrNoRows {
		return nil, ErrUnavailable
	}
	caps, canonical, e := canonicalCapabilities(input.Capabilities)
	if e != nil {
		return nil, e
	}
	if input.PreviousHash != state.Hash {
		return nil, ErrConflict
	}
	if slices.Equal(caps, state.Capabilities) {
		return CapabilityRequestView{RequestID: input.RequestID, State: "approved", Version: state.Version, Hash: state.Hash}, nil
	}
	for _, old := range state.Capabilities {
		if !slices.Contains(caps, old) {
			return nil, ErrConflict
		}
	}
	if len(caps) <= len(state.Capabilities) || identity.Hash(canonical) == state.Hash || len(receipt.Token) < 24 || len(receipt.Token) > 16384 || len(receipt.Proof) < 24 || len(receipt.Proof) > 16384 || receipt.AcceptedAt != now.Unix() || until <= now.UnixMilli() {
		return nil, ErrDenied
	}
	var total, pending int
	if e = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state='queued') FROM identity_capability_requests WHERE device=$1`, device).Scan(&total, &pending); e != nil {
		return nil, ErrUnavailable
	}
	if total >= 64 || pending >= 4 {
		return nil, ErrDenied
	}
	encoded, e := json.Marshal(receipt)
	if e != nil {
		return nil, ErrUnavailable
	}
	protected := s.Seal(encoded, capabilityReceiptAAD(device, input.RequestID))
	deadline := min(until, now.Add(180*time.Second).UnixMilli())
	if _, e = tx.ExecContext(ctx, `INSERT INTO identity_capability_requests(device,request_id,owner,jkt,grant_hash,request_hash,body,receipt,accepted_ms,deadline_ms,auth_kind,session_id,session_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, device, input.RequestID, a.Owner, jkt, a.Grant, identity.Hash(raw), raw, protected, now.UnixMilli(), deadline, kind, session, generation); e != nil {
		return nil, ErrUnavailable
	}
	view.State = "queued"
	return view, nil
}

func (s *Store) CapabilityOIDC(ctx context.Context, principal identity.Principal, proof identity.Proof, raw []byte, receipt CapabilityReceipt, now time.Time) (any, error) {
	if ctx == nil || !principal.HasScope("syn443.enroll") || principal.Expires <= now.Unix() || principal.Thumbprint != proof.Thumbprint || len(raw) > 0 && proof.Claims.RequestHash != identity.Hash(raw) {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer tx.Rollback()
	a, e := lockAccount(ctx, tx, Owner(principal.Issuer, principal.Subject), now.Unix())
	if e != nil {
		return nil, e
	}
	if e = challenge(ctx, tx, a.Owner, proof.Thumbprint, proof.Claims.Nonce, now.Unix()); e != nil {
		var nonce NonceRequired
		if errors.As(e, &nonce) {
			if tx.Commit() != nil {
				return nil, ErrUnavailable
			}
		}
		return nil, e
	}
	var device, owner string
	var original []byte
	var active, approved bool
	e = tx.QueryRowContext(ctx, `SELECT id,owner,request_body,active,approved FROM identity_devices WHERE jkt=$1 FOR UPDATE`, proof.Thumbprint).Scan(&device, &owner, &original, &active, &approved)
	if e != nil || owner != a.Owner || !active || !approved {
		return nil, ErrDenied
	}
	if e = replay(ctx, tx, proof, now.Unix()); e != nil {
		return nil, e
	}
	until := min(principal.Expires, a.Until) * 1000
	result, e := s.queueCapability(ctx, tx, a, device, proof.Thumbprint, "oidc", "", 0, original, raw, receipt, until, now)
	if e != nil {
		return nil, e
	}
	if now.Add(time.Since(started)).UnixMilli() >= until {
		return nil, ErrDenied
	}
	if tx.Commit() != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

func (s *Store) CapabilityDevice(ctx context.Context, b Binding, token string, proof identity.Proof, raw []byte, receipt CapabilityReceipt, now time.Time) (any, error) {
	if ctx == nil || len(raw) > 0 && proof.Claims.RequestHash != identity.Hash(raw) {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.WithDeviceSession(ctx, b, token, proof, now, func(ctx context.Context, tx *sql.Tx, authority DeviceAuthority) (DeviceResult, error) {
		var original []byte
		if e := tx.QueryRowContext(ctx, `SELECT request_body FROM identity_devices WHERE id=$1 AND active AND approved`, b.Device).Scan(&original); e != nil {
			return DeviceResult{}, ErrDenied
		}
		a := account{Owner: authority.Binding.Owner, Grant: authority.GrantHash, Until: authority.AccountUntilMs / 1000}
		until := min(authority.AccountUntilMs, authority.Binding.AccessUntil*1000)
		result, e := s.queueCapability(ctx, tx, a, b.Device, b.Jkt, "device", authority.Binding.Session, authority.Binding.Generation, original, raw, receipt, until, now)
		return DeviceResult{Value: result, UntilMs: until}, e
	})
}
