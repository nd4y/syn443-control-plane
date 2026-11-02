package invitation

import (
	"context"
	"database/sql"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type Verification struct {
	AdminVerifier                               Verifier
	ControlOrigin, IdentityOrigin, AssuranceACR string
	Anchor                                      bootstrap.Anchor
}

// Publication is an independently verified immutable dependency receipt. No
// parser, HTTP caller or database row alone can construct signing authority.
type Publication struct {
	ID, Owner, GrantHash, Thumbprint, Device                                      string
	authorityUntil                                                                int64
	Version, Expires                                                              int64
	Enrollment                                                                    []byte
	issueActor, approvalActor, issueHash, approvalHash, claimHash, enrollmentHash string
}

func (Publication) String() string   { return "VerifiedInvitationPublication([redacted])" }
func (Publication) GoString() string { return "VerifiedInvitationPublication([redacted])" }
func (s *Store) Ready(ctx context.Context, id string, config Verification, now time.Time) (Publication, error) {
	var result Publication
	if !opaque.MatchString(id) {
		return result, ErrDenied
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, ErrUnavailable
	}
	r, e := s.read(ctx, tx, id, false, now)
	tx.Rollback()
	if e != nil {
		return result, e
	}
	if r.Revoked || r.Expires <= now.Unix() || r.CreatedAt > r.ClaimedAt || r.ClaimedAt > r.ApprovedAt || r.ApprovedAt > now.Unix() || r.Expires-r.CreatedAt > 600 || len(r.ApprovalReceipt) == 0 {
		return result, ErrDenied
	}
	decode := func(protected []byte, aad string, dst any) error {
		raw, e := s.open(protected, aad+id)
		if e != nil || identity.DecodeConfiguration(raw, dst) != nil {
			return ErrDenied
		}
		return nil
	}
	var issueReceipt, approvalReceipt Receipt
	var claimedReceipt KeyReceipt
	var claim Claim
	var issued Issued
	if decode(r.Issue, "invitation/issue-receipt/", &issueReceipt) != nil || decode(r.ApprovalReceipt, "invitation/approval-receipt/", &approvalReceipt) != nil || decode(r.ClaimPayload, "invitation/claim-payload/", &claim) != nil || decode(r.ClaimReceipt, "invitation/claim-receipt/", &claimedReceipt) != nil || decode(r.Reply, "invitation/issue-reply/", &issued) != nil {
		return result, ErrDenied
	}
	if issueReceipt.AcceptedAt != r.CreatedAt || approvalReceipt.AcceptedAt != r.ApprovedAt || claimedReceipt.AcceptedAt != r.ClaimedAt || issueReceipt.AcceptedAt < now.Unix()-600 {
		return result, ErrDenied
	}
	// Issuance can precede a human approval by up to10minutes. Its original
	// signature/authentication is checked at acceptance, while SQL authority is
	// checked again at the current publication point. Approval must still be fresh.
	issueActor, issueEnvelope, e := VerifyAdmin(ctx, config.AdminVerifier, issueReceipt, config.ControlOrigin, config.AssuranceACR, time.Unix(issueReceipt.AcceptedAt, 0))
	if e != nil {
		return result, e
	}
	approvalActor, approvalEnvelope, authorityUntil, e := verifyAdmin(ctx, config.AdminVerifier, approvalReceipt, config.ControlOrigin, config.AssuranceACR, now)
	if e != nil {
		return result, e
	}
	var issue IssueRequest
	var approval Approval
	if identity.Decode(issueEnvelope.Payload, &issue, true) != nil || identity.Decode(approvalEnvelope.Payload, &approval, true) != nil || issueEnvelope.Action != "invite.issue" || approvalEnvelope.Action != "invite.approve" || issueEnvelope.RequestID != r.Request || approvalEnvelope.RequestID != r.ApprovalRequest || issueActor != r.Actor || approvalActor != r.ApprovalActor || identity.Hash(issueReceipt.Body) != r.Hash || identity.Hash(approvalReceipt.Body) != r.ApprovalHash {
		return result, ErrDenied
	}
	if issue.Owner != r.Owner || issue.GrantHash != r.Grant || issue.Expires != r.Expires || issue.ServiceID != r.ServiceID || issue.BootstrapRevision != r.BootstrapRevision || approval.ID != r.ID || approval.Thumbprint != r.Thumbprint || approval.PairCode != r.PairCode || approval.Version+1 > r.Version {
		return result, ErrDenied
	}
	invitation, e := bootstrap.AuthenticateLink(issued.Link, config.Anchor, bootstrap.Floor{}, now)
	if e != nil || issued.ID != r.ID || issued.Expires != r.Expires || invitation.Descriptor.ServiceID != r.ServiceID || invitation.Descriptor.Revision != r.BootstrapRevision || invitation.Descriptor.APIOrigin != config.IdentityOrigin || identity.Hash([]byte(invitation.Code)) != r.CodeHash {
		return result, ErrDenied
	}
	claimRaw, e := s.open(r.ClaimPayload, "invitation/claim-payload/"+id)
	if e != nil || claim.validate() != nil || claim.RequestID != r.ClaimRequest || claim.Code != invitation.Code || identity.Hash(claimRaw) != r.ClaimHash || claimedReceipt.URI != config.IdentityOrigin+"/v1/invitations/claim" {
		return result, ErrDenied
	}
	proof, e := identity.VerifyProof(claimedReceipt.Proof, identity.ProofContext{Method: "POST", URI: claimedReceipt.URI, BodyHash: identity.Hash(claimRaw), Now: time.Unix(claimedReceipt.AcceptedAt, 0)})
	thumb, _ := claim.Key.Thumbprint()
	if e != nil || proof.Thumbprint != r.Thumbprint || thumb != r.Thumbprint {
		return result, ErrDenied
	}
	enrollment, e := claim.EnrollmentRequest()
	if e != nil {
		return result, e
	}
	result = Publication{authorityUntil: authorityUntil, ID: r.ID, Owner: r.Owner, GrantHash: r.Grant, Thumbprint: r.Thumbprint, Device: r.Device, Version: r.Version, Expires: r.Expires, Enrollment: enrollment, issueActor: r.Actor, approvalActor: r.ApprovalActor, issueHash: identity.Hash(r.Issue), approvalHash: identity.Hash(r.ApprovalReceipt), claimHash: identity.Hash(r.ClaimPayload), enrollmentHash: identity.Hash(enrollment)}
	tx, e = s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Publication{}, ErrUnavailable
	}
	defer tx.Rollback()
	if e = s.LockPublication(ctx, tx, result, now); e != nil {
		return Publication{}, e
	}
	if e = tx.Commit(); e != nil {
		return Publication{}, ErrUnavailable
	}
	return result, nil
}

// LockPublication repeats authority, account, expiry and exact receipt fences in
// the signer's final transaction. Lock order is account, invitation, device.
func (s *Store) LockPublication(ctx context.Context, tx *sql.Tx, p Publication, now time.Time) error {
	if p.authorityUntil <= now.Unix() || !opaque.MatchString(p.ID) || !opaque.MatchString(p.Owner) || !opaque.MatchString(p.issueActor) || !opaque.MatchString(p.approvalActor) || len(p.Enrollment) == 0 || identity.Hash(p.Enrollment) != p.enrollmentHash {
		return ErrDenied
	}
	a, e := lockAccount(ctx, tx, p.Owner)
	if e != nil {
		return e
	}
	r, e := s.read(ctx, tx, p.ID, true, now)
	if e != nil {
		return e
	}
	if !a.Enabled || a.Until <= now.Unix() || a.Grant != p.GrantHash || r.Grant != p.GrantHash || r.Owner != p.Owner || r.Revoked || r.Expires <= now.Unix() || r.Expires != p.Expires || r.Version != p.Version || r.Thumbprint != p.Thumbprint || r.Device != p.Device || identity.Hash(r.Issue) != p.issueHash || identity.Hash(r.ApprovalReceipt) != p.approvalHash || identity.Hash(r.ClaimPayload) != p.claimHash {
		return ErrConflict
	}
	if e = authorize(ctx, tx, p.issueActor, "invitations.issue", p.Owner, now.Unix()); e != nil {
		return e
	}
	return authorize(ctx, tx, p.approvalActor, "invitations.approve", p.Owner, now.Unix())
}

type Ticket struct {
	ID      string
	Version int64
}

func (s *Store) Pending(ctx context.Context, now time.Time) ([]Ticket, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT id,version FROM managed_invitations WHERE approval_receipt IS NOT NULL AND device IS NULL AND NOT revoked AND expires>$1 AND retry_after<=$1 ORDER BY retry_after,approved_at,id LIMIT 16`, now.Unix())
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := []Ticket{}
	for rows.Next() {
		var id Ticket
		if rows.Scan(&id.ID, &id.Version) != nil {
			return nil, ErrUnavailable
		}
		result = append(result, id)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

// BindDevice is called only by the independently verified publisher, in the same
// transaction as creating the ordinary unapproved identity device. No session
// is minted here. FK/trigger and final receipt/version checks preserve scope.
func (s *Store) BindDevice(ctx context.Context, tx *sql.Tx, p Publication, device string, now time.Time) error {
	if !opaque.MatchString(device) || p.Device != "" {
		return ErrDenied
	}
	if e := s.LockPublication(ctx, tx, p, now); e != nil {
		return e
	}
	var owner, jkt string
	var raw []byte
	var active bool
	if e := tx.QueryRowContext(ctx, `SELECT owner,jkt,request_body,active FROM identity_devices WHERE id=$1 FOR UPDATE`, device).Scan(&owner, &jkt, &raw, &active); e != nil {
		return ErrUnavailable
	}
	if !active || owner != p.Owner || jkt != p.Thumbprint || identity.Hash(raw) != p.enrollmentHash {
		return ErrDenied
	}
	if _, e := tx.ExecContext(ctx, `UPDATE managed_invitations SET device=$2,version=version+1 WHERE id=$1`, p.ID, device); e != nil {
		return ErrUnavailable
	}
	return nil
}

// PublicationFailure is metadata only and is fenced against a new approval or
// revocation. Backoff lets later eligible invitations progress after failures.
func (s *Store) PublicationFailure(ctx context.Context, t Ticket, code string, now time.Time) error {
	if !opaque.MatchString(t.ID) || t.Version < 1 {
		return ErrDenied
	}
	switch code {
	case "authorization_changed", "unsupported_capabilities", "temporarily_unavailable":
	default:
		return ErrDenied
	}
	_, e := s.DB.ExecContext(ctx, `UPDATE managed_invitations SET retry_after=$3,publication_error=$4 WHERE id=$1 AND version=$2 AND device IS NULL AND NOT revoked`, t.ID, t.Version, now.Unix()+30, code)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) Reservations(ctx context.Context, tx *sql.Tx, owner string, now time.Time) (int, error) {
	var count int
	e := tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_invitations WHERE owner=$1 AND claim_jkt IS NOT NULL AND device IS NULL AND NOT revoked AND expires>$2`, owner, now.Unix()).Scan(&count)
	if e != nil {
		return 0, ErrUnavailable
	}
	return count, nil
}

// Expire performs at most16 server-time-fenced cancellations through the narrow
// migration-owned primitive. The publisher gains no general session authority.
func (s *Store) Expire(ctx context.Context) error {
	var count int
	if s.DB.QueryRowContext(ctx, `SELECT managed_invitation_expire()`).Scan(&count) != nil {
		return ErrUnavailable
	}
	return nil
}
