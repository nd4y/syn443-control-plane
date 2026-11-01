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
	approvalActor, approvalEnvelope, e := VerifyAdmin(ctx, config.AdminVerifier, approvalReceipt, config.ControlOrigin, config.AssuranceACR, now)
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
	result = Publication{ID: r.ID, Owner: r.Owner, GrantHash: r.Grant, Thumbprint: r.Thumbprint, Device: r.Device, Version: r.Version, Expires: r.Expires, Enrollment: enrollment, issueActor: r.Actor, approvalActor: r.ApprovalActor, issueHash: identity.Hash(r.Issue), approvalHash: identity.Hash(r.ApprovalReceipt), claimHash: identity.Hash(r.ClaimPayload), enrollmentHash: identity.Hash(enrollment)}
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
	if !opaque.MatchString(p.ID) || !opaque.MatchString(p.Owner) || !opaque.MatchString(p.issueActor) || !opaque.MatchString(p.approvalActor) || len(p.Enrollment) == 0 || identity.Hash(p.Enrollment) != p.enrollmentHash {
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
