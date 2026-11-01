package invitation

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type Verifier interface {
	Verify(context.Context, string, time.Time) (identity.Principal, error)
}
type Receipt struct {
	Token      string `json:"token"`
	Proof      string `json:"proof"`
	URI        string `json:"uri"`
	Body       []byte `json:"body"`
	AcceptedAt int64  `json:"acceptedAt"`
}

func (Receipt) String() string   { return "InvitationAuthorityReceipt([redacted])" }
func (Receipt) GoString() string { return "InvitationAuthorityReceipt([redacted])" }

type Envelope struct {
	Version   int             `json:"version"`
	Action    string          `json:"action"`
	RequestID string          `json:"requestId"`
	Payload   json.RawMessage `json:"payload"`
}
type AdminService struct {
	Store                       *Store
	Verifier                    Verifier
	ControlOrigin, AssuranceACR string
	Descriptor                  string
	Anchor                      bootstrap.Anchor
}
type IssueRequest struct {
	Owner             string `json:"owner"`
	GrantHash         string `json:"grantHash"`
	Expires           int64  `json:"expires"`
	ServiceID         string `json:"serviceId"`
	BootstrapRevision int64  `json:"bootstrapRevision"`
}
type Issued struct {
	ID      string `json:"id"`
	Link    string `json:"link"`
	Expires int64  `json:"expires"`
	Version int64  `json:"version"`
}

func (Issued) String() string   { return "IssuedInvitation([redacted])" }
func (Issued) GoString() string { return "IssuedInvitation([redacted])" }

type Approval struct {
	ID         string `json:"id"`
	Version    int64  `json:"version"`
	Thumbprint string `json:"thumbprint"`
	PairCode   string `json:"pairCode"`
}
type Mutation struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

// Independently verifiable receipts are retained for the signer. The control
// API's UI role flag or successful parsing alone never authorizes enrollment.
func VerifyAdmin(ctx context.Context, verifier Verifier, receipt Receipt, origin, acr string, now time.Time) (string, Envelope, error) {
	var request Envelope
	if verifier == nil || receipt.URI != origin+"/v1/control/action" || receipt.AcceptedAt > now.Unix() || receipt.AcceptedAt < now.Unix()-180 || len(receipt.Token) < 24 || len(receipt.Token) > 16384 || len(receipt.Body) > 65536 || identity.Decode(receipt.Body, &request, true) != nil || request.Version != 1 || !requestID.MatchString(request.RequestID) {
		return "", request, ErrDenied
	}
	p, e := verifier.Verify(ctx, receipt.Token, now)
	sensitive := request.Action != "invite.get"
	if e != nil || !p.HasScope("syn443.control") || p.Expires <= now.Unix() || sensitive && p.MFAUntil(acr, now) <= now.Unix() {
		return "", request, ErrDenied
	}
	proof, e := identity.VerifyProof(receipt.Proof, identity.ProofContext{Method: "POST", URI: receipt.URI, Token: receipt.Token, BodyHash: identity.Hash(receipt.Body), Now: time.Unix(receipt.AcceptedAt, 0)})
	if e != nil || p.Thumbprint != proof.Thumbprint {
		return "", request, ErrDenied
	}
	return identity.Hash([]byte(p.Issuer + "\x00" + p.Subject)), request, nil
}
func (s *AdminService) Dispatch(ctx context.Context, token, proof string, raw []byte, now time.Time) (any, error) {
	if s.Store == nil {
		return nil, ErrUnavailable
	}
	receipt := Receipt{token, proof, s.ControlOrigin + "/v1/control/action", raw, now.Unix()}
	actor, request, e := VerifyAdmin(ctx, s.Verifier, receipt, s.ControlOrigin, s.AssuranceACR, now)
	if e != nil {
		return nil, e
	}
	switch request.Action {
	case "invite.issue":
		var issue IssueRequest
		if identity.Decode(request.Payload, &issue, true) != nil {
			return nil, ErrDenied
		}
		return s.issue(ctx, actor, request.RequestID, issue, receipt, now)
	case "invite.approve":
		var approval Approval
		if identity.Decode(request.Payload, &approval, true) != nil {
			return nil, ErrDenied
		}
		return s.approve(ctx, actor, request.RequestID, approval, receipt, now)
	case "invite.revoke", "invite.get":
		var mutation Mutation
		if identity.Decode(request.Payload, &mutation, true) != nil {
			return nil, ErrDenied
		}
		return s.mutate(ctx, actor, request.RequestID, mutation, request.Action == "invite.revoke", now)
	default:
		return nil, ErrDenied
	}
}
func (s *AdminService) issue(ctx context.Context, actor, request string, issue IssueRequest, receipt Receipt, now time.Time) (Issued, error) {
	if !opaque.MatchString(issue.Owner) || !opaque.MatchString(issue.GrantHash) || issue.Expires <= now.Unix() || issue.Expires > now.Unix()+600 {
		return Issued{}, ErrDenied
	}
	descriptor, _, e := bootstrap.VerifyDescriptor(s.Descriptor, s.Anchor, bootstrap.Floor{}, now)
	if e != nil || descriptor.ServiceID != issue.ServiceID || descriptor.Revision != issue.BootstrapRevision || issue.Expires > descriptor.Expires {
		return Issued{}, ErrDenied
	}
	hash := identity.Hash(receipt.Body)
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return Issued{}, ErrUnavailable
	}
	defer tx.Rollback()
	account, e := lockAccount(ctx, tx, issue.Owner)
	if e != nil {
		return Issued{}, e
	}
	if e = authorize(ctx, tx, actor, "invitations.issue", issue.Owner, now.Unix()); e != nil {
		return Issued{}, e
	}
	if !account.Enabled || account.Until < issue.Expires || account.Grant != issue.GrantHash {
		return Issued{}, ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "invitation-issue/"+actor+"/"+request); e != nil {
		return Issued{}, ErrUnavailable
	}
	var id, oldHash string
	var previous []byte
	e = tx.QueryRowContext(ctx, `SELECT id,body_hash,issue_reply FROM managed_invitations WHERE actor=$1 AND request_id=$2`, actor, request).Scan(&id, &oldHash, &previous)
	if e == nil {
		if oldHash != hash {
			return Issued{}, ErrConflict
		}
		record, e := s.Store.read(ctx, tx, id, true, now)
		if e != nil {
			return Issued{}, e
		}
		if record.Revoked || record.Expires <= now.Unix() || record.Thumbprint != "" {
			return Issued{}, ErrConflict
		}
		plain, e := s.Store.open(previous, "invitation/issue-reply/"+id)
		if e != nil {
			return Issued{}, e
		}
		var reply Issued
		if identity.Decode(plain, &reply, true) != nil {
			return Issued{}, ErrUnavailable
		}
		return reply, tx.Commit()
	}
	if e != sql.ErrNoRows {
		return Issued{}, ErrUnavailable
	}
	var outstanding int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_invitations WHERE owner=$1 AND NOT revoked AND expires>$2 AND final_session IS NULL`, issue.Owner, now.Unix()).Scan(&outstanding); e != nil {
		return Issued{}, ErrUnavailable
	}
	if outstanding >= 16 {
		return Issued{}, ErrDenied
	}
	id, e = random()
	if e != nil {
		return Issued{}, e
	}
	code, e := random()
	if e != nil {
		return Issued{}, e
	}
	link, e := bootstrap.Link(bootstrap.Invitation{ServiceID: descriptor.ServiceID, Origin: descriptor.APIOrigin, Code: code, Manifest: s.Descriptor})
	if e != nil {
		return Issued{}, ErrDenied
	}
	reply := Issued{ID: id, Link: link, Expires: issue.Expires, Version: 1}
	protectedReceipt, e := protect(s.Store, receipt, "invitation/issue-receipt/"+id)
	if e != nil {
		return Issued{}, e
	}
	protectedReply, e := protect(s.Store, reply, "invitation/issue-reply/"+id)
	if e != nil {
		return Issued{}, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO managed_invitations(id,owner,service_id,bootstrap_revision,grant_hash,actor,request_id,body_hash,code_hash,issue_receipt,issue_reply,created_at,expires) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, issue.Owner, issue.ServiceID, issue.BootstrapRevision, issue.GrantHash, actor, request, hash, identity.Hash([]byte(code)), protectedReceipt, protectedReply, now.Unix(), issue.Expires)
	if e != nil {
		return Issued{}, ErrUnavailable
	}
	return reply, tx.Commit()
}
func (s *AdminService) approve(ctx context.Context, actor, request string, approval Approval, receipt Receipt, now time.Time) (View, error) {
	if !opaque.MatchString(approval.ID) || !opaque.MatchString(approval.Thumbprint) || len(approval.PairCode) != 6 || approval.Version < 1 {
		return View{}, ErrDenied
	}
	hash := identity.Hash(receipt.Body)
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return View{}, ErrUnavailable
	}
	defer tx.Rollback()
	owner, e := lookupOwner(ctx, tx, approval.ID)
	if e != nil {
		return View{}, e
	}
	account, e := lockAccount(ctx, tx, owner)
	if e != nil {
		return View{}, e
	}
	if e = authorize(ctx, tx, actor, "invitations.approve", owner, now.Unix()); e != nil {
		return View{}, e
	}
	r, e := s.Store.read(ctx, tx, approval.ID, true, now)
	if e != nil {
		return View{}, e
	}
	if r.Revoked || r.Expires <= now.Unix() || !account.Enabled || account.Until <= now.Unix() || account.Grant != r.Grant {
		return View{}, ErrDenied
	}
	if len(r.ApprovalReceipt) > 0 {
		if r.ApprovalActor == actor && r.ApprovalRequest == request && r.ApprovalHash == hash {
			return r.View, tx.Commit()
		}
		return View{}, ErrConflict
	}
	if r.Version != approval.Version || r.Thumbprint != approval.Thumbprint || r.PairCode != approval.PairCode || r.Thumbprint == "" {
		return View{}, ErrConflict
	}
	protected, e := protect(s.Store, receipt, "invitation/approval-receipt/"+r.ID)
	if e != nil {
		return View{}, e
	}
	_, e = tx.ExecContext(ctx, `UPDATE managed_invitations SET approval_actor=$2,approval_request=$3,approval_hash=$4,approval_receipt=$5,approved_at=$6,version=version+1 WHERE id=$1`, r.ID, actor, request, hash, protected, now.Unix())
	if e != nil {
		return View{}, ErrUnavailable
	}
	r.Version++
	r.State = "provisioning"
	return r.View, tx.Commit()
}
func lookupOwner(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var owner string
	e := tx.QueryRowContext(ctx, `SELECT owner FROM managed_invitations WHERE id=$1`, id).Scan(&owner)
	if e == sql.ErrNoRows {
		return "", ErrDenied
	}
	if e != nil {
		return "", ErrUnavailable
	}
	return owner, nil
}
func (s *AdminService) mutate(ctx context.Context, actor, request string, mutation Mutation, revoke bool, now time.Time) (View, error) {
	if !opaque.MatchString(mutation.ID) {
		return View{}, ErrDenied
	}
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return View{}, ErrUnavailable
	}
	defer tx.Rollback()
	owner, e := lookupOwner(ctx, tx, mutation.ID)
	if e != nil {
		return View{}, e
	}
	if _, e = lockAccount(ctx, tx, owner); e != nil {
		return View{}, e
	}
	action := "invitations.read"
	if revoke {
		action = "invitations.revoke"
	}
	if e = authorize(ctx, tx, actor, action, owner, now.Unix()); e != nil {
		return View{}, e
	}
	r, e := s.Store.read(ctx, tx, mutation.ID, true, now)
	if e != nil {
		return View{}, e
	}
	if revoke && !r.Revoked {
		if r.Version != mutation.Version {
			return View{}, ErrConflict
		}
		if _, e = tx.ExecContext(ctx, `UPDATE managed_invitations SET revoked=true,version=version+1 WHERE id=$1`, r.ID); e != nil {
			return View{}, ErrUnavailable
		}
		r.Revoked = true
		r.Version++
		r.State = "revoked"
	}
	return r.View, tx.Commit()
}
