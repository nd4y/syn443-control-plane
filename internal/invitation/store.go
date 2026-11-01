// Package invitation owns one-use device enrollment reservations. It does not
// create users, sign policies or issue device sessions before publisher approval.
package invitation

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

//go:embed schema.sql
var Schema string

//go:embed roles.sql
var Roles string
var ErrDenied = errors.New("invitation_denied")
var ErrConflict = errors.New("invitation_conflict")
var ErrExpired = errors.New("invitation_expired")
var ErrUnavailable = errors.New("invitation_unavailable")
var ErrPending = errors.New("invitation_pending")
var opaque = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{24,128}$`)

type Store struct {
	DB  *sql.DB
	box cipher.AEAD
}

func (*Store) String() string   { return "InvitationStore([redacted])" }
func (*Store) GoString() string { return "InvitationStore([redacted])" }
func NewStore(db *sql.DB, key []byte) (*Store, error) {
	if db == nil || len(key) != 32 {
		return nil, ErrDenied
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrDenied
	}
	box, e := cipher.NewGCM(block)
	if e != nil {
		return nil, ErrDenied
	}
	return &Store{db, box}, nil
}
func random() (string, error) {
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func (s *Store) seal(raw []byte, aad string) ([]byte, error) {
	if len(raw) > 262144 {
		return nil, ErrDenied
	}
	nonce := make([]byte, s.box.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return nil, ErrUnavailable
	}
	return s.box.Seal(nonce, nonce, raw, []byte(aad)), nil
}
func (s *Store) open(raw []byte, aad string) ([]byte, error) {
	n := s.box.NonceSize()
	if len(raw) < n+s.box.Overhead() || len(raw) > 262144+n+s.box.Overhead() {
		return nil, ErrUnavailable
	}
	value, e := s.box.Open(nil, raw[:n], raw[n:], []byte(aad))
	if e != nil {
		return nil, ErrUnavailable
	}
	return value, nil
}

type account struct {
	Owner, Grant string
	Limit        int
	Until        int64
	Enabled      bool
}

func lockAccount(ctx context.Context, tx *sql.Tx, owner string) (account, error) {
	result := account{Owner: owner}
	if !opaque.MatchString(owner) {
		return result, ErrDenied
	}
	e := tx.QueryRowContext(ctx, `SELECT enabled,device_limit,valid_until,grant_hash FROM identity_accounts WHERE owner=$1 FOR UPDATE`, owner).Scan(&result.Enabled, &result.Limit, &result.Until, &result.Grant)
	if e == sql.ErrNoRows {
		return result, ErrDenied
	}
	if e != nil {
		return result, ErrUnavailable
	}
	return result, nil
}
func authorize(ctx context.Context, tx *sql.Tx, actor, action, owner string, now int64) error {
	var target string
	if !opaque.MatchString(actor) {
		return ErrDenied
	}
	e := tx.QueryRowContext(ctx, `SELECT target_id FROM catalog_acl WHERE actor=$1 AND (action=$2 OR action='*') AND (target_kind='user' OR target_kind='*') AND (target_id=$3 OR target_id='*') AND expires>$4 ORDER BY target_id LIMIT 1 FOR SHARE`, actor, action, owner, now).Scan(&target)
	if e == sql.ErrNoRows {
		return ErrDenied
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}

type View struct {
	Error      string `json:"error,omitempty"`
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Version    int64  `json:"version"`
	Expires    int64  `json:"expires"`
	State      string `json:"state"`
	Thumbprint string `json:"thumbprint"`
	PairCode   string `json:"pairCode"`
	Device     string `json:"device"`
}

func (View) String() string   { return "InvitationView([redacted])" }
func (View) GoString() string { return "InvitationView([redacted])" }

type record struct {
	CreatedAt int64
	View
	Grant, Actor, Request, Hash, CodeHash, ServiceID string
	BootstrapRevision                                int64
	Issue, Reply                                     []byte
	Revoked                                          bool
	ClaimRequest, ClaimHash, Nonce                   string
	ClaimPayload, ClaimReceipt                       []byte
	ClaimedAt                                        int64
	ApprovalActor, ApprovalRequest, ApprovalHash     string
	ApprovalReceipt                                  []byte
	ApprovedAt                                       int64
	FinalRequest, FinalHash, FinalSession            string
	FinalizedAt                                      int64
}

func (s *Store) read(ctx context.Context, tx *sql.Tx, id string, lock bool, now time.Time) (record, error) {
	var r record
	query := `SELECT id,owner,version,expires,grant_hash,actor,request_id,body_hash,code_hash,service_id,bootstrap_revision,issue_receipt,issue_reply,revoked,COALESCE(claim_jkt,''),COALESCE(claim_request,''),COALESCE(claim_hash,''),COALESCE(claim_nonce,''),COALESCE(pair_code,''),claim_payload,claim_receipt,COALESCE(claimed_at,0),COALESCE(approval_actor,''),COALESCE(approval_request,''),COALESCE(approval_hash,''),approval_receipt,COALESCE(approved_at,0),COALESCE(device,''),COALESCE(final_request,''),COALESCE(final_hash,''),COALESCE(final_session,''),COALESCE(finalized_at,0),created_at,publication_error FROM managed_invitations WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	e := tx.QueryRowContext(ctx, query, id).Scan(&r.ID, &r.Owner, &r.Version, &r.Expires, &r.Grant, &r.Actor, &r.Request, &r.Hash, &r.CodeHash, &r.ServiceID, &r.BootstrapRevision, &r.Issue, &r.Reply, &r.Revoked, &r.Thumbprint, &r.ClaimRequest, &r.ClaimHash, &r.Nonce, &r.PairCode, &r.ClaimPayload, &r.ClaimReceipt, &r.ClaimedAt, &r.ApprovalActor, &r.ApprovalRequest, &r.ApprovalHash, &r.ApprovalReceipt, &r.ApprovedAt, &r.Device, &r.FinalRequest, &r.FinalHash, &r.FinalSession, &r.FinalizedAt, &r.CreatedAt, &r.Error)
	if e == sql.ErrNoRows {
		return r, ErrDenied
	}
	if e != nil {
		return r, ErrUnavailable
	}
	r.State = "issued"
	if r.Thumbprint != "" {
		r.State = "pending_approval"
	}
	if len(r.ApprovalReceipt) > 0 {
		r.State = "provisioning"
	}
	if r.Device != "" {
		var active, approved bool
		var offline int64
		var code string
		if tx.QueryRowContext(ctx, `SELECT active,approved,offline_until,publication_error FROM identity_devices WHERE id=$1`, r.Device).Scan(&active, &approved, &offline, &code) != nil {
			return r, ErrUnavailable
		}
		r.Error = code
		if approved && offline > now.Unix() {
			r.State = "ready"
		}
		if !active {
			r.State = "revoked"
		}
	}
	if r.FinalSession != "" && r.State != "revoked" {
		r.State = "completed"
	}
	if r.Expires <= now.Unix() && r.FinalSession == "" {
		r.State = "expired"
	}
	if r.Revoked {
		r.State = "revoked"
	}
	return r, nil
}
func (s *Store) RuntimeRole(ctx context.Context, expected string) error {
	if expected != "syn443_control_api" && expected != "syn443_identity_api" && expected != "syn443_identity_publisher" {
		return ErrDenied
	}
	var current, session string
	var unsafe bool
	e := s.DB.QueryRowContext(ctx, `SELECT current_user,session_user,rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole OR rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) FROM pg_roles r WHERE rolname=current_user`).Scan(&current, &session, &unsafe)
	if e != nil || current != expected || session != expected || unsafe {
		return ErrDenied
	}
	return nil
}
func pair() (string, error) {
	raw := make([]byte, 4)
	if _, e := rand.Read(raw); e != nil {
		return "", ErrUnavailable
	}
	number := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	return fmt.Sprintf("%06d", number%1000000), nil
}
func replay(ctx context.Context, tx *sql.Tx, proof identity.Proof, now int64) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM managed_invitation_replays WHERE expires<=$1`, now); e != nil {
		return ErrUnavailable
	}
	result, e := tx.ExecContext(ctx, `INSERT INTO managed_invitation_replays(jkt,jti,expires) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, proof.Thumbprint, proof.Claims.Jti, now+180)
	if e != nil {
		return ErrUnavailable
	}
	count, e := result.RowsAffected()
	if e != nil {
		return ErrUnavailable
	}
	if count != 1 {
		return ErrDenied
	}
	return nil
}
func protect(s *Store, value any, aad string) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, ErrDenied
	}
	return s.seal(raw, aad)
}
