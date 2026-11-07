package catalog

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

//go:embed schema.sql
var Schema string

//go:embed roles.sql
var Roles string

type Store struct {
	DB     *sql.DB
	box    cipher.AEAD
	macKey []byte
	DeviceFetchEnabled bool
}

func (*Store) String() string   { return "CatalogStore([redacted])" }
func (*Store) GoString() string { return "CatalogStore([redacted])" }
func NewStore(db *sql.DB, key []byte) (*Store, error) {
	if db == nil || len(key) != 32 {
		return nil, ErrInvalid
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrInvalid
	}
	box, e := cipher.NewGCM(block)
	if e != nil {
		return nil, ErrInvalid
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("catalog/private-hashes/v1"))
	return &Store{DB: db, box: box, macKey: h.Sum(nil)}, nil
}
func (s *Store) seal(raw []byte, aad string) ([]byte, error) {
	nonce := make([]byte, s.box.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return nil, ErrUnavailable
	}
	return s.box.Seal(nonce, nonce, raw, []byte(aad)), nil
}
func (s *Store) open(raw []byte, aad string) ([]byte, error) {
	n := s.box.NonceSize()
	if len(raw) < n+s.box.Overhead() || len(raw) > 20*1024*1024 {
		return nil, ErrUnavailable
	}
	v, e := s.box.Open(nil, raw[:n], raw[n:], []byte(aad))
	if e != nil {
		return nil, ErrUnavailable
	}
	return v, nil
}
func random() (string, error) {
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func (s *Store) hash(parts ...[]byte) string {
	h := hmac.New(sha256.New, s.macKey)
	for _, part := range parts {
		h.Write(part)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (s *Store) Now(ctx context.Context, now time.Time) (time.Time, error) {
	var second int64
	e := s.DB.QueryRowContext(ctx, `UPDATE catalog_clock SET second=GREATEST(second,$1) WHERE id=true RETURNING second`, now.Unix()).Scan(&second)
	if e != nil {
		return time.Time{}, ErrUnavailable
	}
	return time.Unix(second, 0).UTC(), nil
}

// Actor is constructed only from a separately verified admin principal. The
// persistence layer still checks live object-scoped SQL authority for each call.
type Actor struct {
	ID           string
	SessionUntil int64
	MFAUntil     int64
}

func authorize(ctx context.Context, tx *sql.Tx, actor Actor, action, kind, id string, now int64, sensitive bool) error {
	if !identifier.MatchString(actor.ID) || actor.SessionUntil <= now || sensitive && actor.MFAUntil <= now {
		return ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT target_id FROM catalog_acl WHERE actor=$1 AND (action=$2 OR action='*') AND (target_kind=$3 OR target_kind='*') AND (target_id=$4 OR target_id='*') AND expires>$5 ORDER BY target_id LIMIT 1 FOR SHARE`, actor.ID, action, kind, id, now)
	if e != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return ErrDenied
	}
	return nil
}
func audit(ctx context.Context, tx *sql.Tx, actor, action, target, request, before, after, outcome string, now int64) error {
	_, e := tx.ExecContext(ctx, `INSERT INTO catalog_audit(actor,action,target,request_id,observed_at,before_hash,after_hash,outcome) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, actor, action, target, request, now, before, after, outcome)
	return e
}
func (s *Store) priorOperation(ctx context.Context, tx *sql.Tx, actor, request, action, target, hash string, now int64) ([]byte, error) {
	var oldAction, oldTarget, oldHash string
	var raw []byte
	var expires int64
	e := tx.QueryRowContext(ctx, `SELECT action,target,body_hash,response,expires FROM catalog_operations WHERE actor=$1 AND request_id=$2`, actor, request).Scan(&oldAction, &oldTarget, &oldHash, &raw, &expires)
	if e == sql.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	if oldAction != action || oldTarget != target || oldHash != hash || expires <= now {
		return nil, ErrConflict
	}
	return s.open(raw, "catalog-operation/v1/"+actor+"/"+request)
}
func (s *Store) recordOperation(ctx context.Context, tx *sql.Tx, actor, request, action, target, hash string, value any, now int64) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return ErrInvalid
	}
	protected, e := s.seal(raw, "catalog-operation/v1/"+actor+"/"+request)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO catalog_operations(actor,request_id,action,target,body_hash,response,expires) VALUES($1,$2,$3,$4,$5,$6,$7)`, actor, request, action, target, hash, protected, now+86400)
	return e
}
func (s *Store) RuntimeRole(ctx context.Context, worker bool) error {
	expected := "syn443_control_api"
	if worker {
		expected = "syn443_source_worker"
	}
	var name, session string
	var unsafe bool
	var memberships int
	if e := s.DB.QueryRowContext(ctx, `SELECT current_user,session_user,rolsuper OR rolbypassrls OR rolinherit OR rolcreatedb OR rolcreaterole,(SELECT count(*) FROM pg_auth_members WHERE member=r.oid) FROM pg_roles r WHERE rolname=current_user`).Scan(&name, &session, &unsafe, &memberships); e != nil || name != expected || session != expected || unsafe || memberships != 0 {
		return ErrDenied
	}
	return nil
}
func aad(kind, id string, revision int64) string {
	return fmt.Sprintf("catalog-%s/v1/%s/%d", kind, id, revision)
}
