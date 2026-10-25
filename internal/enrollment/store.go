// Package enrollment is the durable identity/provisioning pilot. It does not grant admin sessions.
package enrollment

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
	"regexp"
	"strconv"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

//go:embed schema.sql
var Schema string

//go:embed roles.sql
var Roles string
var ErrDenied = errors.New("access_denied")
var ErrConflict = errors.New("idempotency_conflict")
var ErrReplay = errors.New("proof_replayed")
var ErrReuse = errors.New("session_reuse")
var ErrPending = errors.New("provisioning_pending")
var ErrReauth = errors.New("reauthentication_required")
var ErrUnavailable = errors.New("temporarily_unavailable")

type NonceRequired struct{ Value string }

func (e NonceRequired) Error() string { return "use_dpop_nonce" }

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{24,128}$`)

type Request struct {
	RequestID    string       `json:"requestId"`
	Key          identity.JWK `json:"key"`
	Capabilities []string     `json:"capabilities"`
}
type Receipt struct {
	Token      string `json:"token"`
	Proof      string `json:"proof"`
	URI        string `json:"uri"`
	AcceptedAt int64  `json:"acceptedAt"`
}
type Session struct {
	DeviceID       string `json:"deviceId"`
	AccessToken    string `json:"accessToken"`
	RefreshToken   string `json:"refreshToken"`
	AccessUntilMs  int64  `json:"accessUntilMs"`
	RefreshUntilMs int64  `json:"refreshUntilMs"`
	Generation     int64  `json:"generation"`
	Nonce          string `json:"nonce"`
}
type Store struct {
	DB  *sql.DB
	box cipher.AEAD
}

func NewStore(db *sql.DB, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, identity.ErrInvalid
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	box, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return &Store{db, box}, nil
}
func (s *Store) Now(ctx context.Context, wall time.Time) (time.Time, error) {
	var n int64
	e := s.DB.QueryRowContext(ctx, `UPDATE identity_clock SET second=GREATEST(second,$1) WHERE id=true RETURNING second`, wall.Unix()).Scan(&n)
	return time.Unix(n, 0).UTC(), e
}
func random() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func Owner(issuer, subject string) string { return identity.Hash([]byte(issuer + "\x00" + subject)) }
func (s *Store) Seal(raw []byte, aad string) []byte {
	nonce := make([]byte, s.box.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		panic("entropy unavailable")
	}
	return s.box.Seal(nonce, nonce, raw, []byte(aad))
}
func (s *Store) Open(raw []byte, aad string) ([]byte, error) {
	if len(raw) < s.box.NonceSize()+s.box.Overhead() {
		return nil, ErrUnavailable
	}
	return s.box.Open(nil, raw[:s.box.NonceSize()], raw[s.box.NonceSize():], []byte(aad))
}

type account struct {
	Owner string
	Limit int
	Until int64
	Grant string
}

func lockAccount(ctx context.Context, tx *sql.Tx, owner string, now int64) (account, error) {
	var a account
	var enabled bool
	a.Owner = owner
	e := tx.QueryRowContext(ctx, `SELECT enabled,device_limit,valid_until,grant_hash FROM identity_accounts WHERE owner=$1 FOR UPDATE`, owner).Scan(&enabled, &a.Limit, &a.Until, &a.Grant)
	if errors.Is(e, sql.ErrNoRows) || e == nil && (!enabled || a.Until <= now) {
		return a, ErrDenied
	}
	return a, e
}
func replay(ctx context.Context, tx *sql.Tx, p identity.Proof, now int64) error {
	// Bounded by API admission; expiry is longer than the accepted proof age.
	_, e := tx.ExecContext(ctx, `DELETE FROM identity_replays WHERE expires<$1`, now)
	if e != nil {
		return e
	}
	r, e := tx.ExecContext(ctx, `INSERT INTO identity_replays(jkt,jti,expires) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.Thumbprint, p.Claims.Jti, now+180)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrReplay
	}
	return nil
}
func (s *Store) cached(ctx context.Context, tx *sql.Tx, owner, jkt, kind, id, hash string, now int64) (Session, bool, error) {
	var result Session
	var stored string
	var raw []byte
	var expires, recorded, current int64
	var active bool
	e := tx.QueryRowContext(ctx, `SELECT r.body_hash,r.response,r.expires,r.generation,s.generation,s.active AND d.active FROM identity_requests r JOIN identity_sessions s ON s.id=r.session JOIN identity_devices d ON d.id=s.device WHERE r.owner=$1 AND r.jkt=$2 AND r.kind=$3 AND r.request_id=$4`, owner, jkt, kind, id).Scan(&stored, &raw, &expires, &recorded, &current, &active)
	if errors.Is(e, sql.ErrNoRows) {
		return result, false, nil
	}
	if e != nil {
		return result, false, e
	}
	if hash != stored || now >= expires || recorded != current || !active {
		return result, true, ErrConflict
	}
	raw, e = s.Open(raw, "reply/v1/"+owner+"/"+jkt+"/"+kind+"/"+id)
	if e != nil || identity.Decode(raw, &result, true) != nil {
		return result, true, ErrUnavailable
	}
	return result, true, nil
}
func (s *Store) cache(ctx context.Context, tx *sql.Tx, owner, jkt, kind, id, hash, session string, value Session, now int64) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM identity_requests WHERE expires<$1`, now); e != nil {
		return e
	}
	raw, _ := json.Marshal(value)
	encrypted := s.Seal(raw, "reply/v1/"+owner+"/"+jkt+"/"+kind+"/"+id)
	_, e := tx.ExecContext(ctx, `INSERT INTO identity_requests(owner,jkt,kind,request_id,body_hash,response,session,generation,expires) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, owner, jkt, kind, id, hash, encrypted, session, value.Generation, now+180)
	return e
}
func (s *Store) Register(ctx context.Context, principal identity.Principal, proof identity.Proof, raw []byte, receipt Receipt, now time.Time) (Session, error) {
	var result Session
	var req Request
	if identity.Decode(raw, &req, true) != nil || !idPattern.MatchString(req.RequestID) || len(req.Capabilities) < 2 || len(req.Capabilities) > 16 {
		return result, identity.ErrInvalid
	}
	caps := map[string]bool{}
	for _, v := range req.Capabilities {
		if len(v) < 1 || len(v) > 64 || caps[v] {
			return result, identity.ErrInvalid
		}
		caps[v] = true
	}
	if !caps["engine-config.v1"] || !caps["tun.lease.v1"] {
		return result, identity.ErrInvalid
	}
	thumb, e := req.Key.Thumbprint()
	if e != nil || thumb != principal.Thumbprint || thumb != proof.Thumbprint || proof.Claims.RequestHash != identity.Hash(raw) {
		return result, ErrDenied
	}
	owner := Owner(principal.Issuer, principal.Subject)
	n := now.Unix()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	a, e := lockAccount(ctx, tx, owner, n)
	if e != nil {
		return result, e
	}
	var nonce string
	var expires int64
	e = tx.QueryRowContext(ctx, `SELECT nonce,expires FROM identity_challenges WHERE owner=$1 AND jkt=$2`, owner, thumb).Scan(&nonce, &expires)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return result, e
	}
	if e != nil || expires <= n || proof.Claims.Nonce != nonce {
		nonce = random()
		_, e = tx.ExecContext(ctx, `INSERT INTO identity_challenges(owner,jkt,nonce,expires) VALUES($1,$2,$3,$4) ON CONFLICT(owner,jkt) DO UPDATE SET nonce=excluded.nonce,expires=excluded.expires`, owner, thumb, nonce, n+180)
		if e != nil {
			return result, e
		}
		if e = tx.Commit(); e != nil {
			return result, e
		}
		return result, NonceRequired{nonce}
	}
	if e = replay(ctx, tx, proof, n); e != nil {
		return result, e
	}
	result, found, e := s.cached(ctx, tx, owner, thumb, "enroll", req.RequestID, identity.Hash(raw), n)
	if e != nil {
		return result, e
	}
	if found {
		return result, tx.Commit()
	}
	var device, actualOwner string
	var active bool
	e = tx.QueryRowContext(ctx, `SELECT id,owner,active FROM identity_devices WHERE jkt=$1 FOR UPDATE`, thumb).Scan(&device, &actualOwner, &active)
	if errors.Is(e, sql.ErrNoRows) {
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE owner=$1 AND active`, owner).Scan(&count); e != nil {
			return result, e
		}
		if count >= a.Limit {
			return result, ErrDenied
		}
		device = random()
		data, _ := json.Marshal(receipt)
		encrypted := s.Seal(data, "receipt/v1/"+device)
		_, e = tx.ExecContext(ctx, `INSERT INTO identity_devices(id,owner,jkt,request_body,receipt) VALUES($1,$2,$3,$4,$5)`, device, owner, thumb, raw, encrypted)
	} else if e == nil {
		if actualOwner != owner || !active {
			return result, ErrDenied
		}
		// Refreshing an authenticated registration never creates another device or revives a revoked key.
		data, _ := json.Marshal(receipt)
		_, e = tx.ExecContext(ctx, `UPDATE identity_devices SET request_body=$2,receipt=$3,retry_after=0 WHERE id=$1`, device, raw, s.Seal(data, "receipt/v1/"+device))
	}
	if e != nil {
		return result, e
	}
	_, e = tx.ExecContext(ctx, `UPDATE identity_sessions SET active=false WHERE device=$1`, device)
	if e != nil {
		return result, e
	}
	sid := random()
	until := min(n+86400, a.Until)
	result = Session{device, random(), random(), min(n+600, a.Until) * 1000, until * 1000, 0, random()}
	_, e = tx.ExecContext(ctx, `INSERT INTO identity_sessions(id,device,access_hash,refresh_hash,access_until,refresh_until,generation,nonce) VALUES($1,$2,$3,$4,$5,$6,0,$7)`, sid, device, identity.Hash([]byte(result.AccessToken)), identity.Hash([]byte(result.RefreshToken)), result.AccessUntilMs/1000, until, result.Nonce)
	if e != nil {
		return result, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO identity_refresh_history(hash,session,expires) VALUES($1,$2,$3)`, identity.Hash([]byte(result.RefreshToken)), sid, until)
	if e != nil {
		return result, e
	}
	if e = s.cache(ctx, tx, owner, thumb, "enroll", req.RequestID, identity.Hash(raw), sid, result, n); e != nil {
		return result, e
	}
	return result, tx.Commit()
}

type Binding struct {
	Owner, Device, Session, Jkt, Nonce    string
	AccessUntil, RefreshUntil, Generation int64
	Active                                bool
}

func (s *Store) Lookup(ctx context.Context, token string, refresh bool) (Binding, error) {
	var b Binding
	hash := identity.Hash([]byte(token))
	if len(token) < 24 || len(token) > 128 {
		return b, ErrDenied
	}
	query := `SELECT d.owner,d.id,s.id,d.jkt,s.nonce,s.access_until,s.refresh_until,s.generation,s.active AND d.active FROM identity_sessions s JOIN identity_devices d ON d.id=s.device WHERE s.access_hash=$1`
	if refresh {
		query = `SELECT d.owner,d.id,s.id,d.jkt,s.nonce,s.access_until,s.refresh_until,s.generation,s.active AND d.active FROM identity_refresh_history h JOIN identity_sessions s ON s.id=h.session JOIN identity_devices d ON d.id=s.device WHERE h.hash=$1`
	}
	e := s.DB.QueryRowContext(ctx, query, hash).Scan(&b.Owner, &b.Device, &b.Session, &b.Jkt, &b.Nonce, &b.AccessUntil, &b.RefreshUntil, &b.Generation, &b.Active)
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrDenied
	}
	return b, e
}

// Access, refresh and revocation linearize under the same account/device/session locks.
func (s *Store) lockSession(ctx context.Context, tx *sql.Tx, b Binding, proof identity.Proof, now int64, refresh bool) (account, Binding, error) {
	a, e := lockAccount(ctx, tx, b.Owner, now)
	if e != nil {
		return a, b, e
	}
	var active bool
	var owner, jkt string
	e = tx.QueryRowContext(ctx, `SELECT owner,jkt,active FROM identity_devices WHERE id=$1 FOR UPDATE`, b.Device).Scan(&owner, &jkt, &active)
	if e != nil {
		return a, b, e
	}
	if !active || owner != b.Owner || jkt != proof.Thumbprint {
		return a, b, ErrDenied
	}
	e = tx.QueryRowContext(ctx, `SELECT nonce,access_until,refresh_until,generation,active FROM identity_sessions WHERE id=$1 FOR UPDATE`, b.Session).Scan(&b.Nonce, &b.AccessUntil, &b.RefreshUntil, &b.Generation, &b.Active)
	if e != nil {
		return a, b, e
	}
	if !b.Active || b.RefreshUntil <= now || !refresh && b.AccessUntil <= now {
		return a, b, ErrDenied
	}
	if proof.Claims.Nonce != b.Nonce {
		return a, b, NonceRequired{b.Nonce}
	}
	return a, b, replay(ctx, tx, proof, now)
}
func (s *Store) Refresh(ctx context.Context, b Binding, token, id, bodyHash string, proof identity.Proof, now time.Time) (Session, error) {
	var result Session
	if !idPattern.MatchString(id) {
		return result, identity.ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	a, current, e := s.lockSession(ctx, tx, b, proof, now.Unix(), true)
	if e != nil {
		return result, e
	}
	result, found, e := s.cached(ctx, tx, b.Owner, b.Jkt, "refresh", id, bodyHash, now.Unix())
	if e != nil {
		return result, e
	}
	if found {
		return result, tx.Commit()
	}
	var currentHash string
	if e = tx.QueryRowContext(ctx, `SELECT refresh_hash FROM identity_sessions WHERE id=$1`, b.Session).Scan(&currentHash); e != nil {
		return result, e
	}
	if currentHash != identity.Hash([]byte(token)) {
		_, e = tx.ExecContext(ctx, `UPDATE identity_sessions SET active=false WHERE id=$1`, b.Session)
		if e != nil {
			return result, e
		}
		if e = tx.Commit(); e != nil {
			return result, e
		}
		return result, ErrReuse
	}
	result = Session{b.Device, random(), random(), min(now.Unix()+600, a.Until) * 1000, current.RefreshUntil * 1000, current.Generation + 1, random()}
	_, e = tx.ExecContext(ctx, `UPDATE identity_sessions SET access_hash=$2,refresh_hash=$3,access_until=$4,generation=$5,nonce=$6 WHERE id=$1`, b.Session, identity.Hash([]byte(result.AccessToken)), identity.Hash([]byte(result.RefreshToken)), result.AccessUntilMs/1000, result.Generation, result.Nonce)
	if e != nil {
		return result, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO identity_refresh_history(hash,session,expires) VALUES($1,$2,$3)`, identity.Hash([]byte(result.RefreshToken)), b.Session, current.RefreshUntil)
	if e != nil {
		return result, e
	}
	if e = s.cache(ctx, tx, b.Owner, b.Jkt, "refresh", id, bodyHash, b.Session, result, now.Unix()); e != nil {
		return result, e
	}
	return result, tx.Commit()
}
func (s *Store) Publication(ctx context.Context, b Binding, token string, proof identity.Proof, now time.Time) (string, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	_, _, e = s.lockSession(ctx, tx, b, proof, now.Unix(), false)
	if e != nil {
		return "", e
	}
	var hash string
	if e = tx.QueryRowContext(ctx, `SELECT access_hash FROM identity_sessions WHERE id=$1`, b.Session).Scan(&hash); e != nil {
		return "", e
	}
	if hash != identity.Hash([]byte(token)) {
		return "", ErrDenied
	}
	var raw []byte
	var revision int64
	var problem string
	e = tx.QueryRowContext(ctx, `SELECT publication,revision,publication_error FROM identity_devices WHERE id=$1`, b.Device).Scan(&raw, &revision, &problem)
	if e != nil {
		return "", e
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	if raw == nil {
		if problem == "reauthentication_required" {
			return "", ErrReauth
		}
		return "", ErrPending
	}
	raw, e = s.Open(raw, "publication/v1/"+b.Device+"/"+formatInt(revision))
	if e != nil {
		return "", ErrUnavailable
	}
	return string(raw), nil
}
func (s *Store) Revoke(ctx context.Context, b Binding, token, id, bodyHash string, proof identity.Proof, now time.Time) error {
	if !idPattern.MatchString(id) {
		return identity.ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// Serialize duplicates with the original request. Only a matching, fresh key proof can read the receipt.
	var owner string
	if e = tx.QueryRowContext(ctx, `SELECT owner FROM identity_accounts WHERE owner=$1 FOR UPDATE`, b.Owner).Scan(&owner); e != nil {
		return e
	}
	var savedBody, savedAccess, savedKey, savedNonce string
	var expiry int64
	e = tx.QueryRowContext(ctx, `SELECT body_hash,access_hash,jkt,nonce,expires FROM identity_revocations WHERE device=$1 AND request_id=$2`, b.Device, id).Scan(&savedBody, &savedAccess, &savedKey, &savedNonce, &expiry)
	if e == nil {
		if savedBody != bodyHash || savedAccess != identity.Hash([]byte(token)) || savedKey != proof.Thumbprint || proof.Claims.Nonce != savedNonce || now.Unix() >= expiry || now.Unix() >= b.AccessUntil {
			return ErrConflict
		}
		if e = replay(ctx, tx, proof, now.Unix()); e != nil {
			return e
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, _, e = s.lockSession(ctx, tx, b, proof, now.Unix(), false)
	if e != nil {
		return e
	}
	var hash string
	if e = tx.QueryRowContext(ctx, `SELECT access_hash FROM identity_sessions WHERE id=$1`, b.Session).Scan(&hash); e != nil {
		return e
	}
	if hash != identity.Hash([]byte(token)) {
		return ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `UPDATE identity_devices SET active=false WHERE id=$1`, b.Device); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE identity_sessions SET active=false WHERE device=$1`, b.Device); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM identity_revocations WHERE expires<$1`, now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO identity_revocations(device,request_id,body_hash,access_hash,jkt,nonce,expires) VALUES($1,$2,$3,$4,$5,$6,$7)`, b.Device, id, bodyHash, hash, proof.Thumbprint, proof.Claims.Nonce, now.Unix()+180); e != nil {
		return e
	}
	return tx.Commit()
}

// Keeps the encryption AAD independent of locale and implicit SQL casts.
func formatInt(n int64) string { return strconv.FormatInt(n, 10) }
