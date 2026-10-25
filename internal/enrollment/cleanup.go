package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Cleanup contains only public thumbprints. A logged-out client need not retain a private
// key, user/device credential or provider configuration to retry cleanup after a fresh login.
type Cleanup struct {
	RequestID   string   `json:"requestId"`
	Thumbprints []string `json:"thumbprints"`
}

func challenge(ctx context.Context, tx *sql.Tx, owner, jkt, present string, now int64) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM identity_challenges WHERE expires<=$1`, now); e != nil {
		return e
	}
	var nonce string
	var expires int64
	e := tx.QueryRowContext(ctx, `SELECT nonce,expires FROM identity_challenges WHERE owner=$1 AND jkt=$2`, owner, jkt).Scan(&nonce, &expires)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil && expires > now && present == nonce {
		return nil
	}
	if errors.Is(e, sql.ErrNoRows) {
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_challenges WHERE owner=$1`, owner).Scan(&count); e != nil {
			return e
		}
		if count >= 32 {
			return ErrUnavailable
		}
	}
	nonce = random()
	if _, e = tx.ExecContext(ctx, `INSERT INTO identity_challenges(owner,jkt,nonce,expires) VALUES($1,$2,$3,$4) ON CONFLICT(owner,jkt) DO UPDATE SET nonce=excluded.nonce,expires=excluded.expires`, owner, jkt, nonce, now+180); e != nil {
		return e
	}
	return NonceRequired{nonce}
}

func (s *Store) Cleanup(ctx context.Context, principal identity.Principal, proof identity.Proof, raw []byte, now time.Time) error {
	var request Cleanup
	if identity.Decode(raw, &request, true) != nil || !idPattern.MatchString(request.RequestID) || len(request.Thumbprints) < 1 || len(request.Thumbprints) > 16 {
		return identity.ErrInvalid
	}
	seen := map[string]bool{}
	for _, thumb := range request.Thumbprints {
		if len(thumb) != 43 || !idPattern.MatchString(thumb) || seen[thumb] {
			return identity.ErrInvalid
		}
		seen[thumb] = true
	}
	if principal.Thumbprint != proof.Thumbprint || proof.Claims.RequestHash != identity.Hash(raw) {
		return ErrDenied
	}
	owner := Owner(principal.Issuer, principal.Subject)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var known string
	if e = tx.QueryRowContext(ctx, `SELECT owner FROM identity_accounts WHERE owner=$1 FOR UPDATE`, owner).Scan(&known); errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	} else if e != nil {
		return e
	}
	// Denied/expired accounts may still revoke their own devices. This path grants no session or config.
	if e = challenge(ctx, tx, owner, proof.Thumbprint, proof.Claims.Nonce, now.Unix()); e != nil {
		var nonce NonceRequired
		if errors.As(e, &nonce) {
			if err := tx.Commit(); err != nil {
				return err
			}
		}
		return e
	}
	if e = replay(ctx, tx, proof, now.Unix()); e != nil {
		return e
	}
	var saved string
	var until int64
	e = tx.QueryRowContext(ctx, `SELECT body_hash,expires FROM identity_owner_revocations WHERE owner=$1 AND auth_jkt=$2 AND request_id=$3`, owner, proof.Thumbprint, request.RequestID).Scan(&saved, &until)
	if e == nil {
		if saved != identity.Hash(raw) || until <= now.Unix() {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	for _, thumb := range request.Thumbprints {
		var device string
		e = tx.QueryRowContext(ctx, `UPDATE identity_devices SET active=false WHERE owner=$1 AND jkt=$2 RETURNING id`, owner, thumb).Scan(&device)
		if errors.Is(e, sql.ErrNoRows) {
			continue
		}
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE identity_sessions SET active=false WHERE device=$1`, device); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM identity_owner_revocations WHERE expires<$1`, now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO identity_owner_revocations(owner,auth_jkt,request_id,body_hash,expires) VALUES($1,$2,$3,$4,$5)`, owner, proof.Thumbprint, request.RequestID, identity.Hash(raw), now.Unix()+180); e != nil {
		return e
	}
	return tx.Commit()
}
