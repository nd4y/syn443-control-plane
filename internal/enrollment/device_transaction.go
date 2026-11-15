package enrollment

import (
	"context"
	"database/sql"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// DeviceAuthority is produced only under account/device/session row locks.
// A callback may perform bounded SQL/cryptographic work, never network or SDK
// effects. Its result is withheld until the transaction has committed.
type DeviceAuthority struct {
	Binding         Binding
	Issuer, Subject string
	GrantHash       string
	AccountUntilMs  int64
}

func (DeviceAuthority) String() string   { return "DeviceAuthority([redacted])" }
func (DeviceAuthority) GoString() string { return "DeviceAuthority([redacted])" }

type DeviceResult struct {
	Value any
	// A result must carry a finite permission deadline. Row-lock waits and
	// callback work cannot extend a session, account or signed-policy lease.
	UntilMs int64
}

func (s *Store) WithDeviceSession(ctx context.Context, b Binding, token string, proof identity.Proof, now time.Time,
	operation func(context.Context, *sql.Tx, DeviceAuthority) (DeviceResult, error)) (any, error) {
	started := time.Now()
	if operation == nil || len(token) < 24 || len(token) > 128 {
		return nil, identity.ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, current, e := s.lockSession(ctx, tx, b, proof, now.Unix(), false)
	if e != nil {
		return nil, e
	}
	var hash, issuer, subject string
	if e = tx.QueryRowContext(ctx, `SELECT access_hash FROM identity_sessions WHERE id=$1`, current.Session).Scan(&hash); e != nil {
		return nil, e
	}
	if hash != identity.Hash([]byte(token)) {
		return nil, ErrDenied
	}
	if e = tx.QueryRowContext(ctx, `SELECT issuer,subject FROM identity_accounts WHERE owner=$1`, current.Owner).Scan(&issuer, &subject); e != nil {
		return nil, e
	}
	result, e := operation(ctx, tx, DeviceAuthority{Binding: current, Issuer: issuer, Subject: subject, GrantHash: a.Grant, AccountUntilMs: a.Until * 1000})
	if e != nil {
		return nil, e
	}
	final := now.Add(time.Since(started)).UnixMilli()
	if result.UntilMs <= final || a.Until*1000 <= final || current.AccessUntil*1000 <= final || current.RefreshUntil*1000 <= final {
		return nil, ErrDenied
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return result.Value, nil
}
