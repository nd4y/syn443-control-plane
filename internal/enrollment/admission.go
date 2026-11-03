package enrollment

import (
	"context"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Only publish() calls this after independent verification of the original
// OIDC/invitation receipt, device-key proof, live owner grant and capabilities.
// It freezes trusted identity, but produces no signed policy, offline lease,
// overlay reservation or native configuration. The API cannot call an approve
// endpoint or write the approved column itself.
func (p *Publisher) admitIdentity(ctx context.Context, s snapshot, g Grant, fence ApprovalFence, authorityUntil int64, now time.Time) error {
	if ctx == nil || p == nil || p.Store == nil || s.Approved || s.Revision != 0 || authorityUntil <= now.Unix() {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	if e := p.Store.RuntimeRole(ctx, true); e != nil {
		return e
	}
	tx, e := p.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := lockAccount(ctx, tx, s.Owner, current().Unix())
	if e != nil {
		return e
	}
	if a.Grant != s.Grant || g.Hash() != s.Grant || g.Validate(current()) != nil {
		return ErrConflict
	}
	var owner, jkt string
	var raw, receipt, publication []byte
	var revision int64
	var active, approved bool
	e = tx.QueryRowContext(ctx, `SELECT owner,jkt,request_body,receipt,revision,active,approved,publication FROM identity_devices WHERE id=$1 FOR UPDATE`, s.Device).Scan(&owner, &jkt, &raw, &receipt, &revision, &active, &approved, &publication)
	if e != nil {
		return e
	}
	if !active || owner != s.Owner || jkt != s.Jkt || revision != 0 || len(publication) != 0 || identity.Hash(raw) != identity.Hash(s.Raw) || identity.Hash(receipt) != identity.Hash(s.Receipt) {
		return ErrConflict
	}
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE owner=$1 AND active`, s.Owner).Scan(&count); e != nil {
		return e
	}
	if count > g.DeviceLimit {
		return ErrDenied
	}
	if fence != nil {
		if e = fence.Lock(ctx, tx, current()); e != nil {
			return e
		}
	}
	if current().Unix() >= min(authorityUntil, a.Until) {
		return ErrDenied
	}
	if !approved {
		if _, e = tx.ExecContext(ctx, `UPDATE identity_devices SET approved=true,publication_error='configuration_pending',retry_after=0,refresh_after=$2 WHERE id=$1`, s.Device, current().Unix()+30); e != nil {
			return e
		}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if current().Unix() >= min(authorityUntil, a.Until) {
		return ErrDenied
	}
	return tx.Commit()
}
