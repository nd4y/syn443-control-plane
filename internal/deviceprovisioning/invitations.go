// Package deviceprovisioning connects verified invitation consent to the same
// identity device/publisher pipeline as OIDC. It never issues device sessions.
package deviceprovisioning

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

type Invitations struct {
	Identity     *enrollment.Store
	Invitations  *invitation.Store
	Verification invitation.Verification
	Grants       map[string]enrollment.Grant
}

func (i *Invitations) Prepare(ctx context.Context, now time.Time) error {
	if i.Identity == nil || i.Invitations == nil {
		return invitation.ErrUnavailable
	}
	tickets, e := i.Invitations.Pending(ctx, now)
	if e != nil {
		return e
	}
	for _, ticket := range tickets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		code := "authorization_changed"
		p, e := i.Invitations.Ready(ctx, ticket.ID, i.Verification, now)
		if e == nil {
			g, exists := i.Grants[p.Owner]
			if exists && g.Hash() == p.GrantHash && g.Validate(now) == nil {
				var request enrollment.Request
				if identity.Decode(p.Enrollment, &request, true) == nil {
					caps := map[string]bool{}
					for _, capability := range request.Capabilities {
						caps[capability] = true
					}
					supported := true
					for _, required := range g.Template.RequiredCapabilities {
						if !caps[required] {
							supported = false
						}
					}
					code = "unsupported_capabilities"
					if supported {
						e = i.createDevice(ctx, p, g, now)
						if e == nil {
							continue
						}
						code = "temporarily_unavailable"
					}
				}
			}
		}
		if e = i.Invitations.PublicationFailure(ctx, ticket, code, now); e != nil {
			return e
		}
	}
	return nil
}
func (i *Invitations) createDevice(ctx context.Context, p invitation.Publication, g enrollment.Grant, now time.Time) error {
	tx, e := i.Identity.DB.BeginTx(ctx, nil)
	if e != nil {
		return invitation.ErrUnavailable
	}
	defer tx.Rollback()
	if e = i.Invitations.LockPublication(ctx, tx, p, now); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE owner=$1 AND active`, p.Owner).Scan(&count); e != nil {
		return invitation.ErrUnavailable
	}
	if count >= g.DeviceLimit {
		return invitation.ErrDenied
	}
	var existing int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE jkt=$1`, p.Thumbprint).Scan(&existing); e != nil {
		return invitation.ErrUnavailable
	}
	if existing != 0 {
		return invitation.ErrDenied
	}
	randomID := make([]byte, 32)
	if _, e = rand.Read(randomID); e != nil {
		return invitation.ErrUnavailable
	}
	device := base64.RawURLEncoding.EncodeToString(randomID)
	receipt, _ := json.Marshal(enrollment.Receipt{Kind: "invite-v1", InvitationID: p.ID, AcceptedAt: now.Unix()})
	protected := i.Identity.Seal(receipt, "receipt/v1/"+device)
	if _, e = tx.ExecContext(ctx, `INSERT INTO identity_devices(id,owner,jkt,request_body,receipt) VALUES($1,$2,$3,$4,$5)`, device, p.Owner, p.Thumbprint, p.Enrollment, protected); e != nil {
		return invitation.ErrUnavailable
	}
	if e = i.Invitations.BindDevice(ctx, tx, p, device, now); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return invitation.ErrUnavailable
	}
	return nil
}
func (i *Invitations) Verify(ctx context.Context, input enrollment.ApprovalInput, now time.Time) (enrollment.ApprovalFence, error) {
	if i.Invitations == nil {
		return nil, identity.ErrInvalid
	}
	p, e := i.Invitations.Ready(ctx, input.InvitationID, i.Verification, now)
	if e != nil || p.Device != input.Device || p.Owner != input.Owner || p.Thumbprint != input.Thumbprint || p.GrantHash != input.GrantHash || identity.Hash(p.Enrollment) != identity.Hash(input.Request) {
		return nil, identity.ErrInvalid
	}
	return &fence{i.Invitations, p}, nil
}

type fence struct {
	store       *invitation.Store
	publication invitation.Publication
}

func (f *fence) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	return f.store.LockPublication(ctx, tx, f.publication, now)
}
