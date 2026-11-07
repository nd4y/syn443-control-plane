package invitation

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"time"
)

type Completion struct {
	Session  enrollment.Session `json:"session"`
	OwnerTag string             `json:"ownerTag"`
}

func (Completion) String() string   { return "InvitationCompletion([redacted])" }
func (Completion) GoString() string { return "InvitationCompletion([redacted])" }

type DeviceService struct {
	Store             *Store
	Identity          *enrollment.Store
	Origin, ServiceID string
}

func (s *DeviceService) Dispatch(ctx context.Context, path string, raw []byte, proof string, now time.Time) (any, error) {
	if s.Store == nil {
		return nil, enrollment.ErrUnavailable
	}
	if e := s.Store.Expire(ctx); e != nil {
		return nil, enrollment.ErrUnavailable
	}
	var value any
	var e error
	switch path {
	case "/v1/invitations/time":
		value = struct {
			ServiceID string `json:"serviceId"`
		}{s.ServiceID}
	case "/v1/invitations/claim":
		value, e = s.Store.Claim(ctx, s.ServiceID, s.Origin, raw, proof, now)
	case "/v1/invitations/status":
		value, e = s.Store.Status(ctx, s.Origin, raw, proof, now)
	case "/v1/invitations/complete":
		var session enrollment.Session
		session, e = s.Store.Complete(ctx, s.Identity, s.Origin, raw, proof, now)
		if e == nil {
			var issuer, subject, service string
			e = s.Store.DB.QueryRowContext(ctx, `SELECT a.issuer,a.subject,i.service_id FROM managed_invitations i JOIN identity_accounts a ON a.owner=i.owner WHERE i.device=$1 AND i.final_session IS NOT NULL`, session.DeviceID).Scan(&issuer, &subject, &service)
			if e == nil {
				tag, _ := json.Marshal(map[string]string{"service": service, "issuer": issuer, "subject": subject})
				canonical, err := policy.Canonical(tag)
				if err != nil {
					e = ErrUnavailable
				} else {
					value = Completion{session, identity.Hash(canonical)}
				}
			} else {
				e = ErrUnavailable
			}
		}
	case "/v1/invitations/abandon":
		e = s.Store.Abandon(ctx, s.Origin, raw, proof, now)
		value = struct {
			Revoked bool `json:"revoked"`
		}{true}
	default:
		return nil, enrollment.ErrDenied
	}
	switch {
	case errors.Is(e, ErrDenied), errors.Is(e, ErrExpired):
		e = enrollment.ErrDenied
	case errors.Is(e, ErrConflict):
		e = enrollment.ErrConflict
	case errors.Is(e, ErrPending):
		e = enrollment.ErrPending
	case errors.Is(e, ErrUnavailable):
		e = enrollment.ErrUnavailable
	}
	return value, e
}
