package invitation

import (
	"context"
	"errors"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"time"
)

type DeviceService struct {
	Store             *Store
	Identity          *enrollment.Store
	Origin, ServiceID string
}

func (s *DeviceService) Dispatch(ctx context.Context, path string, raw []byte, proof string, now time.Time) (any, error) {
	if s.Store == nil {
		return nil, enrollment.ErrUnavailable
	}
	var value any
	var e error
	switch path {
	case "/v1/invitations/claim":
		value, e = s.Store.Claim(ctx, s.ServiceID, s.Origin, raw, proof, now)
	case "/v1/invitations/status":
		value, e = s.Store.Status(ctx, s.Origin, raw, proof, now)
	case "/v1/invitations/complete":
		value, e = s.Store.Complete(ctx, s.Identity, s.Origin, raw, proof, now)
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
