package enrollment

import (
	"context"
	"database/sql"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

const telemetryPath = "/v1/device/telemetry"

func (a *API) receiveTelemetry(ctx context.Context, binding Binding, token string, proof identity.Proof, raw []byte, now time.Time) error {
	batch, err := telemetry.Decode(raw, now)
	if err != nil {
		return identity.ErrInvalid
	}
	_, err = a.Store.WithDeviceSession(ctx, binding, token, proof, now, func(ctx context.Context, tx *sql.Tx, authority DeviceAuthority) (DeviceResult, error) {
		if err := telemetry.InsertBound(ctx, tx, authority.Binding.Device, batch, now); err != nil {
			return DeviceResult{}, err
		}
		deadline := min(authority.AccountUntilMs, authority.Binding.AccessUntil*1000, now.Add(time.Minute).UnixMilli())
		return DeviceResult{Value: true, UntilMs: deadline}, nil
	})
	return err
}
