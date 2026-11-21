package enrollment

import (
	"context"
	"database/sql"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

const telemetryPath = "/v1/device/telemetry"
const telemetryConnections = 2

// The pool uses the enrollment session role so replay and account revocation
// stay in the same transaction as the event insert.
func OpenTelemetryStore(ctx context.Context, config Config) (*Store, error) {
	store, err := OpenStore(config)
	if err != nil {
		return nil, err
	}
	store.DB.SetMaxOpenConns(telemetryConnections)
	if err = telemetry.CheckIngestionRole(ctx, store.DB); err != nil {
		store.DB.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) receiveTelemetry(ctx context.Context, binding Binding, token string, proof identity.Proof, raw []byte, now time.Time) (telemetry.Receipt, error) {
	batch, err := telemetry.Decode(raw, now)
	if err != nil {
		return telemetry.Receipt{}, identity.ErrInvalid
	}
	_, err = s.WithDeviceSession(ctx, binding, token, proof, now, func(ctx context.Context, tx *sql.Tx, authority DeviceAuthority) (DeviceResult, error) {
		if err := telemetry.InsertBound(ctx, tx, authority.Binding.Device, batch, now); err != nil {
			return DeviceResult{}, err
		}
		deadline := min(authority.AccountUntilMs, authority.Binding.AccessUntil*1000, now.Add(time.Minute).UnixMilli())
		return DeviceResult{Value: true, UntilMs: deadline}, nil
	})
	if err != nil {
		return telemetry.Receipt{}, err
	}
	return batch.Receipt(), nil
}
