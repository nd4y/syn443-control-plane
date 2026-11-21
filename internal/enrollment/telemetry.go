package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

const telemetryPath = "/v1/device/telemetry"
const telemetryConnections = 2

func serveTelemetry(w http.ResponseWriter, r *http.Request, store *Store, origin string, clock func() time.Time, admission *requestAdmission) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost || r.URL.Path != telemetryPath || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" {
		http.NotFound(w, r)
		return
	}
	if !admission.acquire(w, r, clock(), "5") {
		return
	}
	defer func() { <-admission.slots }()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	now, err := store.Now(ctx, clock())
	if err != nil {
		failure(w, ErrUnavailable)
		return
	}
	w.Header().Set("Date", now.Format(http.TimeFormat))
	token, err := requestToken(r)
	if err != nil || r.Header.Get("Origin") != "" || r.Header.Get("Content-Type") != "application/json" {
		failure(w, identity.ErrInvalid)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, telemetry.MaxBatchBytes+1))
	defer clear(raw)
	if err != nil || len(raw) > telemetry.MaxBatchBytes {
		failure(w, identity.ErrInvalid)
		return
	}
	proof, err := boundRequestProof(r, origin+telemetryPath, token, raw, now)
	if err != nil {
		failure(w, err)
		return
	}
	binding, err := store.Lookup(ctx, token, false)
	if err != nil {
		failure(w, err)
		return
	}
	if !binding.Active || binding.Jkt != proof.Thumbprint {
		failure(w, ErrDenied)
		return
	}
	receipt, err := store.receiveTelemetry(ctx, binding, token, proof, raw, now)
	if errors.Is(err, telemetry.ErrBudget) {
		w.Header().Set("Retry-After", "300")
		http.Error(w, "telemetry_budget_exhausted", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}

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
