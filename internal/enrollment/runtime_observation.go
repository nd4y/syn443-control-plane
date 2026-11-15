package enrollment

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const runtimeObservationPath = "/v1/device/runtime"
const maxRuntimeObservationBody = 1024

var ErrRuntimeObservationBudget = errors.New("runtime_observation_budget_exhausted")

// No identity, endpoint, free-form label or device clock is accepted here.
// The report is a client observation, not an independent traffic attestation.
type RuntimeObservation struct {
	Version        int    `json:"version"`
	Sequence       int64  `json:"sequence"`
	Build          int    `json:"build"`
	Phase          string `json:"phase"`
	PolicyRevision int64  `json:"policyRevision"`
	EngineKnown    bool   `json:"engineKnown"`
	EngineActive   bool   `json:"engineActive"`
	Network        string `json:"network"`
	SampledAtMs    int64  `json:"sampledAtMs"`
}

func (RuntimeObservation) String() string   { return "RuntimeObservation([redacted])" }
func (RuntimeObservation) GoString() string { return "RuntimeObservation([redacted])" }

func DecodeRuntimeObservation(raw []byte) (RuntimeObservation, error) {
	var r RuntimeObservation
	var fields map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > maxRuntimeObservationBody || identity.Decode(raw, &r, true) != nil ||
		json.Unmarshal(raw, &fields) != nil || len(fields) != 9 || r.Version != 1 ||
		r.Sequence < 1 || r.Sequence > 9007199254740991 || r.Build < 1 || r.Build > 2100000000 ||
		r.PolicyRevision < 0 || r.PolicyRevision > 9007199254740991 || r.SampledAtMs < 1 || r.SampledAtMs > 9007199254740991 {
		return RuntimeObservation{}, identity.ErrInvalid
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return RuntimeObservation{}, identity.ErrInvalid
		}
	}
	if !r.EngineKnown && r.EngineActive {
		return RuntimeObservation{}, identity.ErrInvalid
	}
	switch r.Phase {
	case "online":
		if !r.EngineKnown || !r.EngineActive || r.PolicyRevision == 0 {
			return RuntimeObservation{}, identity.ErrInvalid
		}
	case "off":
		if !r.EngineKnown || r.EngineActive {
			return RuntimeObservation{}, identity.ErrInvalid
		}
	case "starting", "recovering", "no_network", "blocked", "unknown":
	default:
		return RuntimeObservation{}, identity.ErrInvalid
	}
	switch r.Network {
	case "none", "wifi", "cellular", "unknown":
	default:
		return RuntimeObservation{}, identity.ErrInvalid
	}
	return r, nil
}

func (s *Store) RecordRuntimeObservation(ctx context.Context, binding Binding, token string, proof identity.Proof, raw []byte, now time.Time) error {
	report, e := DecodeRuntimeObservation(raw)
	if e != nil {
		return e
	}
	started := time.Now()
	current := func() int64 { return now.Add(time.Since(started)).UnixMilli() }
	hash := identity.Hash(raw)
	_, e = s.WithDeviceSession(ctx, binding, token, proof, now, func(ctx context.Context, tx *sql.Tx, authority DeviceAuthority) (DeviceResult, error) {
		var approved bool
		var revision, offline int64
		var grant string
		if e := tx.QueryRowContext(ctx, `SELECT approved,revision,offline_until,publication_grant_hash FROM identity_devices WHERE id=$1`, authority.Binding.Device).Scan(&approved, &revision, &offline, &grant); e != nil {
			return DeviceResult{}, ErrUnavailable
		}
		if !approved || report.PolicyRevision > revision || report.EngineActive && (report.PolicyRevision == 0 || offline <= now.Unix() || grant != authority.GrantHash) {
			return DeviceResult{}, ErrDenied
		}
		result := DeviceResult{UntilMs: authority.AccountUntilMs}
		if report.EngineActive {
			result.UntilMs = min(result.UntilMs, offline*1000)
		}
		var sequence, received int64
		var priorHash, priorKey string
		e := tx.QueryRowContext(ctx, `SELECT sequence,report_hash,key_thumbprint,received_at_ms FROM identity_runtime_observations WHERE device=$1 FOR UPDATE`, authority.Binding.Device).Scan(&sequence, &priorHash, &priorKey, &received)
		if e == nil {
			if priorKey == authority.Binding.Jkt {
				if sequence == report.Sequence && hash == priorHash {
					return result, nil // An acknowledgement is not a new observation.
				}
				if report.Sequence <= sequence {
					return DeviceResult{}, ErrConflict
				}
			}
			if current() < received || current()-received < 30_000 {
				return DeviceResult{}, ErrRuntimeObservationBudget
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return DeviceResult{}, ErrUnavailable
		}
		// Old exact acknowledgements above never renew freshness. A new sample
		// must still be recent after all authorization/observation lock waits.
		if report.SampledAtMs > current()+30_000 || report.SampledAtMs < current()-120_000 {
			return DeviceResult{}, ErrConflict
		}
		result.UntilMs = min(result.UntilMs, report.SampledAtMs+180_000)
		_, e = tx.ExecContext(ctx, `INSERT INTO identity_runtime_observations(device,key_thumbprint,sequence,report_hash,build,phase,policy_revision,engine_known,engine_active,network,sampled_at_ms,received_at_ms)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(device) DO UPDATE SET key_thumbprint=EXCLUDED.key_thumbprint,sequence=EXCLUDED.sequence,report_hash=EXCLUDED.report_hash,
		 build=EXCLUDED.build,phase=EXCLUDED.phase,policy_revision=EXCLUDED.policy_revision,engine_known=EXCLUDED.engine_known,engine_active=EXCLUDED.engine_active,network=EXCLUDED.network,sampled_at_ms=EXCLUDED.sampled_at_ms,received_at_ms=EXCLUDED.received_at_ms`,
			authority.Binding.Device, authority.Binding.Jkt, report.Sequence, hash, report.Build, report.Phase, report.PolicyRevision, report.EngineKnown, report.EngineActive, report.Network, report.SampledAtMs, current())
		if e != nil {
			return DeviceResult{}, ErrUnavailable
		}
		if report.SampledAtMs < current()-120_000 {
			return DeviceResult{}, ErrConflict
		}
		return result, nil
	})
	return e
}
