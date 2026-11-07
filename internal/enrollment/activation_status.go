package enrollment

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

// ActivationReport is a device observation about one exact signed publication.
// It does not change the desired configuration or authorize any new operation.
type ActivationReport struct {
	Version              int    `json:"version"`
	PolicyRevision       int64  `json:"policyRevision"`
	EnvelopeHash         string `json:"envelopeHash"`
	ActivationGeneration int64  `json:"activationGeneration"`
	Outcome              string `json:"outcome"`
	ActivePolicyRevision int64  `json:"activePolicyRevision"`
}

const activationStatusPath = "/v1/device/policy/status"
const maxActivationReportBody = 1024

func decodeActivationReport(raw []byte) (ActivationReport, error) {
	var r ActivationReport
	if len(raw) == 0 || len(raw) > maxActivationReportBody || identity.Decode(raw, &r, true) != nil ||
		r.Version != 1 || r.PolicyRevision < 1 || r.PolicyRevision > 9007199254740991 ||
		r.ActivationGeneration < 1 || r.ActivationGeneration > 9007199254740991 || !overlayDigest(r.EnvelopeHash) {
		return ActivationReport{}, identity.ErrInvalid
	}
	switch r.Outcome {
	case "committed", "degraded":
		if r.ActivePolicyRevision != r.PolicyRevision {
			return ActivationReport{}, identity.ErrInvalid
		}
	case "rolled_back":
		if r.ActivePolicyRevision < 0 || r.ActivePolicyRevision >= r.PolicyRevision {
			return ActivationReport{}, identity.ErrInvalid
		}
	default:
		return ActivationReport{}, identity.ErrInvalid
	}
	return r, nil
}

func (s *Store) RecordActivation(ctx context.Context, binding Binding, token string, proof identity.Proof,
	raw []byte, roots map[string]*ecdsa.PublicKey, now time.Time) error {
	report, e := decodeActivationReport(raw)
	if e != nil {
		return e
	}
	_, e = s.WithDeviceSession(ctx, binding, token, proof, now, func(ctx context.Context, tx *sql.Tx, authority DeviceAuthority) (DeviceResult, error) {
		var body []byte
		var revision int64
		var grant string
		var approved bool
		device := authority.Binding.Device
		e := tx.QueryRowContext(ctx, `SELECT publication,revision,publication_grant_hash,approved FROM identity_devices WHERE id=$1`, device).Scan(&body, &revision, &grant, &approved)
		if e != nil || len(body) == 0 || !approved || grant != authority.GrantHash {
			return DeviceResult{}, ErrDenied
		}
		if revision != report.PolicyRevision {
			return DeviceResult{}, ErrConflict
		}
		envelope, e := s.Open(body, "publication/v1/"+device+"/"+formatInt(revision))
		if e != nil {
			return DeviceResult{}, ErrUnavailable
		}
		if identity.Hash(envelope) != report.EnvelopeHash {
			return DeviceResult{}, ErrConflict
		}
		published, e := policy.VerifyBound(string(envelope), roots, device, authority.Binding.Jkt, now)
		if e != nil || published.Operation != "configure" || published.Revision != revision {
			return DeviceResult{}, ErrDenied
		}
		result := DeviceResult{UntilMs: min(authority.AccountUntilMs, published.OfflineUntilMs)}
		var prior ActivationReport
		e = tx.QueryRowContext(ctx, `SELECT policy_revision,envelope_hash,activation_generation,outcome,active_policy_revision FROM identity_policy_activation WHERE device=$1`, device).Scan(
			&prior.PolicyRevision, &prior.EnvelopeHash, &prior.ActivationGeneration, &prior.Outcome, &prior.ActivePolicyRevision)
		if e == nil {
			prior.Version = 1
			if prior == report {
				return result, nil
			}
			if prior.PolicyRevision >= report.PolicyRevision {
				return DeviceResult{}, ErrConflict
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return DeviceResult{}, ErrUnavailable
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO identity_policy_activation(device,policy_revision,envelope_hash,activation_generation,outcome,active_policy_revision,received_at_ms)
		 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(device) DO UPDATE SET policy_revision=EXCLUDED.policy_revision,envelope_hash=EXCLUDED.envelope_hash,
		 activation_generation=EXCLUDED.activation_generation,outcome=EXCLUDED.outcome,active_policy_revision=EXCLUDED.active_policy_revision,received_at_ms=EXCLUDED.received_at_ms`,
			device, revision, report.EnvelopeHash, report.ActivationGeneration, report.Outcome, report.ActivePolicyRevision, now.UnixMilli())
		if e != nil {
			return DeviceResult{}, ErrUnavailable
		}
		return result, nil
	})
	return e
}
