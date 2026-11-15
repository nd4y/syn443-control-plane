package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

type RuntimeObservationView struct {
	enrollment.RuntimeObservation
	ReceivedAtMs int64 `json:"receivedAtMs"`
}

type ConfigurationRuntimeObservation struct {
	Device       string                  `json:"device"`
	ObservedAtMs int64                   `json:"observedAtMs"`
	State        string                  `json:"state"`
	Report       *RuntimeObservationView `json:"report,omitempty"`
}

func (ConfigurationRuntimeObservation) String() string {
	return "ConfigurationRuntimeObservation([redacted])"
}
func (ConfigurationRuntimeObservation) GoString() string {
	return "ConfigurationRuntimeObservation([redacted])"
}

func (c *ConfigurationControl) runtimeObservation(ctx context.Context, actor, device, request string, until int64, now time.Time) (ConfigurationRuntimeObservation, error) {
	result := ConfigurationRuntimeObservation{Device: device, State: "none"}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	var grantUntil int64
	e = tx.QueryRowContext(ctx, `SELECT expires FROM catalog_acl WHERE actor=$1 AND action IN ('configuration.drafts.read','*') AND target_kind IN ('device','*') AND target_id IN ($2,'*') AND expires>$3 ORDER BY expires DESC LIMIT 1 FOR SHARE`, actor, device, current().Unix()).Scan(&grantUntil)
	if e == sql.ErrNoRows {
		return result, enrollment.ErrDenied
	}
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	var key string
	var active, approved, enabled bool
	var accountUntil, issuedRevision int64
	e = tx.QueryRowContext(ctx, `SELECT d.jkt,d.active,d.approved,a.enabled,a.valid_until,d.revision FROM identity_devices d JOIN identity_accounts a ON a.owner=d.owner WHERE d.id=$1 FOR SHARE OF d,a`, device).Scan(&key, &active, &approved, &enabled, &accountUntil, &issuedRevision)
	if e == sql.ErrNoRows || e == nil && (!active || !approved || !enabled || current().Unix() >= min(until, accountUntil)) {
		return result, enrollment.ErrDenied
	}
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	var report RuntimeObservationView
	var reportKey string
	report.Version = 1
	e = tx.QueryRowContext(ctx, `SELECT key_thumbprint,sequence,build,phase,policy_revision,engine_known,engine_active,network,sampled_at_ms,received_at_ms FROM identity_runtime_observations WHERE device=$1`, device).Scan(&reportKey, &report.Sequence, &report.Build, &report.Phase, &report.PolicyRevision, &report.EngineKnown, &report.EngineActive, &report.Network, &report.SampledAtMs, &report.ReceivedAtMs)
	if e != nil && e != sql.ErrNoRows {
		return result, enrollment.ErrUnavailable
	}
	if e == nil && reportKey == key {
		raw, err := json.Marshal(report.RuntimeObservation)
		if err != nil {
			return result, enrollment.ErrUnavailable
		}
		if _, err = enrollment.DecodeRuntimeObservation(raw); err != nil || report.PolicyRevision > issuedRevision || report.ReceivedAtMs <= 0 || report.ReceivedAtMs > current().UnixMilli() || report.SampledAtMs < report.ReceivedAtMs-120_000 || report.SampledAtMs > report.ReceivedAtMs+30_000 {
			return result, enrollment.ErrUnavailable
		}
		result.Report = &report
	}
	if e = layerACL(ctx, tx, actor, "configuration.drafts.read", "device", device, current().Unix()); e != nil {
		return result, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO catalog_audit(actor,action,target,request_id,observed_at,before_hash,after_hash,outcome) VALUES($1,'configuration.runtime.get',$2,$3,$4,'','','read')`, actor, device, request, current().Unix()); e != nil {
		return result, enrollment.ErrUnavailable
	}
	if current().Unix() >= min(until, accountUntil, grantUntil) {
		return result, enrollment.ErrDenied
	}
	result.ObservedAtMs = current().UnixMilli()
	if result.Report != nil {
		result.State = "stale"
		if result.ObservedAtMs < min(report.ReceivedAtMs, report.SampledAtMs)+180_000 {
			result.State = "recent"
		}
	}
	if e = tx.Commit(); e != nil {
		return ConfigurationRuntimeObservation{}, enrollment.ErrUnavailable
	}
	return result, nil
}
