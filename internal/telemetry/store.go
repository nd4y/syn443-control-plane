package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const EventsPerDeviceHour = 256

var ErrBudget = errors.New("telemetry_budget_exhausted")
var ErrUnavailable = errors.New("telemetry_unavailable")

func CheckIngestionRole(ctx context.Context, db *sql.DB) error {
	var scoped bool
	err := db.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'public.identity_telemetry_events','INSERT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_events','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_events','UPDATE')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_events','DELETE')
 AND has_column_privilege(current_user,'public.identity_telemetry_windows','used','UPDATE')`).Scan(&scoped)
	if err != nil || !scoped {
		return ErrUnavailable
	}
	return nil
}

// InsertBound accepts only the device identifier from an already locked and
// authenticated enrollment transaction. A batch or event never supplies it.
func InsertBound(ctx context.Context, tx *sql.Tx, device string, batch Batch, now time.Time) error {
	if tx == nil || !opaque.MatchString(device) || batch.Validate(now) != nil {
		return ErrInvalid
	}
	encoded, err := json.Marshal(batch.Events)
	if err != nil || len(encoded) > MaxBatchBytes {
		return ErrInvalid
	}
	defer clear(encoded)
	period := now.UTC().Truncate(time.Hour).Unix()
	var used int
	err = tx.QueryRowContext(ctx, `INSERT INTO identity_telemetry_windows(device,period,used) VALUES($1,$2,$3)
 ON CONFLICT (device,period) DO UPDATE SET used=identity_telemetry_windows.used+EXCLUDED.used
 WHERE identity_telemetry_windows.used+EXCLUDED.used<=$4 RETURNING used`,
		device, period, len(batch.Events), EventsPerDeviceHour).Scan(&used)
	if err == sql.ErrNoRows {
		return ErrBudget
	}
	if err != nil {
		return ErrUnavailable
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_telemetry_events(device,event_id,session_id,build,policy_revision,algorithm_revision,
 received_at_ms,observed_at_ms,elapsed_ms,network_epoch,kind,code,mode,path_id,duration_ms)
 SELECT $1,e.id,$2,$3,$4,$5,$6,e."atMs",e."elapsedMs",e."networkEpoch",e.kind,e.code,e.mode,e.path,e."durationMs"
 FROM jsonb_to_recordset($7::jsonb) AS e(id text,"atMs" bigint,"elapsedMs" bigint,"networkEpoch" bigint,
 kind text,code text,mode text,path text,"durationMs" integer)
 ON CONFLICT DO NOTHING`, device, batch.Session, batch.Build, batch.PolicyRevision, batch.AlgorithmRevision,
		now.UnixMilli(), string(encoded))
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
