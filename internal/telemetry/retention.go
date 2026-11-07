package telemetry

import (
	"context"
	"database/sql"
	"time"
)

const DetailRetention = 14 * 24 * time.Hour

type Pruned struct{ Events, Windows int64 }

func CheckRetentionRole(ctx context.Context, db *sql.DB) error {
	var scoped bool
	err := db.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'public.identity_telemetry_events','DELETE')
 AND has_column_privilege(current_user,'public.identity_telemetry_events','received_at_ms','SELECT')
 AND NOT has_column_privilege(current_user,'public.identity_telemetry_events','code','SELECT')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_events','INSERT')
 AND has_table_privilege(current_user,'public.identity_telemetry_windows','DELETE')
 AND NOT has_any_column_privilege(current_user,'public.identity_devices','SELECT')`).Scan(&scoped)
	if err != nil || !scoped {
		return ErrUnavailable
	}
	return nil
}

// Prune removes one bounded batch of expired data. New events and other
// application tables are not affected.
func Prune(ctx context.Context, db *sql.DB, now time.Time) (Pruned, error) {
	var out Pruned
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return out, ErrUnavailable
	}
	defer tx.Rollback()
	events, err := tx.ExecContext(ctx, `WITH expired AS (
 SELECT device,event_id FROM identity_telemetry_events WHERE received_at_ms<$1 ORDER BY received_at_ms LIMIT 1024)
 DELETE FROM identity_telemetry_events e USING expired x WHERE e.device=x.device AND e.event_id=x.event_id`, now.Add(-DetailRetention).UnixMilli())
	if err != nil {
		return out, ErrUnavailable
	}
	windows, err := tx.ExecContext(ctx, `WITH expired AS (
 SELECT device,period FROM identity_telemetry_windows WHERE period<$1 ORDER BY period LIMIT 1024)
 DELETE FROM identity_telemetry_windows w USING expired x WHERE w.device=x.device AND w.period=x.period`, now.Add(-48*time.Hour).Unix())
	if err != nil {
		return out, ErrUnavailable
	}
	out.Events, _ = events.RowsAffected()
	out.Windows, _ = windows.RowsAffected()
	if err = tx.Commit(); err != nil {
		return Pruned{}, ErrUnavailable
	}
	return out, nil
}
