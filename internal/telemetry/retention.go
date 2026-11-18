package telemetry

import (
	"context"
	"database/sql"
	"time"
)

const DetailRetention = 14 * 24 * time.Hour

type Pruned struct{ Events, Windows, Summaries int64 }

func CheckRetentionRole(ctx context.Context, db *sql.DB) error {
	var scoped bool
	err := db.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'public.identity_telemetry_events','DELETE')
 AND has_column_privilege(current_user,'public.identity_telemetry_events','received_at_ms','SELECT')
 AND NOT has_column_privilege(current_user,'public.identity_telemetry_events','code','SELECT')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_events','INSERT')
 AND has_table_privilege(current_user,'public.identity_telemetry_windows','DELETE')
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','DELETE')
 AND has_column_privilege(current_user,'public.identity_telemetry_hourly','hour_start_ms','SELECT')
 AND NOT has_column_privilege(current_user,'public.identity_telemetry_hourly','events','SELECT')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_hourly','INSERT')
 AND NOT has_any_column_privilege(current_user,'public.identity_devices','SELECT')`).Scan(&scoped)
	if err != nil || !scoped {
		return ErrUnavailable
	}
	return nil
}

// Prune removes one bounded batch of expired data. New events and other
// application tables are not affected.
func Prune(ctx context.Context, db *sql.DB, now time.Time) (Pruned, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Pruned{}, ErrUnavailable
	}
	defer tx.Rollback()
	out, err := pruneRows(ctx, tx, now)
	if err != nil || tx.Commit() != nil {
		return Pruned{}, ErrUnavailable
	}
	return out, nil
}

// PruneScheduled checks authority and the DB clock in the same transaction
// that owns the three bounded deletes. The returned clock is authoritative
// for the worker's next step only after commit succeeds.
func PruneScheduled(ctx context.Context, db *sql.DB, previous time.Time) (time.Time, Pruned, error) {
	if ctx == nil || ctx.Err() != nil || db == nil {
		return time.Time{}, Pruned{}, ErrUnavailable
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, Pruned{}, ErrUnavailable
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL search_path TO pg_catalog, public, pg_temp"); err != nil {
		return time.Time{}, Pruned{}, ErrUnavailable
	}
	var now time.Time
	var scoped bool
	err = tx.QueryRowContext(ctx, scheduledAuthority).Scan(&scoped, &now)
	if err != nil || !scoped || now.Year() < 2020 || now.Year() >= 3000 || now.Before(previous) {
		return time.Time{}, Pruned{}, ErrUnavailable
	}
	var locked bool
	err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended('telemetry/retention/v1',0))").Scan(&locked)
	if err != nil || !locked {
		return time.Time{}, Pruned{}, ErrUnavailable
	}
	out, err := pruneRows(ctx, tx, now)
	if err != nil || ctx.Err() != nil || tx.Commit() != nil {
		return time.Time{}, Pruned{}, ErrUnavailable
	}
	return now.UTC(), out, nil
}

const scheduledAuthority = `WITH allowed(relation, keys) AS (
 VALUES ('public.identity_telemetry_events'::regclass, ARRAY['device','event_id','received_at_ms']),
        ('public.identity_telemetry_windows'::regclass, ARRAY['device','period']),
        ('public.identity_telemetry_hourly'::regclass, ARRAY['hour_start_ms'])
)
SELECT current_user='syn443_telemetry_retention' AND session_user=current_user
 AND EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=current_user
   AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolinherit OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication)
   AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid))
 AND NOT has_any_column_privilege(current_user,'public.identity_devices','SELECT,INSERT,UPDATE,REFERENCES')
 AND NOT has_table_privilege(current_user,'public.identity_devices','DELETE,TRUNCATE,TRIGGER')
 AND (SELECT COALESCE(bool_and(
   has_table_privilege(current_user,t.relation,'DELETE')
   AND NOT has_table_privilege(current_user,t.relation,'TRUNCATE,TRIGGER')
   AND (SELECT COALESCE(bool_and(
     has_column_privilege(current_user,t.relation,a.attnum,'SELECT')=(a.attname::text=ANY(t.keys))
     AND NOT has_column_privilege(current_user,t.relation,a.attnum,'INSERT,UPDATE,REFERENCES')
   ), false) FROM pg_attribute a WHERE a.attrelid=t.relation AND a.attnum>0 AND NOT a.attisdropped)
 ), false) FROM allowed t),
 statement_timestamp()`

func pruneRows(ctx context.Context, tx *sql.Tx, now time.Time) (Pruned, error) {
	var out Pruned
	events, err := tx.ExecContext(ctx, `WITH expired AS (
 SELECT device,event_id FROM public.identity_telemetry_events WHERE received_at_ms<$1 ORDER BY received_at_ms,device,event_id LIMIT 1024)
 DELETE FROM public.identity_telemetry_events e USING expired x WHERE e.device=x.device AND e.event_id=x.event_id`, now.Add(-DetailRetention).UnixMilli())
	if err != nil {
		return out, ErrUnavailable
	}
	windows, err := tx.ExecContext(ctx, `WITH expired AS (
 SELECT device,period FROM public.identity_telemetry_windows WHERE period<$1 ORDER BY period,device LIMIT 1024)
 DELETE FROM public.identity_telemetry_windows w USING expired x WHERE w.device=x.device AND w.period=x.period`, now.Add(-48*time.Hour).Unix())
	if err != nil {
		return out, ErrUnavailable
	}
	summaries, err := tx.ExecContext(ctx, `WITH expired AS (
 SELECT DISTINCT hour_start_ms FROM public.identity_telemetry_hourly WHERE hour_start_ms<$1 ORDER BY hour_start_ms LIMIT 4)
 DELETE FROM public.identity_telemetry_hourly h USING expired x WHERE h.hour_start_ms=x.hour_start_ms`, now.Add(-SummaryRetention).UnixMilli())
	if err != nil {
		return out, ErrUnavailable
	}
	if out.Events, err = events.RowsAffected(); err != nil {
		return Pruned{}, ErrUnavailable
	}
	if out.Windows, err = windows.RowsAffected(); err != nil {
		return Pruned{}, ErrUnavailable
	}
	if out.Summaries, err = summaries.RowsAffected(); err != nil {
		return Pruned{}, ErrUnavailable
	}
	return out, nil
}
