package telemetry

import (
	"context"
	"database/sql"
	_ "embed"
	"time"
)

//go:embed report-roles.sql
var ReportRoles string

type HourReport struct {
	SchemaVersion int       `json:"schemaVersion"`
	HourStartMS   int64     `json:"hourStartMs"`
	Available     bool      `json:"available"`
	Rows          []hourRow `json:"rows"`
}

const HourLayout = "2006-01-02T15:00Z"

func ParseHour(value string) (time.Time, error) {
	hour, err := time.Parse(HourLayout, value)
	if err != nil || hour.Format(HourLayout) != value {
		return time.Time{}, ErrInvalid
	}
	return hour, nil
}

func CheckReportRole(ctx context.Context, db *sql.DB) error {
	var scoped bool
	err := db.QueryRowContext(ctx, `SELECT current_user='syn443_telemetry_reader' AND session_user=current_user
 AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
   AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolinherit OR r.rolcreatedb OR r.rolcreaterole)
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid))
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_hourly','INSERT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_hourly','UPDATE')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_hourly','DELETE')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_hourly','TRUNCATE')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_events','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_events','INSERT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_events','UPDATE')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_events','DELETE')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_windows','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_devices','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_accounts','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_sessions','SELECT')`).Scan(&scoped)
	if err != nil || !scoped {
		return ErrUnavailable
	}
	return nil
}

func ReportHour(ctx context.Context, db *sql.DB, hour, now time.Time) (HourReport, error) {
	hour = hour.UTC()
	if hour.UnixMilli() <= 0 || !hour.Equal(hour.Truncate(time.Hour)) ||
		hour.Add(time.Hour).After(now.Add(-time.Hour)) || hour.Before(now.Add(-SummaryRetention)) {
		return HourReport{}, ErrInvalid
	}
	out := HourReport{SchemaVersion: 1, HourStartMS: hour.UnixMilli(), Rows: []hourRow{}}
	rows, err := db.QueryContext(ctx, `SELECT kind,code,mode,events,timed,duration_total_ms
 FROM public.identity_telemetry_hourly WHERE hour_start_ms=$1 ORDER BY kind,code,mode LIMIT 257`, out.HourStartMS)
	if err != nil {
		return HourReport{}, ErrUnavailable
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var row hourRow
		if err = rows.Scan(&row.Kind, &row.Code, &row.Mode, &row.Events, &row.Timed, &row.Duration); err != nil {
			return HourReport{}, ErrUnavailable
		}
		total += row.Events
		if len(out.Rows) >= 256 || total > MaxHourlyEvents || !codes[row.Kind][row.Code] || !modes[row.Mode] ||
			row.Events <= 0 || row.Timed < 0 || row.Timed > row.Events || row.Duration < 0 || row.Duration > row.Timed*600_000 {
			return HourReport{}, ErrUnavailable
		}
		out.Rows = append(out.Rows, row)
	}
	if rows.Err() != nil {
		return HourReport{}, ErrUnavailable
	}
	out.Available = len(out.Rows) > 0
	return out, nil
}
