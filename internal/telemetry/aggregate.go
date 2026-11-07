package telemetry

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"time"
)

//go:embed analysis-roles.sql
var AnalysisRoles string

//go:embed retention-roles.sql
var RetentionRoles string

const (
	MaxHourlyEvents  = 100_000
	SummaryRetention = 180 * 24 * time.Hour
)

type Hourly struct{ Groups, Events int64 }

type hourRow struct {
	Kind     string `json:"kind"`
	Code     string `json:"code"`
	Mode     string `json:"mode"`
	Events   int64  `json:"events"`
	Timed    int64  `json:"timed"`
	Duration int64  `json:"duration"`
}

func CheckAnalysisRole(ctx context.Context, db *sql.DB) error {
	var scoped bool
	err := db.QueryRowContext(ctx, `SELECT
 has_column_privilege(current_user,'public.identity_telemetry_events','received_at_ms','SELECT')
 AND has_column_privilege(current_user,'public.identity_telemetry_events','kind','SELECT')
 AND has_column_privilege(current_user,'public.identity_telemetry_events','code','SELECT')
 AND has_column_privilege(current_user,'public.identity_telemetry_events','mode','SELECT')
 AND has_column_privilege(current_user,'public.identity_telemetry_events','duration_ms','SELECT')
 AND NOT EXISTS (SELECT 1 FROM pg_attribute a
  WHERE a.attrelid='public.identity_telemetry_events'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND a.attname NOT IN ('received_at_ms','kind','code','mode','duration_ms')
  AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT'))
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_events','INSERT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_events','UPDATE')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_events','DELETE')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_events','TRUNCATE')
 AND NOT has_any_column_privilege(current_user,'public.identity_devices','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_accounts','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_sessions','SELECT')
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','SELECT')
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','INSERT')
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','DELETE')`).Scan(&scoped)
	if err != nil || !scoped {
		return ErrUnavailable
	}
	return nil
}

// AggregateHour replaces one settled UTC hour atomically. The extra event
// detects overload; a truncated result cannot replace a complete summary.
func AggregateHour(ctx context.Context, db *sql.DB, hour, now time.Time) (Hourly, error) {
	hour = hour.UTC()
	end := hour.Add(time.Hour)
	if hour.UnixMilli() <= 0 || !hour.Equal(hour.Truncate(time.Hour)) ||
		end.After(now.Add(-time.Hour)) || hour.Before(now.Add(-DetailRetention)) ||
		hour.Unix()/3600 > 2_147_483_647 {
		return Hourly{}, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Hourly{}, ErrUnavailable
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(443052,$1::integer)`, hour.Unix()/3600).Scan(&locked); err != nil || !locked {
		return Hourly{}, ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, `WITH evidence AS MATERIALIZED (
 SELECT kind,code,mode,duration_ms FROM public.identity_telemetry_events
 WHERE received_at_ms >= $1 AND received_at_ms < $2 LIMIT $3)
 SELECT kind,code,mode,count(*),count(duration_ms),coalesce(sum(duration_ms),0)
 FROM evidence GROUP BY kind,code,mode ORDER BY kind,code,mode LIMIT 257`,
		hour.UnixMilli(), end.UnixMilli(), MaxHourlyEvents+1)
	if err != nil {
		return Hourly{}, ErrUnavailable
	}
	out := Hourly{}
	grouped := make([]hourRow, 0, 32)
	for rows.Next() {
		var row hourRow
		if err = rows.Scan(&row.Kind, &row.Code, &row.Mode, &row.Events, &row.Timed, &row.Duration); err != nil {
			rows.Close()
			return Hourly{}, ErrUnavailable
		}
		out.Events += row.Events
		if len(grouped) >= 256 || out.Events > MaxHourlyEvents {
			rows.Close()
			return Hourly{}, ErrBudget
		}
		grouped = append(grouped, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Hourly{}, ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM public.identity_telemetry_hourly WHERE hour_start_ms=$1`, hour.UnixMilli()); err != nil {
		return Hourly{}, ErrUnavailable
	}
	encoded, err := json.Marshal(grouped)
	if err != nil {
		return Hourly{}, ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.identity_telemetry_hourly(hour_start_ms,kind,code,mode,events,timed,duration_total_ms)
 SELECT $1,kind,code,mode,events,timed,duration FROM jsonb_to_recordset($2::jsonb)
 AS e(kind text,code text,mode text,events bigint,timed bigint,duration bigint)`, hour.UnixMilli(), string(encoded)); err != nil {
		return Hourly{}, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return Hourly{}, ErrUnavailable
	}
	out.Groups = int64(len(grouped))
	return out, nil
}
