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

type SettledAggregate struct {
	Hour time.Time
	Hourly
}

type hourRow struct {
	Kind                     string `json:"kind"`
	Code                     string `json:"code"`
	Mode                     string `json:"mode"`
	Events                   int64  `json:"events"`
	Timed                    int64  `json:"timed"`
	Duration                 int64  `json:"duration"`
	BaselineReselections     int64  `json:"baselineReselections,omitempty"`
	ConservativeReselections int64  `json:"conservativeReselections,omitempty"`
}

const analysisPrivileges = `has_column_privilege(current_user,'public.identity_telemetry_events','received_at_ms','SELECT')
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
 AND has_table_privilege(current_user,'public.identity_telemetry_analysis_events','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_analysis_events','INSERT')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_analysis_events','UPDATE')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_analysis_events','DELETE')
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','SELECT')
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','INSERT')
 AND has_table_privilege(current_user,'public.identity_telemetry_hourly','DELETE')`

func CheckAnalysisRole(ctx context.Context, db *sql.DB) error {
	var scoped bool
	err := db.QueryRowContext(ctx, "SELECT "+analysisPrivileges).Scan(&scoped)
	if err != nil || !scoped {
		return ErrUnavailable
	}
	return nil
}

// AggregateHour replaces one settled UTC hour atomically. The extra event
// detects overload; a truncated result cannot replace a complete summary.
func AggregateHour(ctx context.Context, db *sql.DB, hour, now time.Time) (Hourly, error) {
	hour = hour.UTC()
	if hour.UnixMilli() <= 0 || !hour.Equal(hour.Truncate(time.Hour)) ||
		hour.Add(time.Hour).After(now.Add(-time.Hour)) || hour.Before(now.Add(-DetailRetention)) ||
		hour.Unix()/3600 > 2_147_483_647 {
		return Hourly{}, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Hourly{}, ErrUnavailable
	}
	defer tx.Rollback()
	out, err := aggregateHour(ctx, tx, hour)
	if err != nil {
		return Hourly{}, err
	}
	if err = tx.Commit(); err != nil {
		return Hourly{}, ErrUnavailable
	}
	return out, nil
}

// AggregateSettledHour selects the latest fully settled hour using the
// transaction's database timestamp. The caller's clock bounds clock skew.
// Both manual and scheduled invocations use the same per-hour database lock.
func AggregateSettledHour(ctx context.Context, db *sql.DB, reference time.Time) (SettledAggregate, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || reference.IsZero() {
		return SettledAggregate{}, ErrUnavailable
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return SettledAggregate{}, ErrUnavailable
	}
	defer tx.Rollback()
	now, err := analysisClock(ctx, tx, reference)
	if err != nil {
		return SettledAggregate{}, err
	}
	hour := now.UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	out, err := aggregateHour(ctx, tx, hour)
	if err != nil {
		return SettledAggregate{}, err
	}
	if ctx.Err() != nil || tx.Commit() != nil {
		return SettledAggregate{}, ErrUnavailable
	}
	return SettledAggregate{Hour: hour, Hourly: out}, nil
}

func analysisClock(ctx context.Context, tx *sql.Tx, reference time.Time) (time.Time, error) {
	if _, err := tx.ExecContext(ctx, "SET LOCAL search_path TO pg_catalog, public, pg_temp"); err != nil {
		return time.Time{}, ErrUnavailable
	}
	var scoped bool
	var now time.Time
	if err := tx.QueryRowContext(ctx, settledAnalysisAuthority).Scan(&scoped, &now); err != nil || !scoped ||
		now.Year() < 2020 || now.Year() >= 3000 || now.Sub(reference).Abs() > 2*time.Minute {
		return time.Time{}, ErrUnavailable
	}
	return now.UTC(), nil
}

// AggregatePendingHour repairs a single missing summary. On an error after
// selection, Hour is a scheduling hint only. No counts are returned until commit.
func AggregatePendingHour(ctx context.Context, db *sql.DB, reference, after time.Time) (SettledAggregate, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || reference.IsZero() {
		return SettledAggregate{}, ErrUnavailable
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return SettledAggregate{}, ErrUnavailable
	}
	defer tx.Rollback()
	now, err := analysisClock(ctx, tx, reference)
	if err != nil {
		return SettledAggregate{}, err
	}
	oldest := now.Add(-DetailRetention)
	if rounded := oldest.Truncate(time.Hour); rounded.Before(oldest) {
		oldest = rounded.Add(time.Hour)
	}
	latest := now.Truncate(time.Hour).Add(-2 * time.Hour)
	var millis int64
	err = tx.QueryRowContext(ctx, `SELECT h FROM generate_series($1::bigint, $2::bigint, 3600000::bigint) AS hours(h)
		WHERE NOT EXISTS (SELECT 1 FROM public.identity_telemetry_hourly WHERE hour_start_ms=h)
		AND EXISTS (SELECT 1 FROM public.identity_telemetry_events WHERE received_at_ms>=h AND received_at_ms<h+3600000)
		ORDER BY h <= $3::bigint, h LIMIT 1`, oldest.UnixMilli(), latest.UnixMilli(), after.UnixMilli()).Scan(&millis)
	if err == sql.ErrNoRows {
		return SettledAggregate{}, nil
	}
	if err != nil {
		return SettledAggregate{}, ErrUnavailable
	}
	hour := time.UnixMilli(millis).UTC()
	out, err := aggregateHour(ctx, tx, hour)
	if err != nil {
		return SettledAggregate{Hour: hour}, err
	}
	if ctx.Err() != nil || tx.Commit() != nil {
		return SettledAggregate{Hour: hour}, ErrUnavailable
	}
	return SettledAggregate{Hour: hour, Hourly: out}, nil
}

const settledAnalysisAuthority = `SELECT
 current_user='syn443_telemetry_analysis' AND current_user=session_user
 AND EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=current_user
   AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolinherit OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication)
   AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid))
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_events','TRIGGER')
 AND NOT has_any_column_privilege(current_user,'public.identity_telemetry_hourly','UPDATE,REFERENCES')
 AND NOT has_table_privilege(current_user,'public.identity_telemetry_hourly','TRUNCATE,TRIGGER')
 AND ` + analysisPrivileges + `,
 statement_timestamp()`

func aggregateHour(ctx context.Context, tx *sql.Tx, hour time.Time) (Hourly, error) {
	var locked bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(443052,$1::integer)`, hour.Unix()/3600).Scan(&locked); err != nil || !locked {
		return Hourly{}, ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, `WITH evidence AS MATERIALIZED (
 SELECT kind,code,mode,duration_ms,decision_variant FROM public.identity_telemetry_analysis_events
 WHERE received_at_ms >= $1 AND received_at_ms < $2 LIMIT $3)
 SELECT kind,code,mode,count(*),count(duration_ms),coalesce(sum(duration_ms),0),
  count(*) FILTER (WHERE decision_variant=1),count(*) FILTER (WHERE decision_variant=2)
 FROM evidence GROUP BY kind,code,mode ORDER BY kind,code,mode LIMIT 257`,
		hour.UnixMilli(), hour.Add(time.Hour).UnixMilli(), MaxHourlyEvents+1)
	if err != nil {
		return Hourly{}, ErrUnavailable
	}
	out := Hourly{}
	grouped := make([]hourRow, 0, 32)
	for rows.Next() {
		var row hourRow
		if err = rows.Scan(&row.Kind, &row.Code, &row.Mode, &row.Events, &row.Timed, &row.Duration,
			&row.BaselineReselections, &row.ConservativeReselections); err != nil {
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.identity_telemetry_hourly(hour_start_ms,kind,code,mode,events,timed,duration_total_ms,baseline_reselections,conservative_reselections)
 SELECT $1,kind,code,mode,events,timed,duration,coalesce("baselineReselections",0),coalesce("conservativeReselections",0)
 FROM jsonb_to_recordset($2::jsonb)
 AS e(kind text,code text,mode text,events bigint,timed bigint,duration bigint,
  "baselineReselections" bigint,"conservativeReselections" bigint)`, hour.UnixMilli(), string(encoded)); err != nil {
		return Hourly{}, ErrUnavailable
	}
	out.Groups = int64(len(grouped))
	return out, nil
}
