package catalog

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

const telemetrySummaryAction = "telemetry.summary.get"

func (a *API) readTelemetrySummary(ctx context.Context, actor Actor, hour, now time.Time, requestID string) (telemetry.HourReport, error) {
	if a.TelemetrySummary == nil || actor.SessionUntil <= now.Unix() {
		return telemetry.HourReport{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	defer tx.Rollback()
	// A catalog-wide wildcard does not grant access to global telemetry.
	var target string
	err = tx.QueryRowContext(ctx, `SELECT target_id FROM catalog_acl
 WHERE actor=$1 AND action=$2 AND target_kind='telemetry' AND target_id='global' AND expires>$3
 FOR SHARE`, actor.ID, telemetrySummaryAction, now.Unix()).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) {
		return telemetry.HourReport{}, ErrDenied
	}
	if err != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	report, err := a.TelemetrySummary(ctx, hour, now)
	if errors.Is(err, telemetry.ErrInvalid) {
		return telemetry.HourReport{}, ErrInvalid
	}
	if err != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	if audit(ctx, tx, actor.ID, telemetrySummaryAction, "telemetry:"+hour.Format(telemetry.HourLayout), requestID, "", "", "read", now.Unix()) != nil || tx.Commit() != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	return report, nil
}
