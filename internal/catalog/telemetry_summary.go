package catalog

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

const telemetrySummaryAction = "telemetry.summary.get"

var errTelemetrySummaryHidden = errors.New("telemetry_summary_hidden")

func (a *API) readTelemetrySummary(ctx context.Context, actor Actor, hour, now time.Time, requestID string) (telemetry.HourReport, error) {
	if actor.SessionUntil <= now.Unix() {
		return telemetry.HourReport{}, ErrDenied
	}
	if a.TelemetrySummary == nil {
		return telemetry.HourReport{}, errTelemetrySummaryHidden
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	defer tx.Rollback()
	// A catalog-wide wildcard does not grant access to global telemetry.
	var grantUntil int64
	err = tx.QueryRowContext(ctx, `SELECT expires FROM catalog_acl
 WHERE actor=$1 AND action=$2 AND target_kind='telemetry' AND target_id='global' AND expires>$3
 FOR SHARE`, actor.ID, telemetrySummaryAction, now.Unix()).Scan(&grantUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return telemetry.HourReport{}, errTelemetrySummaryHidden
	}
	if err != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	// SQL holds the grant row for the read. Its expiry and the session expiry
	// can still pass while the separate aggregate reader is working.
	current := func() time.Time {
		at := now.Add(time.Since(started))
		if wall := a.Clock(); wall.After(at) {
			return wall
		}
		return at
	}
	authorized := func(at time.Time) error {
		if at.Unix() >= actor.SessionUntil {
			return ErrDenied
		}
		if at.Unix() >= grantUntil {
			return errTelemetrySummaryHidden
		}
		return nil
	}
	at := current()
	if err = authorized(at); err != nil {
		return telemetry.HourReport{}, err
	}
	until := time.Unix(min(grantUntil, actor.SessionUntil), 0)
	readCtx, cancelRead := context.WithTimeout(ctx, until.Sub(at))
	defer cancelRead()
	report, err := a.TelemetrySummary(readCtx, hour, now)
	at = current()
	if e := authorized(at); e != nil {
		return telemetry.HourReport{}, e
	}
	if errors.Is(err, telemetry.ErrInvalid) {
		return telemetry.HourReport{}, ErrInvalid
	}
	if err != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	if readCtx.Err() != nil || audit(readCtx, tx, actor.ID, telemetrySummaryAction, "telemetry:"+hour.Format(telemetry.HourLayout), requestID, "", "", "read", at.Unix()) != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	if err = authorized(current()); err != nil {
		return telemetry.HourReport{}, err
	}
	if err = tx.Commit(); err != nil {
		return telemetry.HourReport{}, ErrUnavailable
	}
	if err = authorized(current()); err != nil {
		return telemetry.HourReport{}, err
	}
	return report, nil
}
