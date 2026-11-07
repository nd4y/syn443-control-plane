//go:build postgres

package catalog

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func TestSQLTelemetrySummaryRequiresExplicitACLAndAuditsReads(t *testing.T) {
	f := adminHTTPFixture(t)
	hour := f.Now.Truncate(time.Hour).Add(-2 * time.Hour)
	payload := map[string]string{"hour": hour.Format(telemetry.HourLayout)}
	f.call(t, telemetrySummaryAction, payload, 404)
	var reads int
	f.API.TelemetrySummary = func(_ context.Context, got, now time.Time) (telemetry.HourReport, error) {
		reads++
		if !got.Equal(hour) || !now.Equal(f.Now) {
			t.Fatal("wrong report boundaries")
		}
		return telemetry.HourReport{SchemaVersion: 1, HourStartMS: got.UnixMilli()}, nil
	}
	f.call(t, telemetrySummaryAction, payload, 404) // The fixture has only a wildcard grant.
	if reads != 0 {
		t.Fatal("the aggregate reader was reached without its exact grant")
	}
	if _, err := fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires)
 VALUES($1,$2,'telemetry','global',$3)`, f.Actor.ID, telemetrySummaryAction, f.Now.Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	f.call(t, telemetrySummaryAction, map[string]string{"hour": payload["hour"], "device": "synthetic-device"}, 400)
	f.call(t, telemetrySummaryAction, map[string]string{"hour": "2026-02-30T07:00Z"}, 400)
	f.Verifier.Principal.Scope = "syn443.chat"
	f.call(t, telemetrySummaryAction, payload, 403)
	f.Verifier.Principal.Scope = "openid syn443.control"
	var report telemetry.HourReport
	if raw := f.call(t, telemetrySummaryAction, payload, 200); json.Unmarshal(raw, &report) != nil || report.HourStartMS != hour.UnixMilli() || report.Available || reads != 1 {
		t.Fatal("missing bounded, empty hourly report")
	}
	var count int
	if err := fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_audit
 WHERE actor=$1 AND action=$2 AND target=$3 AND outcome='read'`, f.Actor.ID, telemetrySummaryAction,
		"telemetry:"+payload["hour"]).Scan(&count); err != nil || count != 1 {
		t.Fatal("successful report read must be audited", err)
	}
	f.API.TelemetrySummary = func(context.Context, time.Time, time.Time) (telemetry.HourReport, error) {
		return telemetry.HourReport{}, telemetry.ErrUnavailable
	}
	f.call(t, telemetrySummaryAction, payload, 503)
	if _, err := fixtureOwner.Exec(`UPDATE catalog_acl SET expires=$1 WHERE actor=$2 AND action=$3`,
		f.Now.Unix(), f.Actor.ID, telemetrySummaryAction); err != nil {
		t.Fatal(err)
	}
	f.call(t, telemetrySummaryAction, payload, 404)
	if _, err := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, f.Actor.ID); err != nil {
		t.Fatal(err)
	}
	f.call(t, telemetrySummaryAction, payload, 403)
}
