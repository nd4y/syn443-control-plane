//go:build postgres

package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func seedRetentionRows(t *testing.T, eventCount int) (time.Time, string) {
	t.Helper()
	f := newFixture(t, 1)
	f.enableTelemetry(t)
	deviceKey := key(t)
	session, _, _ := f.register(t, deviceKey)
	eventID := random()
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 98, AlgorithmRevision: 1,
		Events: []telemetry.Event{{ID: eventID, AtMS: f.now.UnixMilli(), Kind: "vpn", Code: "online", Mode: "wifi"}}}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal("synthetic telemetry marshal failed")
	}
	expect(t, f.call(t, deviceKey, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body), http.StatusOK)
	var dbNow time.Time
	if err := fixtureOwner.QueryRow("SELECT statement_timestamp()").Scan(&dbNow); err != nil {
		t.Fatal("fixture clock unavailable")
	}
	// Keep the real API receipt as a fresh control. Historical rows are fixture
	// data only, timestamped on opposite sides of the existing retention limit.
	if _, err := fixtureOwner.Exec(`UPDATE identity_telemetry_events SET received_at_ms=$2 WHERE event_id=$1`,
		eventID, dbNow.Add(-telemetry.DetailRetention+time.Hour).UnixMilli()); err != nil {
		t.Fatal("fixture fresh event unavailable")
	}
	if _, err := fixtureOwner.Exec(`INSERT INTO identity_telemetry_events
 (device,event_id,session_id,build,policy_revision,algorithm_revision,received_at_ms,observed_at_ms,elapsed_ms,network_epoch,kind,code,mode)
 SELECT device,lpad(i::text,43,'x'),session_id,build,policy_revision,algorithm_revision,$2,observed_at_ms,0,0,kind,code,mode
 FROM identity_telemetry_events CROSS JOIN generate_series(1,$3::int) i WHERE event_id=$1`,
		eventID, dbNow.Add(-telemetry.DetailRetention-time.Hour).UnixMilli(), eventCount); err != nil {
		t.Fatal("fixture expired events unavailable")
	}
	return dbNow, eventID
}

func TestTelemetryScheduledRetentionPrunesOneBatchAndKeepsFreshEvents(t *testing.T) {
	before, freshID := seedRetentionRows(t, 1026)
	observed, result, err := telemetry.PruneScheduled(t.Context(), fixtureTelemetryRetention, time.Time{})
	if err != nil || observed.Before(before) || result.Events != 1024 {
		t.Fatal("scheduled retention did not apply exactly one bounded batch")
	}
	observedAgain, next, err := telemetry.PruneScheduled(t.Context(), fixtureTelemetryRetention, observed)
	if err != nil || observedAgain.Before(observed) || next.Events != 2 {
		t.Fatal("next step did not expire only the remaining rows")
	}
	var count, fresh int
	err = fixtureOwner.QueryRow("SELECT count(*), count(*) FILTER (WHERE event_id=$1) FROM identity_telemetry_events", freshID).
		Scan(&count, &fresh)
	if err != nil || count != 1 || fresh != 1 {
		t.Fatal("retention deleted the fresh event")
	}
}

func TestTelemetryScheduledRetentionRejectsOtherRolesRollbackAndConcurrentOwner(t *testing.T) {
	now, _ := seedRetentionRows(t, 1)
	rejected := func(ctx context.Context, db *sql.DB, previous time.Time) {
		t.Helper()
		observed, result, err := telemetry.PruneScheduled(ctx, db, previous)
		if !errors.Is(err, telemetry.ErrUnavailable) || !observed.IsZero() || result != (telemetry.Pruned{}) {
			t.Fatal("denied step produced committed evidence")
		}
	}
	rejected(t.Context(), fixtureOwner, time.Time{})
	rejected(t.Context(), fixtureAnalysis, time.Time{})
	rejected(t.Context(), fixtureTelemetryRetention, now.Add(time.Hour))
	const grantExtra = "GRANT SELECT (code) ON identity_telemetry_events TO syn443_telemetry_retention"
	const revokeExtra = "REVOKE SELECT (code) ON identity_telemetry_events FROM syn443_telemetry_retention"
	if _, err := fixtureOwner.Exec(grantExtra); err != nil {
		t.Fatal("fixture could not add an unexpected read privilege")
	}
	t.Cleanup(func() {
		if _, err := fixtureOwner.Exec(revokeExtra); err != nil {
			t.Error("fixture privilege cleanup failed")
		}
	})
	rejected(t.Context(), fixtureTelemetryRetention, time.Time{})
	if _, err := fixtureOwner.Exec(revokeExtra); err != nil {
		t.Fatal("fixture could not restore the scoped role")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rejected(ctx, fixtureTelemetryRetention, time.Time{})
	lock, err := fixtureOwner.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal("fixture lock transaction failed")
	}
	defer lock.Rollback()
	if _, err = lock.Exec("SELECT pg_advisory_xact_lock(hashtextextended('telemetry/retention/v1',0))"); err != nil {
		t.Fatal("fixture could not hold retention lock")
	}
	rejected(t.Context(), fixtureTelemetryRetention, time.Time{})
	var count int
	if err = lock.QueryRow("SELECT count(*) FROM identity_telemetry_events").Scan(&count); err != nil || count != 2 {
		t.Fatal("rejected step deleted telemetry")
	}
}
