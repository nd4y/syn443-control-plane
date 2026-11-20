//go:build postgres

package enrollment

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func TestTelemetryAggregateWorkerProcessCommitsStopsAndResumes(t *testing.T) {
	f := newFixture(t, 1)
	f.api.TelemetryEnabled = true
	k := key(t)
	session, _, _ := f.register(t, k)
	base := time.Now().UTC().Truncate(time.Hour).Add(-9 * time.Hour)
	// Only these hours are shared with the other database fixtures.
	for _, hour := range []time.Time{base, base.Add(time.Hour)} {
		clear := func() {
			if _, err := fixtureOwner.Exec("DELETE FROM identity_telemetry_hourly WHERE hour_start_ms=$1", hour.UnixMilli()); err != nil {
				t.Error(err)
			}
		}
		clear()
		t.Cleanup(clear)
	}
	dsn := filepath.Join(t.TempDir(), "analysis")
	if err := os.WriteFile(dsn, []byte(fixtureAnalysisDSN), 0600); err != nil {
		t.Fatal("could not prepare a temporary analysis credential")
	}
	for _, hour := range []time.Time{base, base.Add(time.Hour)} {
		event := telemetry.Event{ID: random(), AtMS: f.now.UnixMilli(), Kind: "probe", Code: "ok", Mode: "wifi"}
		body, err := json.Marshal(telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 52, AlgorithmRevision: 1, Events: []telemetry.Event{event}})
		if err != nil {
			t.Fatal(err)
		}
		expect(t, f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body), http.StatusOK)
		if _, err := fixtureOwner.Exec("UPDATE identity_telemetry_events SET received_at_ms=$1 WHERE event_id=$2", hour.UnixMilli(), event.ID); err != nil {
			t.Fatal(err)
		}
		observe := func() {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SYN443_TEST_BINARY_DIR"), "enrollment-admin"), "telemetry-aggregate-worker")
			cmd.Env = []string{"SYN443_TELEMETRY_ANALYSIS_DSN_FILE=" + dsn}
			stdout, err := cmd.StdoutPipe()
			if err != nil || cmd.Start() != nil {
				t.Fatal("analysis worker failed to start")
			}
			defer func() {
				if cmd.ProcessState == nil {
					cancel()
					_ = cmd.Wait()
				}
			}()
			scanner := bufio.NewScanner(stdout)
			want := fmt.Sprintf("Telemetry hour summarized: hour=%s groups=1 events=1", hour.Format("2006-01-02T15:00Z"))
			if !scanner.Scan() || scanner.Text() != want {
				t.Fatal("analysis worker did not confirm the expected hour")
			}
			report, err := telemetry.ReportHour(t.Context(), fixtureTelemetryReader, hour, time.Now())
			if err != nil || !report.Available || len(report.Rows) != 1 || report.Rows[0].Events != 1 {
				t.Fatal("worker output preceded durable reader-visible data", err)
			}
			if cmd.Process.Signal(syscall.SIGTERM) != nil || cmd.Wait() != nil {
				t.Fatal("worker did not stop cleanly after commit")
			}
		}
		observe()
	}
}

func TestTelemetryWorkerRecoversRetainedGapsAndWrapsAfterBusyHour(t *testing.T) {
	f := newFixture(t, 1)
	f.api.TelemetryEnabled = true
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := t.Context()
	var now time.Time
	if err := fixtureOwner.QueryRowContext(ctx, "SELECT statement_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	start := now.UTC().Truncate(time.Hour)
	first, second := start.Add(-23*time.Hour), start.Add(-5*time.Hour)
	outside := start.Add(-telemetry.DetailRetention - time.Hour)
	future := start.Add(time.Hour)
	hours := []time.Time{first, second, second, outside, future}
	clear := func() {
		for _, h := range hours {
			if _, err := fixtureOwner.Exec("DELETE FROM identity_telemetry_hourly WHERE hour_start_ms=$1", h.UnixMilli()); err != nil {
				t.Error(err)
			}
		}
	}
	clear()
	t.Cleanup(clear)
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 52, AlgorithmRevision: 1}
	for range hours {
		batch.Events = append(batch.Events, telemetry.Event{ID: random(), AtMS: f.now.UnixMilli(), Kind: "probe", Code: "ok", Mode: "wifi"})
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body), http.StatusOK)
	for i, h := range hours {
		if _, err := fixtureOwner.ExecContext(ctx, "UPDATE identity_telemetry_events SET received_at_ms=$2 WHERE event_id=$1",
			batch.Events[i].ID, h.Add(5*time.Minute).UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	next := func(after time.Time) (telemetry.SettledAggregate, error) {
		return telemetry.AggregatePendingHour(ctx, fixtureAnalysis, time.Now(), after)
	}
	if res, err := telemetry.AggregatePendingHour(ctx, fixtureOwner, now, time.Time{}); err != telemetry.ErrUnavailable || !res.Hour.IsZero() {
		t.Fatal("wrong role selected work", res, err)
	}
	if res, err := telemetry.AggregatePendingHour(ctx, fixtureAnalysis, now.Add(time.Hour), time.Time{}); err != telemetry.ErrUnavailable || !res.Hour.IsZero() {
		t.Fatal("clock skew selected work", res, err)
	}
	lock, err := fixtureOwner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(443052,$1::integer)", first.Unix()/3600); err != nil {
		t.Fatal(err)
	}
	busy, err := next(time.Time{})
	if err != telemetry.ErrUnavailable || !busy.Hour.Equal(first) || busy.Events != 0 {
		t.Fatal("busy hour was reported as completed or could not be deferred", busy, err)
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureOwner.ExecContext(ctx, `INSERT INTO identity_telemetry_events
		(device,event_id,session_id,build,policy_revision,algorithm_revision,received_at_ms,observed_at_ms,elapsed_ms,network_epoch,kind,code,mode)
		SELECT device,lpad(i::text,43,'x'),session_id,build,policy_revision,algorithm_revision,received_at_ms,observed_at_ms,0,0,
		kind,'overload_'||chr(97+i/26)||chr(97+i%26),mode FROM identity_telemetry_events
		CROSS JOIN generate_series(1,257) i WHERE event_id=$1`, batch.Events[0].ID); err != nil {
		t.Fatal(err)
	}
	over, err := next(time.Time{})
	if err != telemetry.ErrBudget || !over.Hour.Equal(first) || over.Events != 0 {
		t.Fatal("budget failure could not be deferred safely", over, err)
	}
	later, err := next(over.Hour)
	if err != nil || !later.Hour.Equal(second) || later.Groups != 1 || later.Events != 2 {
		t.Fatal("the over-budget hour starved a later retained hour", later, err)
	}
	if _, err := fixtureOwner.ExecContext(ctx, "DELETE FROM identity_telemetry_events WHERE left(code,9)='overload_'"); err != nil {
		t.Fatal(err)
	}
	retry, err := next(later.Hour)
	if err != nil || !retry.Hour.Equal(first) || retry.Events != 1 {
		t.Fatal("older hour did not recover after wrap", retry, err)
	}
	again, err := next(time.Time{})
	if err != nil || !again.Hour.IsZero() || again.Events != 0 {
		t.Fatal("restart selected a completed, expired or unsettled hour", again, err)
	}
	report, err := telemetry.ReportHour(ctx, fixtureTelemetryReader, second, now)
	if err != nil || !report.Available || len(report.Rows) != 1 || report.Rows[0].Events != 2 {
		t.Fatal("approved summary reader could not read committed result", err)
	}
}
