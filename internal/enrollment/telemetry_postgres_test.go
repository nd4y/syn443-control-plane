//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func TestTelemetrySettledHourUsesDatabaseClockAndSharesManualLock(t *testing.T) {
	f := newFixture(t, 1)
	f.enableTelemetry(t)
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := t.Context()
	var before time.Time
	if err := fixtureOwner.QueryRowContext(ctx, "SELECT statement_timestamp()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	base := before.UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 52, AlgorithmRevision: 1}
	for range 5 {
		batch.Events = append(batch.Events, telemetry.Event{
			ID: random(), AtMS: f.now.UnixMilli(), Kind: "probe", Code: "ok", Mode: "wifi",
		})
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body), http.StatusOK)
	eventTimes := []time.Time{
		base.Add(-time.Millisecond), base, base.Add(time.Hour - time.Millisecond),
		base.Add(time.Hour), base.Add(2 * time.Hour),
	}
	for i, event := range batch.Events {
		if _, err := fixtureOwner.ExecContext(ctx, "UPDATE identity_telemetry_events SET received_at_ms=$2 WHERE event_id=$1",
			event.ID, eventTimes[i].UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}

	lock, err := fixtureOwner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	// Protect both possible hours so a test crossing an hour boundary remains deterministic.
	for _, hour := range []time.Time{base, base.Add(time.Hour)} {
		if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(443052,$1::integer)", hour.Unix()/3600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := telemetry.AggregateSettledHour(ctx, fixtureAnalysis, time.Now()); err != telemetry.ErrUnavailable {
		t.Fatal("the scheduled transaction ignored the aggregate lock")
	}
	if _, err := telemetry.AggregateHour(ctx, fixtureAnalysis, base, base.Add(3*time.Hour)); err != telemetry.ErrUnavailable {
		t.Fatal("the existing manual command lost the aggregate lock")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		out, err := telemetry.AggregateSettledHour(ctx, fixtureAnalysis, time.Now())
		if err != nil {
			t.Fatal("scheduled analysis failed", err)
		}
		want := int64(2)
		if out.Hour.Equal(base.Add(time.Hour)) {
			want = 1
		} else if !out.Hour.Equal(base) {
			t.Fatal("the selected hour is outside the valid database time window")
		}
		if out.Events != want || out.Groups != 1 {
			t.Fatal("the replacement included events from another hour", out)
		}
		report, err := telemetry.ReportHour(ctx, fixtureTelemetryReader, out.Hour, time.Now().Add(2*time.Minute))
		if err != nil || !report.Available || len(report.Rows) != 1 || report.Rows[0].Events != want {
			t.Fatal("the committed report is missing or was duplicated", err)
		}
	}
}

func TestTelemetrySettledHourRejectsWrongRoleClockAndExtraWriteAuthority(t *testing.T) {
	newFixture(t, 1)
	ctx := t.Context()
	for _, db := range []*sql.DB{fixtureOwner, fixtureTelemetryRetention, fixtureTelemetryReader} {
		if out, err := telemetry.AggregateSettledHour(ctx, db, time.Now()); err != telemetry.ErrUnavailable || !out.Hour.IsZero() {
			t.Fatal("an unrelated role was authorized")
		}
	}
	for _, shift := range []time.Duration{-3 * time.Minute, 3 * time.Minute} {
		if out, err := telemetry.AggregateSettledHour(ctx, fixtureAnalysis, time.Now().Add(shift)); err != telemetry.ErrUnavailable || !out.Hour.IsZero() {
			t.Fatal("an excessive database clock difference was accepted")
		}
	}
	if _, err := fixtureOwner.ExecContext(ctx, "GRANT UPDATE(events) ON identity_telemetry_hourly TO syn443_telemetry_analysis"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := fixtureOwner.Exec("REVOKE UPDATE(events) ON identity_telemetry_hourly FROM syn443_telemetry_analysis"); err != nil {
			t.Error("restore analysis role after fixture", err)
		}
	})
	if out, err := telemetry.AggregateSettledHour(ctx, fixtureAnalysis, time.Now()); err != telemetry.ErrUnavailable || !out.Hour.IsZero() {
		t.Fatal("a role with surplus write privileges was authorized")
	}
}

func TestTelemetrySummaryUsesScopedRolesAndKeepsLastCompleteHour(t *testing.T) {
	f := newFixture(t, 1)
	f.enableTelemetry(t)
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := t.Context()
	if err := telemetry.CheckAnalysisRole(ctx, fixtureAnalysis); err != nil || telemetry.CheckAnalysisRole(ctx, fixtureOwner) == nil {
		t.Fatal("incorrect analysis privilege boundary", err)
	}
	if err := telemetry.CheckRetentionRole(ctx, fixtureTelemetryRetention); err != nil || telemetry.CheckRetentionRole(ctx, fixtureAnalysis) == nil {
		t.Fatal("retention role is not separate", err)
	}
	if err := telemetry.CheckReportRole(ctx, fixtureTelemetryReader); err != nil || telemetry.CheckReportRole(ctx, fixtureAnalysis) == nil {
		t.Fatal("report role has broader permissions than intended", err)
	}
	if _, err := fixtureTelemetryReader.Exec(`SELECT kind FROM identity_telemetry_events`); err == nil {
		t.Fatal("report reader could see raw events")
	}
	if _, err := fixtureAnalysis.Exec(`SELECT device,event_id,session_id,path_id FROM identity_telemetry_events`); err == nil {
		t.Fatal("analysis role read event identity")
	}
	period := f.now.UTC().Truncate(time.Hour)
	now := period.Add(3 * time.Hour)
	if _, err := telemetry.AggregateHour(ctx, fixtureAnalysis, period, period.Add(time.Hour)); !errors.Is(err, telemetry.ErrInvalid) {
		t.Fatal("unsettled hour was summarized", err)
	}
	duration := 93
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 52, AlgorithmRevision: 1,
		Events: []telemetry.Event{
			{ID: random(), AtMS: f.now.UnixMilli(), Kind: "probe", Code: "ok", Mode: "wifi", DurationMS: &duration},
			{ID: random(), AtMS: f.now.UnixMilli(), Kind: "probe", Code: "ok", Mode: "wifi"},
			{ID: random(), AtMS: f.now.UnixMilli(), Kind: "vpn", Code: "online", Mode: "wifi"},
		}}
	body, _ := json.Marshal(batch)
	expect(t, f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body), http.StatusOK)
	if _, err := fixtureOwner.Exec(`UPDATE identity_telemetry_events SET received_at_ms=$2 WHERE event_id=$1`,
		batch.Events[2].ID, period.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		out, err := telemetry.AggregateHour(ctx, fixtureAnalysis, period, now)
		if err != nil || out.Groups != 1 || out.Events != 2 {
			t.Fatal("aggregate did not select exactly one hour", err, out)
		}
	}
	verify := func() {
		t.Helper()
		var events, timed, total int
		if err := fixtureAnalysis.QueryRow(`SELECT events,timed,duration_total_ms FROM identity_telemetry_hourly
 WHERE hour_start_ms=$1 AND kind='probe' AND code='ok' AND mode='wifi'`, period.UnixMilli()).Scan(&events, &timed, &total); err != nil || events != 2 || timed != 1 || total != duration {
			t.Fatal("complete aggregate changed", err)
		}
		report, err := telemetry.ReportHour(ctx, fixtureTelemetryReader, period, now)
		if err != nil || report.SchemaVersion != 1 || !report.Available || len(report.Rows) != 1 ||
			report.Rows[0].Events != 2 || report.Rows[0].Timed != 1 || report.Rows[0].Duration != int64(duration) {
			t.Fatal("read-only report did not return the complete aggregate", err)
		}
	}
	verify()
	empty, err := telemetry.ReportHour(ctx, fixtureTelemetryReader, period.Add(time.Hour), now)
	if err != nil || empty.Available || len(empty.Rows) != 0 {
		t.Fatal("unprocessed hour looked like a completed summary", err)
	}
	if _, err = fixtureTelemetryReader.Exec(`DELETE FROM identity_telemetry_hourly WHERE hour_start_ms=$1`, period.UnixMilli()); err == nil {
		t.Fatal("report role could modify aggregates")
	}
	if _, err := fixtureOwner.Exec(`INSERT INTO identity_telemetry_events(device,event_id,session_id,build,policy_revision,algorithm_revision,received_at_ms,observed_at_ms,elapsed_ms,network_epoch,kind,code,mode)
 SELECT device,lpad(i::text,43,'x'),session_id,build,policy_revision,algorithm_revision,received_at_ms,observed_at_ms,0,0,
 kind,'overload_'||chr(97+i/26)||chr(97+i%26),mode
 FROM identity_telemetry_events CROSS JOIN generate_series(1,257) i WHERE event_id=$1`, batch.Events[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetry.AggregateHour(ctx, fixtureAnalysis, period, now); !errors.Is(err, telemetry.ErrBudget) {
		t.Fatal("over-budget summary was accepted", err)
	}
	verify()
	if _, err := fixtureOwner.Exec(`INSERT INTO identity_telemetry_hourly(hour_start_ms,kind,code,mode,events,timed,duration_total_ms) VALUES($1,'probe','ok','wifi',1,0,0)`,
		period.Add(-telemetry.SummaryRetention-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if got, err := telemetry.Prune(ctx, fixtureTelemetryRetention, now); err != nil || got.Summaries != 1 {
		t.Fatal("aggregate retention did not remove only expired hours", err, got)
	}
	verify()
}

func TestTelemetryReportCountsOnlyKnownDecisionsWithoutRawRevisionAccess(t *testing.T) {
	f := newFixture(t, 1)
	f.enableTelemetry(t)
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := t.Context()
	for _, column := range []string{"device", "policy_revision", "algorithm_revision"} {
		if _, err := fixtureAnalysis.Exec("SELECT " + column + " FROM identity_telemetry_events"); err == nil {
			t.Fatal("analysis role read a restricted raw column", column)
		}
	}
	if _, err := fixtureTelemetryReader.Exec(`SELECT decision_variant FROM identity_telemetry_analysis_events`); err == nil {
		t.Fatal("report reader could see individual variant labels")
	}
	for _, stamp := range []struct {
		policy    int64
		algorithm int
		build     int
	}{{41, 1, 60}, {42, 2, 60}, {0, 1, 60}, {43, 99, 128}, {44, 3, 127}, {0, 3, 128}, {45, 3, 128}} {
		batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: stamp.build,
			PolicyRevision: stamp.policy, AlgorithmRevision: stamp.algorithm,
			Events: []telemetry.Event{{ID: random(), AtMS: f.now.UnixMilli(), Kind: "route", Code: "reselected", Mode: "wifi"}}}
		body, _ := json.Marshal(batch)
		expect(t, f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body), http.StatusOK)
	}
	hour := f.now.UTC().Truncate(time.Hour)
	now := hour.Add(3 * time.Hour)
	if _, err := telemetry.AggregateHour(ctx, fixtureAnalysis, hour, now); err != nil {
		t.Fatal(err)
	}
	report, err := telemetry.ReportHour(ctx, fixtureTelemetryReader, hour, now)
	if err != nil || !report.Available || len(report.Rows) != 1 {
		t.Fatal("could not read the decision aggregate", err)
	}
	row := report.Rows[0]
	if row.Events != 7 || row.BaselineReselections != 1 || row.ConservativeReselections != 1 || row.AdaptiveReselections != 1 {
		t.Fatal("unknown or missing decision stamps entered an algorithm count")
	}
}

func TestDeviceTelemetryIsBoundedDeduplicatedAndScopedToItsSession(t *testing.T) {
	f := newFixture(t, 2)
	ctx := context.Background()
	if err := telemetry.CheckIngestionRole(ctx, fixtureAPI); err != nil || telemetry.CheckIngestionRole(ctx, fixtureOwner) == nil {
		t.Fatal("wrong telemetry ingestion database role", err)
	}
	deviceKey, otherKey := key(t), key(t)
	first, _, _ := f.register(t, deviceKey)
	second, _, _ := f.register(t, otherKey)
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 51, AlgorithmRevision: 1,
		Events: []telemetry.Event{{ID: random(), AtMS: f.now.UnixMilli(), ElapsedMS: 100, NetworkEpoch: 1,
			Kind: "vpn", Code: "online", Mode: "wifi"}}}
	body, _ := json.Marshal(batch)
	expect(t, f.call(t, deviceKey, "POST", telemetryPath, first.AccessToken, first.Nonce, body), http.StatusNotFound)
	f.enableTelemetry(t)
	for range 2 {
		response := f.call(t, deviceKey, "POST", telemetryPath, first.AccessToken, first.Nonce, body)
		expect(t, response, http.StatusOK)
		var receipt telemetry.Receipt
		if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil || receipt.SchemaVersion != 1 ||
			len(receipt.EventIDs) != 1 || receipt.EventIDs[0] != batch.Events[0].ID {
			t.Fatal("missing or invalid committed event receipt", err)
		}
	}
	wrongScope := f.call(t, otherKey, "POST", telemetryPath, first.AccessToken, first.Nonce, body)
	if wrongScope.Code != http.StatusUnauthorized && wrongScope.Code != http.StatusForbidden {
		t.Fatal("another device used the session to submit telemetry", wrongScope.Code)
	}
	private := bytes.Replace(body, []byte(`"mode":"wifi"`), []byte(`"mode":"wifi","address":"node.example.invalid"`), 1)
	expect(t, f.call(t, deviceKey, "POST", telemetryPath, first.AccessToken, first.Nonce, private), http.StatusUnauthorized)
	expect(t, f.call(t, otherKey, "POST", telemetryPath, second.AccessToken, second.Nonce, body), http.StatusOK)
	var stored int
	if err := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_telemetry_events WHERE event_id=$1 AND device IN ($2,$3)`,
		batch.Events[0].ID, first.DeviceID, second.DeviceID).Scan(&stored); err != nil || stored != 2 {
		t.Fatal("telemetry duplicate or cross-device collision", err, stored)
	}
	if _, err := fixtureAPI.Exec(`SELECT code FROM identity_telemetry_events`); err == nil {
		t.Fatal("ingestion role can read event data")
	}
	if _, err := fixtureOwner.Exec(`UPDATE identity_telemetry_windows SET used=$2 WHERE device=$1`, first.DeviceID, telemetry.EventsPerDeviceHour); err != nil {
		t.Fatal(err)
	}
	limited := f.call(t, deviceKey, "POST", telemetryPath, first.AccessToken, first.Nonce, body)
	expect(t, limited, http.StatusTooManyRequests)
	if limited.Header().Get("Retry-After") != "3600" {
		t.Fatal("full UTC hour must be observed before retry", limited.Header().Get("Retry-After"))
	}
	if _, err := fixtureOwner.Exec(`UPDATE identity_telemetry_events SET received_at_ms=$2 WHERE device=$1`, first.DeviceID, f.now.Add(-telemetry.DetailRetention-time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	out, err := telemetry.Prune(ctx, fixtureOwner, f.now)
	if err != nil || out.Events != 1 {
		t.Fatal("retention did not remove only expired evidence", err, out)
	}
	if err := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_telemetry_events WHERE device=$1`, second.DeviceID).Scan(&stored); err != nil || stored != 1 {
		t.Fatal("recent event was not retained", err)
	}
}

func TestTelemetryRetryAdviceEndsAtTheActualSQLQuotaWindow(t *testing.T) {
	f := newFixture(t, 1)
	f.now = f.now.UTC().Truncate(time.Hour).Add(time.Hour - 2*time.Second)
	f.api.Clock = func() time.Time { return f.now }
	f.enableTelemetry(t)
	k := key(t)
	session, _, _ := f.register(t, k)
	period := f.now.Truncate(time.Hour).Unix()
	if _, err := fixtureOwner.Exec(`INSERT INTO identity_telemetry_windows(device,period,used) VALUES($1,$2,$3)`,
		session.DeviceID, period, telemetry.EventsPerDeviceHour); err != nil {
		t.Fatal(err)
	}
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 55, AlgorithmRevision: 1,
		Events: []telemetry.Event{{ID: random(), AtMS: f.now.UnixMilli(), Kind: "vpn", Code: "online", Mode: "wifi"}}}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	for _, wait := range []string{"2", "1"} {
		response := f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body)
		expect(t, response, http.StatusTooManyRequests)
		if response.Header().Get("Retry-After") != wait {
			t.Fatal("wrong quota boundary", response.Header().Get("Retry-After"), wait)
		}
		f.now = f.now.Add(time.Second)
	}
	response := f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body)
	expect(t, response, http.StatusOK)
	var receipt telemetry.Receipt
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil || len(receipt.EventIDs) != 1 || receipt.EventIDs[0] != batch.Events[0].ID {
		t.Fatal("missing event receipt at the quota boundary", err)
	}
	var received int64
	if err := fixtureOwner.QueryRow(`SELECT received_at_ms FROM identity_telemetry_events WHERE device=$1 AND event_id=$2`,
		session.DeviceID, batch.Events[0].ID).Scan(&received); err != nil || received != f.now.UnixMilli() {
		t.Fatal("throttled attempts stored an event or the accepted attempt was lost", err)
	}
}

func TestTelemetryLateBatchesPreserveFirstReceiptAndObservation(t *testing.T) {
	f := newFixture(t, 1)
	// Advance the signed requests and server admission on the same fixture clock.
	f.api.Clock = func() time.Time { return f.now }
	f.enableTelemetry(t)
	k := key(t)
	session, _, _ := f.register(t, k)
	origin := f.now.UTC().Truncate(time.Second)
	event := func(age time.Duration, monotonic, epoch int64) telemetry.Event {
		return telemetry.Event{ID: random(), AtMS: origin.Add(-age).UnixMilli(),
			ElapsedMS: monotonic, NetworkEpoch: epoch, Kind: "vpn", Code: "online", Mode: "wifi"}
	}
	older := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 52, PolicyRevision: 3, AlgorithmRevision: 1,
		Events: []telemetry.Event{event(10*time.Minute, 2000, 2), event(11*time.Minute, 1000, 1)}}
	newer := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 53, PolicyRevision: 4, AlgorithmRevision: 2,
		Events: []telemetry.Event{event(time.Second, 8000, 4)}}

	send := func(at time.Duration, batch telemetry.Batch) {
		t.Helper()
		f.now = origin.Add(at)
		body, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		response := f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body)
		expect(t, response, http.StatusOK)
		var receipt telemetry.Receipt
		if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil || receipt.SchemaVersion != 1 || len(receipt.EventIDs) != len(batch.Events) {
			t.Fatal("missing committed acknowledgement", err)
		}
		for i, e := range batch.Events {
			if receipt.EventIDs[i] != e.ID {
				t.Fatal("receipt lost the submitted order")
			}
		}
	}
	send(0, newer)
	send(2*time.Second, older)
	send(4*time.Second, older)
	send(6*time.Second, newer)

	var total int
	if err := fixtureOwner.QueryRowContext(t.Context(), `SELECT count(*) FROM identity_telemetry_events WHERE device=$1`, session.DeviceID).Scan(&total); err != nil || total != 3 {
		t.Fatal("late delivery or replay changed the event count", total, err)
	}
	for _, delivery := range []struct {
		batch telemetry.Batch
		at    time.Time
	}{{newer, origin}, {older, origin.Add(2 * time.Second)}} {
		b := delivery.batch
		for _, e := range b.Events {
			var match bool
			err := fixtureOwner.QueryRowContext(t.Context(), `SELECT session_id=$3 AND build=$4 AND policy_revision=$5
 AND algorithm_revision=$6 AND received_at_ms=$7 AND observed_at_ms=$8 AND elapsed_ms=$9 AND network_epoch=$10
 FROM identity_telemetry_events WHERE device=$1 AND event_id=$2`,
				session.DeviceID, e.ID, b.Session, b.Build, b.PolicyRevision, b.AlgorithmRevision,
				delivery.at.UnixMilli(), e.AtMS, e.ElapsedMS, e.NetworkEpoch).Scan(&match)
			if err != nil || !match {
				t.Fatal("stored event lost its original observation or first receipt", err)
			}
		}
	}
}

func TestHourlyDurationP95UsesMeasuredNearestRankAndPreservesLegacyRows(t *testing.T) {
	f := newFixture(t, 1)
	f.enableTelemetry(t)
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := t.Context()
	period := f.now.UTC().Truncate(time.Hour)
	now := period.Add(3 * time.Hour)
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 52, AlgorithmRevision: 1}
	add := func(kind, code string, duration *int) {
		batch.Events = append(batch.Events, telemetry.Event{ID: random(), AtMS: f.now.UnixMilli(),
			Kind: kind, Code: code, Mode: "wifi", DurationMS: duration})
	}
	for value := range 19 {
		add("probe", "ok", &value)
	}
	tail, zero := 600000, 0
	add("probe", "ok", &tail)
	add("probe", "ok", nil)
	add("probe", "dns_timeout", &zero)
	add("vpn", "online", nil)
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(t, k, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body), http.StatusOK)
	for range 2 {
		totals, err := telemetry.AggregateHour(ctx, fixtureAnalysis, period, now)
		if err != nil || totals.Events != 23 || totals.Groups != 3 {
			t.Fatal("wrong sample or bucket count", totals, err)
		}
		report, err := telemetry.ReportHour(ctx, fixtureTelemetryReader, period, now)
		if err != nil || !report.Available || len(report.Rows) != 3 {
			t.Fatal("missing hourly rows", err)
		}
		for _, row := range report.Rows {
			switch row.Code {
			case "ok":
				if row.Timed != 20 || row.Events != 21 || row.DurationP95MS == nil || *row.DurationP95MS != 18 {
					t.Fatal("p95 must be sample 19 of 20 measured observations")
				}
			case "dns_timeout":
				if row.Timed != 1 || row.DurationP95MS == nil || *row.DurationP95MS != 0 {
					t.Fatal("zero measurement was lost")
				}
			case "online":
				if row.Timed != 0 || row.DurationP95MS != nil {
					t.Fatal("missing observation acquired a duration")
				}
			default:
				t.Fatal("unexpected bucket")
			}
		}
	}
	if _, err := fixtureOwner.ExecContext(ctx, `UPDATE identity_telemetry_hourly SET duration_p95_ms=NULL WHERE hour_start_ms=$1 AND code='ok'`, period.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	report, err := telemetry.ReportHour(ctx, fixtureTelemetryReader, period, now)
	if err != nil || len(report.Rows) != 3 {
		t.Fatal("legacy summary unavailable", err)
	}
	for _, row := range report.Rows {
		if row.Code == "ok" && (row.DurationP95MS != nil || row.Timed != 20) {
			t.Fatal("legacy hour invented a percentile")
		}
	}
}
