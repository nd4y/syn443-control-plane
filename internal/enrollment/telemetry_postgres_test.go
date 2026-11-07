//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func TestTelemetrySummaryUsesScopedRolesAndKeepsLastCompleteHour(t *testing.T) {
	f := newFixture(t, 1)
	f.api.TelemetryEnabled = true
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := t.Context()
	if err := telemetry.CheckAnalysisRole(ctx, fixtureAnalysis); err != nil || telemetry.CheckAnalysisRole(ctx, fixtureOwner) == nil {
		t.Fatal("incorrect analysis privilege boundary", err)
	}
	if err := telemetry.CheckRetentionRole(ctx, fixtureTelemetryRetention); err != nil || telemetry.CheckRetentionRole(ctx, fixtureAnalysis) == nil {
		t.Fatal("retention role is not separate", err)
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
	}
	verify()
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
	if _, err := fixtureOwner.Exec(`INSERT INTO identity_telemetry_hourly VALUES($1,'probe','ok','wifi',1,0,0)`,
		period.Add(-telemetry.SummaryRetention-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if got, err := telemetry.Prune(ctx, fixtureTelemetryRetention, now); err != nil || got.Summaries != 1 {
		t.Fatal("aggregate retention did not remove only expired hours", err, got)
	}
	verify()
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
	f.api.TelemetryEnabled = true
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
	if limited.Header().Get("Retry-After") == "" {
		t.Fatal("missing bounded upload retry advice")
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
