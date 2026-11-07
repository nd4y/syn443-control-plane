//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

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
	expect(t, f.call(t, deviceKey, "POST", telemetryPath, first.AccessToken, first.Nonce, body), http.StatusNoContent)
	expect(t, f.call(t, deviceKey, "POST", telemetryPath, first.AccessToken, first.Nonce, body), http.StatusNoContent)
	wrongScope := f.call(t, otherKey, "POST", telemetryPath, first.AccessToken, first.Nonce, body)
	if wrongScope.Code != http.StatusUnauthorized && wrongScope.Code != http.StatusForbidden {
		t.Fatal("another device used the session to submit telemetry", wrongScope.Code)
	}
	private := bytes.Replace(body, []byte(`"mode":"wifi"`), []byte(`"mode":"wifi","address":"node.example.invalid"`), 1)
	expect(t, f.call(t, deviceKey, "POST", telemetryPath, first.AccessToken, first.Nonce, private), http.StatusUnauthorized)
	expect(t, f.call(t, otherKey, "POST", telemetryPath, second.AccessToken, second.Nonce, body), http.StatusNoContent)
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
