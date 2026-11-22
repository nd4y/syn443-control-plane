//go:build postgres

package enrollment

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func TestStandaloneTelemetryProcessReceivesBoundEvents(t *testing.T) {
	exerciseStandaloneTelemetry(t, "")
}

func TestPackagedTelemetryProcessReceivesBoundEvents(t *testing.T) {
	image := os.Getenv("SYN443_TEST_TELEMETRY_IMAGE")
	if image == "" {
		t.Skip("packaged telemetry image is required by the release workflow")
	}
	exerciseStandaloneTelemetry(t, image)
}

func exerciseStandaloneTelemetry(t *testing.T, image string) {
	t.Helper()
	f := newFixture(t, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	f.origin = "http://" + addr
	f.api.Origin = f.origin
	f.api.ExternalTelemetry = true
	f.api.Clock = func() time.Time { return f.now }
	k := key(t)
	s, _, _ := f.register(t, k)
	if err := f.publisher().RunOnce(t.Context(), f.now); err != nil {
		t.Fatal(err)
	}
	policy := f.call(t, k, http.MethodGet, "/v1/device/policy", s.AccessToken, s.Nonce, nil)
	expect(t, policy, http.StatusOK)
	if policy.Header().Get("X-SYN443-Telemetry") != "1" {
		t.Fatal("external public route not advertised")
	}
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 65, AlgorithmRevision: 1,
		Events: []telemetry.Event{{ID: random(), AtMS: f.now.UnixMilli(), Kind: "vpn", Code: "online", Mode: "wifi"}}}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(t, k, http.MethodPost, telemetryPath, s.AccessToken, s.Nonce, raw), http.StatusNotFound)
	dir := t.TempDir()
	dsn, config := filepath.Join(dir, "database"), filepath.Join(dir, "ingest.json")
	if err := os.WriteFile(dsn, []byte(fixtureIngestDSN), 0600); err != nil {
		t.Fatal(err)
	}
	dbPath := dsn
	if image != "" {
		dbPath = "/run/syn443/telemetry/database"
	}
	privateJSON(t, config, map[string]any{"databaseFile": dbPath, "listen": addr, "origin": f.origin, "fixtureHttp": true})
	client := &http.Client{Timeout: 2 * time.Second}
	start := func() func() {
		t.Helper()
		var stop func()
		if image == "" {
			stop, _ = startProcess(t, "telemetry-ingest", []string{"SYN443_TELEMETRY_CONFIG=" + config})
		} else {
			stop = startTelemetryImage(t, image, config, dsn)
		}
		deadline := time.Now().Add(6 * time.Second)
		for {
			r, err := client.Get(f.origin + "/readyz")
			if err == nil {
				r.Body.Close()
				if r.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("standalone process did not become ready")
			}
			time.Sleep(20 * time.Millisecond)
		}
		return stop
	}
	stop := start()
	defer func() { stop() }()
	for _, path := range []string{"/v1/device/policy", "/v1/device/session/refresh", "/v1/devices/enroll", "/v1/control", "/v1/device/telemetry?extra=1"} {
		r, err := client.Post(f.origin+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Fatal("unexpected route on ingestion-only process", path)
		}
	}
	request := func(payload []byte, proof string) *http.Request {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.origin+telemetryPath, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+s.AccessToken)
		req.Header.Set("DPoP", proof)
		return req
	}
	send := func(payload []byte, proof string, want int) []byte {
		t.Helper()
		res, err := client.Do(request(payload, proof))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(io.LimitReader(res.Body, 2048))
		if err != nil || res.StatusCode != want {
			t.Fatal("standalone device response", res.StatusCode, want, err)
		}
		return data
	}
	proof := func(payload []byte) string {
		return signed(t, k, http.MethodPost, f.origin+telemetryPath, s.AccessToken, s.Nonce, payload, f.now)
	}
	first := proof(raw)
	var receipt telemetry.Receipt
	if err := json.Unmarshal(send(raw, first, http.StatusOK), &receipt); err != nil || len(receipt.EventIDs) != 1 || receipt.EventIDs[0] != batch.Events[0].ID {
		t.Fatal("missing durable receipt", err)
	}
	send(raw, first, http.StatusUnauthorized)
	send(raw, proof(raw), http.StatusOK)
	var stored int
	if err := fixtureOwner.QueryRow("SELECT count(*) FROM identity_telemetry_events WHERE device=$1 AND event_id=$2", s.DeviceID, batch.Events[0].ID).Scan(&stored); err != nil || stored != 1 {
		t.Fatal("event was not durably deduplicated", err)
	}
	t.Run("unread_receipt_survives_restart_and_newer_batch", func(t *testing.T) {
		old := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 64, PolicyRevision: 3, AlgorithmRevision: 1}
		for i := range 2 {
			old.Events = append(old.Events, telemetry.Event{ID: random(), AtMS: f.now.Add(-time.Duration(i+1) * time.Minute).UnixMilli(),
				ElapsedMS: int64(2000 - i*1000), NetworkEpoch: 1, Kind: "vpn", Code: "online", Mode: "wifi"})
		}
		encode := func(batch telemetry.Batch) []byte {
			t.Helper()
			body, err := json.Marshal(batch)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
		body := encode(old)
		// Do not read the socket: no HTTP status or receipt reaches this client.
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := request(body, proof(body)).Write(conn); err != nil {
			t.Fatal(err)
		}
		var received int64
		deadline := time.Now().Add(5 * time.Second)
		for received == 0 {
			var count int
			err := fixtureOwner.QueryRowContext(t.Context(), `SELECT count(*), COALESCE(MIN(received_at_ms),0)
 FROM identity_telemetry_events WHERE device=$1 AND session_id=$2`, s.DeviceID, old.Session).Scan(&count, &received)
			if err != nil || count != 0 && count != len(old.Events) {
				t.Fatal("partial or unreadable telemetry commit", count, err)
			}
			if received == 0 {
				if time.Now().After(deadline) {
					t.Fatal("the request never committed before disconnect")
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		stop()
		// Advance the authoritative identity floor through its normal signed API.
		// A later replay that overwrites the receipt time must be observable.
		f.now = time.UnixMilli(received).UTC().Add(3 * time.Second)
		expect(t, f.call(t, k, http.MethodGet, "/v1/device/policy", s.AccessToken, s.Nonce, nil), http.StatusOK)
		stop = start()
		wantReceipt := func(batch telemetry.Batch, body []byte) {
			t.Helper()
			var ack telemetry.Receipt
			if err := json.Unmarshal(send(body, proof(body), http.StatusOK), &ack); err != nil || ack.SchemaVersion != 1 || len(ack.EventIDs) != len(batch.Events) {
				t.Fatal("missing committed receipt after restart", err)
			}
			for i, event := range batch.Events {
				if ack.EventIDs[i] != event.ID {
					t.Fatal("receipt changed the submitted event order")
				}
			}
		}
		recent := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 65, PolicyRevision: 4, AlgorithmRevision: 2,
			Events: []telemetry.Event{{ID: random(), AtMS: f.now.UnixMilli(), ElapsedMS: 3000, NetworkEpoch: 2, Kind: "vpn", Code: "online", Mode: "wifi"}}}
		wantReceipt(recent, encode(recent))
		wantReceipt(old, body)
		var distinct int
		var latest int64
		err = fixtureOwner.QueryRowContext(t.Context(), `SELECT count(*),MAX(received_at_ms) FROM identity_telemetry_events
 WHERE device=$1 AND session_id IN ($2,$3)`, s.DeviceID, old.Session, recent.Session).Scan(&distinct, &latest)
		if err != nil || distinct != 3 || latest <= received {
			t.Fatal("replay duplicated a row or failed to cross a receipt-time boundary", distinct, err)
		}
		for _, e := range old.Events {
			var matches bool
			err := fixtureOwner.QueryRowContext(t.Context(), `SELECT session_id=$3 AND build=$4 AND policy_revision=$5 AND algorithm_revision=$6
 AND received_at_ms=$7 AND observed_at_ms=$8 AND elapsed_ms=$9 AND network_epoch=$10
 FROM identity_telemetry_events WHERE device=$1 AND event_id=$2`, s.DeviceID, e.ID, old.Session, old.Build, old.PolicyRevision,
				old.AlgorithmRevision, received, e.AtMS, e.ElapsedMS, e.NetworkEpoch).Scan(&matches)
			if err != nil || !matches {
				t.Fatal("replay changed a committed observation", err)
			}
		}
	})
	f.enableTelemetry(t)
	expect(t, f.rawCall(http.MethodPost, telemetryPath, s.AccessToken, first, raw), http.StatusUnauthorized)
	fromIntegrated := proof(raw)
	expect(t, f.rawCall(http.MethodPost, telemetryPath, s.AccessToken, fromIntegrated, raw), http.StatusOK)
	send(raw, fromIntegrated, http.StatusUnauthorized)
	if _, err := fixtureOwner.Exec("UPDATE identity_accounts SET enabled=false"); err != nil {
		t.Fatal(err)
	}
	send(raw, proof(raw), http.StatusForbidden)
	stop()
	if _, err := fixtureOwner.Exec("UPDATE identity_accounts SET enabled=true"); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(t, k, http.MethodGet, "/v1/device/policy", s.AccessToken, s.Nonce, nil), http.StatusOK)
}

func TestStandaloneTelemetryRejectsPrivilegeDrift(t *testing.T) {
	newFixture(t, 1)
	ctx := t.Context()
	if service, err := OpenStandaloneIngest(ctx, fixtureAPIDSN, "https://api.example.invalid", false); err == nil {
		service.Close()
		t.Fatal("enrollment role accepted by standalone ingest")
	}
	service, err := OpenStandaloneIngest(ctx, fixtureIngestDSN, "https://api.example.invalid", false)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	for _, statement := range []string{
		"SELECT issuer,subject FROM identity_accounts LIMIT 0",
		"SELECT publication FROM identity_devices LIMIT 0", "SELECT refresh_hash FROM identity_sessions LIMIT 0",
		"UPDATE identity_devices SET active=false WHERE false", "UPDATE identity_sessions SET active=false WHERE false",
		"DELETE FROM identity_replays WHERE false", "SELECT code FROM identity_telemetry_events LIMIT 0",
		"UPDATE identity_clock SET second=0 WHERE false",
	} {
		if _, err := fixtureIngest.ExecContext(ctx, statement); err == nil {
			t.Fatal("unexpected SQL permission")
		}
	}
	if _, err := fixtureOwner.ExecContext(ctx, "GRANT SELECT(subject) ON identity_accounts TO syn443_telemetry_ingest"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := fixtureOwner.Exec("REVOKE SELECT(subject) ON identity_accounts FROM syn443_telemetry_ingest"); err != nil {
			t.Error(err)
		}
	}()
	if service.Ready(ctx) == nil {
		t.Fatal("reader accepted broader authority")
	}
}
