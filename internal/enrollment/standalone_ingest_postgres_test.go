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
	var stop func()
	if image == "" {
		stop, _ = startProcess(t, "telemetry-ingest", []string{"SYN443_TELEMETRY_CONFIG=" + config})
	} else {
		stop = startTelemetryImage(t, image, config, dsn)
	}
	defer stop()
	client := &http.Client{Timeout: 2 * time.Second}
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
	send := func(proof string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.origin+telemetryPath, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+s.AccessToken)
		req.Header.Set("DPoP", proof)
		res, err := client.Do(req)
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
	proof := func() string {
		return signed(t, k, http.MethodPost, f.origin+telemetryPath, s.AccessToken, s.Nonce, raw, f.now)
	}
	first := proof()
	var receipt telemetry.Receipt
	if err := json.Unmarshal(send(first, http.StatusOK), &receipt); err != nil || len(receipt.EventIDs) != 1 || receipt.EventIDs[0] != batch.Events[0].ID {
		t.Fatal("missing durable receipt", err)
	}
	send(first, http.StatusUnauthorized)
	send(proof(), http.StatusOK)
	var stored int
	if err := fixtureOwner.QueryRow("SELECT count(*) FROM identity_telemetry_events WHERE device=$1 AND event_id=$2", s.DeviceID, batch.Events[0].ID).Scan(&stored); err != nil || stored != 1 {
		t.Fatal("event was not durably deduplicated", err)
	}
	f.enableTelemetry(t)
	expect(t, f.rawCall(http.MethodPost, telemetryPath, s.AccessToken, first, raw), http.StatusUnauthorized)
	fromIntegrated := proof()
	expect(t, f.rawCall(http.MethodPost, telemetryPath, s.AccessToken, fromIntegrated, raw), http.StatusOK)
	send(fromIntegrated, http.StatusUnauthorized)
	if _, err := fixtureOwner.Exec("UPDATE identity_accounts SET enabled=false"); err != nil {
		t.Fatal(err)
	}
	send(proof(), http.StatusForbidden)
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
