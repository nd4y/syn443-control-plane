//go:build postgres

package enrollment

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

func (f *fixture) enableTelemetry(t *testing.T) {
	t.Helper()
	store, err := OpenTelemetryStore(t.Context(), Config{
		Database: fixtureAPIDSN, EncryptionKey: base64.StdEncoding.EncodeToString(f.encryption),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	f.api.TelemetryStore = store
}

func TestTelemetryPressurePreservesPolicyAndRefresh(t *testing.T) {
	f := newFixture(t, 1)
	f.enableTelemetry(t)
	userKey := key(t)
	session, _, _ := f.register(t, userKey)
	if err := f.publisher().RunOnce(t.Context(), f.now); err != nil {
		t.Fatal(err)
	}
	batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 51, AlgorithmRevision: 1,
		Events: []telemetry.Event{{ID: random(), AtMS: f.now.UnixMilli(), Kind: "vpn", Code: "online", Mode: "wifi"}}}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	uploads := f.api.TelemetryStore.DB
	if uploads == f.api.Store.DB || uploads.Stats().MaxOpenConnections != 2 {
		t.Fatal("upload pool must be separate and bounded")
	}
	var held []*sql.Conn
	defer func() {
		for _, conn := range held {
			conn.Close()
		}
	}()
	for range uploads.Stats().MaxOpenConnections {
		conn, err := uploads.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	// Wait for actual signed requests to reach the exhausted upload pool.
	// An additional upload must receive backpressure before it queues for SQL.
	waited := uploads.Stats().WaitCount
	replies := make(chan *httptest.ResponseRecorder, len(held))
	for range held {
		proof := signed(t, userKey, http.MethodPost, f.origin+telemetryPath, session.AccessToken, session.Nonce, body, f.now)
		go func() { replies <- f.rawCall(http.MethodPost, telemetryPath, session.AccessToken, proof, body) }()
	}
	deadline := time.Now().Add(4 * time.Second)
	for uploads.Stats().WaitCount-waited < int64(len(held)) {
		if time.Now().After(deadline) {
			t.Fatal("uploads did not reach their isolated database pool")
		}
		time.Sleep(5 * time.Millisecond)
	}
	limited := f.call(t, userKey, http.MethodPost, telemetryPath, session.AccessToken, session.Nonce, body)
	expect(t, limited, http.StatusServiceUnavailable)
	if limited.Header().Get("Retry-After") == "" || uploads.Stats().WaitCount-waited != int64(len(held)) {
		t.Fatal("overload must be retryable before opening another database request")
	}
	published := f.call(t, userKey, http.MethodGet, "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, published, http.StatusOK)
	if published.Header().Get("Content-Type") != "application/jose" || published.Header().Get("X-SYN443-Telemetry") != "1" {
		t.Fatal("signed policy or upload capability missing")
	}
	refreshBody, _ := json.Marshal(map[string]string{"requestId": random()})
	refreshed := f.call(t, userKey, http.MethodPost, "/v1/device/session/refresh", session.RefreshToken, session.Nonce, refreshBody)
	expect(t, refreshed, http.StatusOK)
	var next Session
	if err := json.Unmarshal(refreshed.Body.Bytes(), &next); err != nil || next.DeviceID != session.DeviceID || next.Generation != session.Generation+1 {
		t.Fatal("session did not rotate for the same device", err)
	}
	for _, conn := range held {
		conn.Close()
	}
	held = nil
	for range cap(replies) {
		select {
		case response := <-replies:
			expect(t, response, http.StatusForbidden)
		case <-time.After(5 * time.Second):
			t.Fatal("queued request did not recheck its rotated session")
		}
	}
	var stored int
	count := func() int {
		t.Helper()
		if err := fixtureOwner.QueryRow("SELECT count(*) FROM identity_telemetry_events WHERE event_id=$1", batch.Events[0].ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		return stored
	}
	if count() != 0 {
		t.Fatal("stale requests committed an event")
	}
	for range 2 {
		accepted := f.call(t, userKey, http.MethodPost, telemetryPath, next.AccessToken, next.Nonce, body)
		expect(t, accepted, http.StatusOK)
		var receipt telemetry.Receipt
		if err := json.Unmarshal(accepted.Body.Bytes(), &receipt); err != nil || len(receipt.EventIDs) != 1 || receipt.EventIDs[0] != batch.Events[0].ID || count() != 1 {
			t.Fatal("retry did not acknowledge the committed event exactly once", err)
		}
	}
}

func TestTelemetryAddressBudgetLeavesPolicyAccessible(t *testing.T) {
	f := newFixture(t, 1)
	f.enableTelemetry(t)
	f.api.Clock = func() time.Time { return f.now }
	k := key(t)
	s, _, _ := f.register(t, k)
	if err := f.publisher().RunOnce(t.Context(), f.now); err != nil {
		t.Fatal(err)
	}
	// The transport peer can be a shared gateway. Malformed uploads still
	// consume their own pre-authentication budget.
	for range 120 {
		expect(t, f.rawCall(http.MethodPost, telemetryPath, "", "", nil), http.StatusUnauthorized)
	}
	limited := f.rawCall(http.MethodPost, telemetryPath, "", "", nil)
	expect(t, limited, http.StatusTooManyRequests)
	if limited.Header().Get("Retry-After") != "60" {
		t.Fatal("missing address-window retry")
	}
	expect(t, f.call(t, k, http.MethodGet, "/v1/device/policy", s.AccessToken, s.Nonce, nil), http.StatusOK)
	f.now = f.now.Add(time.Minute)
	expect(t, f.rawCall(http.MethodPost, telemetryPath, "", "", nil), http.StatusUnauthorized)
}
