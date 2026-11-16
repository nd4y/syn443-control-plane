//go:build postgres

package catalog

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func reconcileHTTPProof(t *testing.T, f *adminFixture, raw []byte) string {
	t.Helper()
	b64 := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": identity.PublicJWK(&f.Key.PublicKey)})
	id, _ := random()
	claims, _ := json.Marshal(identity.ProofClaims{Jti: id, Htm: "POST", Htu: f.API.Origin + configurationReconcilePath, Iat: f.Now.Unix(), Ath: identity.Hash([]byte(adminToken)), RequestHash: identity.Hash(raw)})
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, f.Key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + b64.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func reconcileHTTPRequest(f *adminFixture, raw []byte, proof string) *http.Request {
	r := httptest.NewRequest("POST", f.API.Origin+configurationReconcilePath, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "DPoP "+adminToken)
	r.Header.Set("DPoP", proof)
	return r
}

func TestSQLConfigurationReconcileHttpBindsActualFixedUriBodyTokenKeyAndFreshProof(t *testing.T) {
	f := adminHTTPFixture(t)
	raw := []byte(`{"version":1,"requestId":"synthetic-recovery-request-0001","intent":"lookup","originalBody64":"e30"}`)
	calls := 0
	f.API.ConfigurationReconcile = func(ctx context.Context, token, proof string, body []byte, now time.Time) (any, error) {
		calls++
		if token != adminToken || !bytes.Equal(body, raw) || now != f.Now || ctx.Err() != nil {
			t.Fatal("unbound fixed callback")
		}
		return map[string]string{"outcome": "UNKNOWN"}, nil
	}
	good := reconcileHTTPProof(t, f, raw)
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, reconcileHTTPRequest(f, raw, good))
	if w.Code != 200 || calls != 1 {
		t.Fatal("fixed route did not dispatch", w.Code)
	}
	for _, proof := range []string{good, f.proof(t, raw), "invalid-proof"} {
		w = httptest.NewRecorder()
		f.API.ServeHTTP(w, reconcileHTTPRequest(f, raw, proof))
		if w.Code != 403 || calls != 1 {
			t.Fatal("proof replay/foreign path accepted", w.Code)
		}
	}
	w = httptest.NewRecorder()
	f.API.ServeHTTP(w, reconcileHTTPRequest(f, append(raw, ' '), reconcileHTTPProof(t, f, raw)))
	if w.Code != 403 || calls != 1 {
		t.Fatal("body substitution")
	}
}

func TestSQLConfigurationReconcileHttpHasItsOwnExact512KiBBoundWithoutOrdinaryRouteWidening(t *testing.T) {
	f := adminHTTPFixture(t)
	calls := 0
	f.API.ConfigurationReconcile = func(_ context.Context, _, _ string, raw []byte, _ time.Time) (any, error) {
		calls++
		if len(raw) != 524288 {
			t.Fatal("transport bound drift")
		}
		return map[string]string{"outcome": "UNKNOWN"}, nil
	}
	raw := append(bytes.Repeat([]byte{' '}, 524286), '{', '}')
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, reconcileHTTPRequest(f, raw, reconcileHTTPProof(t, f, raw)))
	if w.Code != 200 || calls != 1 {
		t.Fatal("exact route limit rejected", w.Code)
	}
	raw = append(raw, ' ')
	w = httptest.NewRecorder()
	f.API.ServeHTTP(w, reconcileHTTPRequest(f, raw, "not-consumed"))
	if w.Code != 400 || calls != 1 {
		t.Fatal("oversized transport dispatched", w.Code)
	}
	// A version-two source/catalog/invitation action is never enabled by this
	// configuration-only protocol extension.
	for _, a := range []string{"source.upload", "invite.create", "configuration.inventory.get"} {
		if controlActionVersion(2, a) {
			t.Fatal("v2 escaped fixed mutation family")
		}
	}
}

func TestSQLConfigurationReconcileHttpRejectsQueriesEncodedPathsOriginAndDuplicateHeaders(t *testing.T) {
	f := adminHTTPFixture(t)
	f.API.ConfigurationReconcile = func(context.Context, string, string, []byte, time.Time) (any, error) {
		t.Fatal("invalid route invoked callback")
		return nil, nil
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Method = "GET" }, func(r *http.Request) { r.URL.RawQuery = "x=1" }, func(r *http.Request) { r.URL.ForceQuery = true }, func(r *http.Request) { r.URL.RawPath = configurationReconcilePath }, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example.invalid") }, func(r *http.Request) { r.Header.Add("DPoP", "duplicate") }, func(r *http.Request) { r.Header.Add("Authorization", "DPoP foreign") }, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }} {
		r := reconcileHTTPRequest(f, []byte(`{}`), "not-a-proof")
		change(r)
		w := httptest.NewRecorder()
		f.API.ServeHTTP(w, r)
		if w.Code != 403 && w.Code != 404 {
			t.Fatal("weak route guard", w.Code)
		}
	}
}

func TestSQLConfigurationReconcileHttpReservesOneOfOriginalFourSlotsDuringThreeActualOrdinaryCallbacks(t *testing.T) {
	f := adminHTTPFixture(t)
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	f.API.Configurations = func(context.Context, string, string, []byte, time.Time) (any, error) {
		entered <- struct{}{}
		<-release
		return map[string]bool{"read": true}, nil
	}
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Error("ordinary callback owner did not exit")
		}
	})
	for i := 0; i < 3; i++ {
		raw, _ := json.Marshal(Action{Version: 1, Action: "configuration.inventory.get", RequestID: identity.Hash([]byte{byte(i)}), Payload: json.RawMessage(`{"id":"synthetic-device"}`)})
		r := f.request(raw, f.proof(t, raw))
		wg.Add(1)
		go func() { defer wg.Done(); f.API.ServeHTTP(httptest.NewRecorder(), r) }()
	}
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(8 * time.Second):
			t.Fatal("three actual ordinary owners missing")
		}
	}
	raw := []byte(`{}`)
	f.API.ConfigurationReconcile = func(context.Context, string, string, []byte, time.Time) (any, error) {
		return map[string]string{"outcome": "UNKNOWN"}, nil
	}
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, reconcileHTTPRequest(f, raw, reconcileHTTPProof(t, f, raw)))
	if w.Code != 200 {
		t.Fatal("recovery starved by ordinary slot debt", w.Code)
	}
	if len(f.API.slots) != 3 || len(f.API.normalSlots) != 3 || len(f.API.reconcileSlots) != 0 {
		t.Fatal("global four-slot ownership drift")
	}
}

func TestSQLConfigurationReconcileHttpCancellationRetainsDebtUntilActualCallbackExit(t *testing.T) {
	f := adminHTTPFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	f.API.ConfigurationReconcile = func(context.Context, string, string, []byte, time.Time) (any, error) {
		close(entered)
		<-release
		return map[string]string{"outcome": "UNKNOWN"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	raw := []byte(`{}`)
	r := reconcileHTTPRequest(f, raw, reconcileHTTPProof(t, f, raw)).WithContext(ctx)
	go func() { defer close(done); f.API.ServeHTTP(httptest.NewRecorder(), r) }()
	t.Cleanup(func() {
		cancel()
		once.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Error("actual reconcile owner did not exit")
		}
	})
	select {
	case <-entered:
	case <-time.After(8 * time.Second):
		t.Fatal("missing actual held reconcile callback")
	}
	cancel()
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, reconcileHTTPRequest(f, raw, reconcileHTTPProof(t, f, raw)))
	if w.Code != 503 || len(f.API.slots) != 1 || len(f.API.reconcileSlots) != 1 {
		t.Fatal("cancellation released unknown owner")
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("callback exit not confirmed")
	}
	if len(f.API.slots) != 0 || len(f.API.reconcileSlots) != 0 {
		t.Fatal("completed callback retained slot")
	}
}
