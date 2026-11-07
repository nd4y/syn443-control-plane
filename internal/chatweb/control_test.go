package chatweb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestConsoleSourceMutationsRemainInTheClosedActionAllowlist(t *testing.T) {
	for _, action := range []string{"source.put", "source.sync", "source.shares.put", "job.get", "job.list", "configuration.preview.request", "configuration.publish", "configuration.request.get", "configuration.inventory.get", "configuration.layers.draft.get", "configuration.layers.draft.put", "configuration.layers.drafts.list", "configuration.layers.draft.discard", "configuration.history.get"} {
		raw := []byte(`{"version":1,"action":"` + action + `","requestId":"synthetic-request-123","payload":{}}`)
		if !validConsoleAction(raw, false) {
			t.Fatal("implemented scoped source action rejected")
		}
	}
	for _, action := range []string{"source.delete", "configuration.force-apply", "resource.delete", "users.grant", "/v1/admin"} {
		raw := []byte(`{"version":1,"action":"` + action + `","requestId":"synthetic-request-123","payload":{}}`)
		if validConsoleAction(raw, false) {
			t.Fatal("unimplemented or arbitrary upstream action admitted")
		}
	}
}

type consoleTransportFunc func(*http.Request) (*http.Response, error)

func (f consoleTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConsoleUsesSeparateCookieAudienceAndOnlyClosedControlActions(t *testing.T) {
	s, _, principal := webFixture(t)
	s.config.ControlConsole = true
	principal.Scope = "syn443.control"
	underlying := s.client.Transport
	var mu sync.Mutex
	var forwarded []string
	s.client.Transport = consoleTransportFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			mu.Lock()
			forwarded = append(forwarded, r.URL.Path)
			mu.Unlock()
		}
		return underlying.RoundTrip(r)
	})
	cookie := loginWeb(t, s)
	if cookie.Name != "syn443-control" {
		t.Fatal("support/control cookie collision")
	}
	body := `{"version":1,"action":"source.list","requestId":"synthetic-request-123","payload":{"owner":"synthetic-user","after":""}}`
	if w := webCall(s, "/control/action", body, cookie); w.Code != 200 {
		t.Fatal("control forwarding", w.Code)
	}
	mu.Lock()
	if len(forwarded) != 2 || forwarded[0] != "/v1/control/action" || forwarded[1] != "/v1/control/action" {
		t.Fatal("proxy URI/nonce retry changed authority")
	}
	mu.Unlock()
	history := `{"version":1,"action":"job.list","requestId":"synthetic-history-request","payload":{"sourceId":"source-a","after":""}}`
	if w := webCall(s, "/control/action", history, cookie); w.Code != 200 {
		t.Fatal("scoped job history did not reach the control API", w.Code)
	}
	report := `{"version":1,"action":"telemetry.summary.get","requestId":"synthetic-report-request","payload":{"hour":"2026-01-02T01:00Z"}}`
	if w := webCall(s, "/control/action", report, cookie); w.Code != 200 {
		t.Fatal("scoped telemetry report did not reach the control API", w.Code)
	}
	shares := `{"version":1,"action":"source.shares.put","requestId":"synthetic-share-request","payload":{"id":"source-a","revision":1,"shares":{"revision":0,"recipients":[]}}}`
	if w := webCall(s, "/control/action", shares, cookie); w.Code != 200 {
		t.Fatal("source recipient mutation did not reach the control API", w.Code)
	}
	request := httptest.NewRequest("POST", "/control/action", strings.NewReader(body))
	request.AddCookie(cookie)
	blocked := httptest.NewRecorder()
	s.ServeHTTP(blocked, request)
	if blocked.Code != 403 {
		t.Fatal("console bypassed CSRF")
	}
	if w := webCall(s, "/chat/self", `{}`, cookie); w.Code != 404 {
		t.Fatal("control token reached chat", w.Code)
	}
	for _, bad := range []string{
		strings.Replace(body, "source.list", "source.delete", 1),
		strings.Replace(body, "source.list", "configuration.force-apply", 1),
		strings.Replace(body, `"version":1`, `"version":2`, 1),
		strings.Replace(body, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(body, `"requestId":"synthetic-request-123"`, `"requestId":"short"`, 1),
		strings.Replace(body, `"payload":`, `"unknown":true,"payload":`, 1),
	} {
		if w := webCall(s, "/control/action", bad, cookie); w.Code != 400 {
			t.Fatal("open control envelope", w.Code)
		}
	}
	if w := webCall(s, "/control/action", strings.Repeat("x", 278529), cookie); w.Code != 413 {
		t.Fatal("console body bound", w.Code)
	}
	principal.Scope = "syn443.chat"
	for _, session := range s.sessions {
		session.accessUntil = s.clock()
	}
	if w := webCall(s, "/control/action", body, cookie); w.Code != 401 {
		t.Fatal("refresh crossed administrative scope", w.Code)
	}
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("console asset boundary", path, w.Code)
		}
	}
	if strings.Contains(s.cookieName(true), "admin") {
		t.Fatal("login cookie collision")
	}
}

func TestConsoleMissingScopeCannotCreateSessionAndSupportCannotProxyControl(t *testing.T) {
	s, _, _ := webFixture(t)
	s.config.ControlConsole = true
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.token(context.Background(), &session{key: key}, nil); e == nil {
		t.Fatal("support token created administrative session")
	}
	s.config.ControlConsole = false
	cookie := loginWeb(t, s)
	if w := webCall(s, "/control/action", `{}`, cookie); w.Code != 404 {
		t.Fatal("support BFF reached control API", w.Code)
	}
	for _, action := range []string{"source.list", "source.get", "source.snapshot", "source.shares.get", "resource.get", "configuration.draft.get", "configuration.draft.put"} {
		raw := []byte(`{"version":1,"action":"` + action + `","requestId":"synthetic-request-123","payload":{}}`)
		if !validConsoleAction(raw, false) {
			t.Fatal("implemented action unavailable", action)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, request)
	data, _ := io.ReadAll(w.Result().Body)
	if strings.Contains(string(data), "configuration.draft.put") {
		t.Fatal("support served console assets")
	}
}

func TestManualSourceImportUsesSeparateBoundAndExactControlBody(t *testing.T) {
	s, _, principal := webFixture(t)
	s.config.ControlConsole = true
	principal.Scope = "syn443.control"
	const path = "/control/source/import"
	raw := `{"version":1,"action":"source.import","requestId":"synthetic-import-request","payload":{"id":"source-a","revision":1,"data":"` +
		strings.Repeat("YWFh", 72000) + `"}}`
	upstream := s.client.Transport
	var forwarded int
	s.client.Transport = consoleTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/control/action" {
			return upstream.RoundTrip(r)
		}
		body, e := io.ReadAll(r.Body)
		if e != nil || string(body) != raw || r.Header.Get("DPoP") == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "DPoP ") {
			t.Fatal("import reached upstream without its exact body or bound authority")
		}
		forwarded++
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"id":"synthetic-import-job","sourceId":"source-a","phase":"queued"}`))}, nil
	})
	cookie := loginWeb(t, s)
	if w := webCall(s, "/control/action", raw, cookie); w.Code != 413 {
		t.Fatal("ordinary action admitted the large upload", w.Code)
	}
	if w := webCall(s, path, strings.Replace(raw, "source.import", "source.put", 1), cookie); w.Code != 400 {
		t.Fatal("import endpoint admitted another action", w.Code)
	}
	s.sourceImports <- struct{}{}
	if w := webCall(s, path, raw, cookie); w.Code != 503 {
		t.Fatal("concurrent source import exceeded its slot budget", w.Code)
	}
	<-s.sourceImports
	if w := webCall(s, path, raw, cookie); w.Code != 200 || forwarded != 1 {
		t.Fatal("valid source import did not reach its existing job API", w.Code)
	}
}
