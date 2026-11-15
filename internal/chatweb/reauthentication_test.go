package chatweb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func reauthenticationFixture(t *testing.T) (*Server, *http.Cookie, *identity.Principal) {
	t.Helper()
	s, _, p := webFixture(t)
	s.config.ControlConsole = true
	s.config.ReauthenticationACR = "urn:syn443:loa:2"
	p.Scope = "syn443.control"
	p.Expires = time.Now().Unix() + 300
	p.AuthTime = time.Now().Unix() - 3600
	p.ACR = "0"
	return s, loginWeb(t, s), p
}

func reauthenticationStart(t *testing.T, s *Server, cookie *http.Cookie) (*url.URL, *http.Cookie) {
	t.Helper()
	w := webCall(s, "/reauth", `{"device":"device-a"}`, cookie)
	if w.Code != 200 {
		t.Fatal("reauthentication start", w.Code)
	}
	var link map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &link); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(link["url"])
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("acr_values") != s.config.ReauthenticationACR || q.Get("scope") != "openid syn443.control" || q.Get("code_challenge_method") != "S256" || q.Get("dpop_jkt") == "" || q.Get("redirect_uri") != s.config.Origin+"/callback" {
		t.Fatal("reauthentication must require the pinned fresh assurance and PKCE/DPoP")
	}
	return u, w.Result().Cookies()[0]
}

func reauthenticationCallback(s *Server, u *url.URL, loginCookie, parentCookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/callback?"+url.Values{"code": {"synthetic-reauth-code"}, "state": {u.Query().Get("state")}, "iss": {s.config.Issuer}}.Encode(), nil)
	r.AddCookie(loginCookie)
	if parentCookie != nil {
		r.AddCookie(parentCookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func strongAuthentication(p *identity.Principal) {
	p.ACR = "urn:syn443:loa:2"
	p.AuthTime = time.Now().Unix()
	p.Methods = []string{"otp"}
	p.Expires = time.Now().Unix() + 300
}

func TestControlReauthenticationBindsTheExistingOwnerAndReplacesOnlyItsSession(t *testing.T) {
	s, old, p := reauthenticationFixture(t)
	before := webCall(s, "/session", "{}", old)
	if before.Code != 200 || !strings.Contains(before.Body.String(), `"reauthenticationFresh":false`) {
		t.Fatal("shared SSO is not fresh MFA")
	}
	u, loginCookie := reauthenticationStart(t, s, old)
	strongAuthentication(p)
	w := reauthenticationCallback(s, u, loginCookie, old)
	if w.Code != 303 || w.Header().Get("Location") != "/#device=device-a" {
		t.Fatal("reauthentication callback", w.Code)
	}
	var current *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cookieName(false) {
			current = c
		}
	}
	if current == nil || current.Value == old.Value || !current.HttpOnly || current.SameSite != http.SameSiteLaxMode {
		t.Fatal("session cookie not rotated safely")
	}
	if webCall(s, "/session", "{}", old).Code != 401 {
		t.Fatal("previous session survived replacement")
	}
	w = webCall(s, "/session", "{}", current)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"reauthenticationFresh":true`) || !strings.Contains(w.Body.String(), `"reauthenticationIssuer"`) {
		t.Fatal("fresh signed assurance not reported")
	}
	if reauthenticationCallback(s, u, loginCookie, current).Code != 401 {
		t.Fatal("one-use callback was replayed")
	}
}

func TestControlReauthenticationRejectsWrongOwnerMissingParentAndInsufficientAssurance(t *testing.T) {
	for _, kind := range []string{"owner", "missing-parent", "no-method", "wrong-acr", "stale", "expired-pending"} {
		t.Run(kind, func(t *testing.T) {
			s, old, p := reauthenticationFixture(t)
			u, loginCookie := reauthenticationStart(t, s, old)
			strongAuthentication(p)
			parent := old
			switch kind {
			case "owner":
				p.Subject = "another-admin"
			case "missing-parent":
				parent = nil
			case "no-method":
				p.Methods = nil
			case "wrong-acr":
				p.ACR = "0"
			case "stale":
				p.AuthTime = time.Now().Unix() - 601
			case "expired-pending":
				pending := s.pending[u.Query().Get("state")]
				pending.expires = s.clock().Add(-time.Second)
				s.pending[u.Query().Get("state")] = pending
			}
			if w := reauthenticationCallback(s, u, loginCookie, parent); w.Code != 401 {
				t.Fatal("unauthorized reauthentication accepted", w.Code)
			}
			if webCall(s, "/session", "{}", old).Code != 200 {
				t.Fatal("a rejected new login destroyed the existing session")
			}
			if len(s.sessions) != 1 {
				t.Fatal("failed callback created a session")
			}
		})
	}
}

type reauthenticationTransport func(*http.Request) (*http.Response, error)

func (f reauthenticationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestControlReauthenticationCannotResurrectALoggedOutSessionAfterTokenExchange(t *testing.T) {
	s, old, p := reauthenticationFixture(t)
	u, loginCookie := reauthenticationStart(t, s, old)
	strongAuthentication(p)
	base := s.client.Transport
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.client.Transport = reauthenticationTransport(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return base.RoundTrip(r)
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- reauthenticationCallback(s, u, loginCookie, old) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("token exchange did not start")
	}
	if webCall(s, "/logout", "{}", old).Code != 200 {
		t.Fatal("logout failed")
	}
	unblock()
	select {
	case w := <-done:
		if w.Code != 401 {
			t.Fatal("logout lost to an older callback", w.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback did not finish")
	}
	if len(s.sessions) != 0 {
		t.Fatal("logged-out session was resurrected")
	}
}

func TestControlReauthenticationPreservesOriginBoundsAndConfiguredCapability(t *testing.T) {
	s, cookie, _ := reauthenticationFixture(t)
	for _, body := range []string{`{"scope":"admin"}`, `{"device":"../wrong"}`, `{"device":null}`, strings.Repeat("x", 513)} {
		if w := webCall(s, "/reauth", body, cookie); w.Code != 400 {
			t.Fatal("untrusted reauthentication input", w.Code)
		}
	}
	for _, path := range []string{"/reauth?scope=admin", "/reauth/"} {
		w := webCall(s, path, "{}", cookie)
		if w.Code == 200 {
			t.Fatal("arbitrary reauthentication route accepted")
		}
	}
	r := httptest.NewRequest("POST", "/reauth", strings.NewReader("{}"))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://other.example.invalid")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Syn443-CSRF", "1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin reauthentication")
	}
	s.config.ReauthenticationACR = ""
	if webCall(s, "/reauth", "{}", cookie).Code != 404 {
		t.Fatal("unconfigured assurance was used")
	}
	w = webCall(s, "/session", "{}", cookie)
	if strings.Contains(w.Body.String(), "reauthentication") {
		t.Fatal("unconfigured capability was advertised")
	}
	for _, acr := range []string{"two values", "\n", strings.Repeat("a", 129)} {
		c := s.config
		c.ReauthenticationACR = acr
		if _, e := New(context.Background(), c, nil); e == nil {
			t.Fatal("invalid assurance configuration")
		}
	}
}

func TestControlReauthenticationSessionMetadataIsBoundedBySessionGateAndLogout(t *testing.T) {
	s, cookie, _ := reauthenticationFixture(t)
	v := s.sessions[cookie.Value]
	v.gate <- struct{}{}
	r := httptest.NewRequest("POST", "/session", strings.NewReader("{}"))
	r.AddCookie(cookie)
	r.Header.Set("Origin", s.config.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Syn443-CSRF", "1")
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("cancelled metadata wait was not bounded")
	}
	<-v.gate
	v.cancel()
	if webCall(s, "/session", "{}", cookie).Code != 401 {
		t.Fatal("cancelled session retained metadata")
	}
}

func TestOnlyClosedScopedAssuranceDenialsPreserveTheConsoleSession(t *testing.T) {
	s, cookie, _ := reauthenticationFixture(t)
	for _, body := range []string{`{"code":"catalog_reauthentication_required"}`, `{"code":"catalog_denied"}`, `{"code":"catalog_reauthentication_required","extra":"synthetic-untrusted"}`, `{"code":"catalog_reauthentication_required","code":"catalog_reauthentication_required"}`} {
		s.client.Transport = reauthenticationTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		w := webCall(s, "/control/action", `{"version":1,"action":"source.list","requestId":"synthetic-request-123","payload":{}}`, cookie)
		if w.Code != 403 {
			t.Fatal("assurance denial became success", w.Code)
		}
		want := body == `{"code":"catalog_reauthentication_required"}`
		if strings.Contains(w.Body.String(), "catalog_reauthentication_required") != want || want && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatal("untrusted error body was forwarded")
		}
	}
}
