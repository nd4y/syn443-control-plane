package chatweb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type verifyFunc func(context.Context, string, time.Time) (identity.Principal, error)

func (f verifyFunc) Verify(c context.Context, t string, n time.Time) (identity.Principal, error) {
	return f(c, t, n)
}
func webFixture(t *testing.T) (*Server, *httptest.Server, *identity.Principal) {
	t.Helper()
	p := &identity.Principal{Issuer: "https://id.example.invalid/realms/test", Subject: "test-admin"}
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protocol/openid-connect/token" {
			proof, e := identity.VerifyProof(r.Header.Get("DPoP"), identity.ProofContext{Method: "POST", URI: issuer.URL + r.URL.Path, Now: time.Now()})
			if e != nil {
				t.Error("token proof")
				w.WriteHeader(400)
				return
			}
			p.Thumbprint = proof.Thumbprint
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"DPoP","expires_in":300}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		proof, e := identity.RequestProof(r.Header.Get("DPoP"), identity.ProofContext{Method: "POST", URI: issuer.URL + r.URL.Path, Token: "synthetic-access", BodyHash: identity.Hash(raw), Now: time.Now()})
		if e != nil || proof.Thumbprint != p.Thumbprint {
			t.Error("API proof")
			w.WriteHeader(400)
			return
		}
		if proof.Claims.Nonce == "" {
			w.Header().Set("DPoP-Nonce", "fixture-nonce")
			w.WriteHeader(401)
			io.WriteString(w, `{"code":"use_dpop_nonce"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"admin":true,"conversation":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	}))
	t.Cleanup(issuer.Close)
	c := Config{Origin: "https://web.example.invalid", APIOrigin: issuer.URL, Issuer: issuer.URL, ClientID: "support-web", Audience: "support-api", FixtureHTTP: true}
	s := newServer(c, verifyFunc(func(_ context.Context, token string, _ time.Time) (identity.Principal, error) {
		if token != "synthetic-access" {
			return identity.Principal{}, invalid
		}
		return *p, nil
	}), issuer.Client().Transport)
	t.Cleanup(s.Close)
	return s, issuer, p
}
func webCall(s *Server, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Origin", s.config.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Syn443-CSRF", "1")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func loginWeb(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	w := webCall(s, "/login", "{}", nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var link map[string]string
	json.Unmarshal(w.Body.Bytes(), &link)
	u, _ := url.Parse(link["url"])
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("dpop_jkt") == "" || u.Query().Get("scope") != "" {
		t.Fatal("OAuth binding")
	}
	callback := "/callback?" + url.Values{"code": {"test-code"}, "state": {u.Query().Get("state")}, "iss": {s.config.Issuer}}.Encode()
	r := httptest.NewRequest("GET", callback, nil)
	r.AddCookie(w.Result().Cookies()[0])
	out := httptest.NewRecorder()
	s.ServeHTTP(out, r)
	if out.Code != 303 {
		t.Fatalf("callback %d", out.Code)
	}
	replay := httptest.NewRecorder()
	s.ServeHTTP(replay, r)
	if replay.Code != 401 {
		t.Fatal("callback replay")
	}
	for _, c := range out.Result().Cookies() {
		if c.Name == s.cookieName(false) {
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				t.Fatal("cookie")
			}
			return c
		}
	}
	t.Fatal("missing session")
	return nil
}
func TestOAuthPKCEBoundKeyNonceProxyRefreshAndLogout(t *testing.T) {
	s, _, _ := webFixture(t)
	cookie := loginWeb(t, s)
	if w := webCall(s, "/session", "{}", cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := webCall(s, "/chat/self", "{}", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"admin":true`) {
		t.Fatal(w.Code)
	}
	s.sessions[cookie.Value].accessUntil = time.Now().Add(-time.Second)
	if w := webCall(s, "/chat/self", "{}", cookie); w.Code != 200 {
		t.Fatal("refresh", w.Code)
	}
	if w := webCall(s, "/logout", "{}", cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := webCall(s, "/chat/self", "{}", cookie); w.Code != 401 {
		t.Fatal("logged out")
	}
}
func TestWebRejectsCSRFQuerySessionCapacityOversizeAndStaticInjection(t *testing.T) {
	s, _, _ := webFixture(t)
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("asset security")
		}
	}
	script, _ := assets.ReadFile("assets/app.js")
	if strings.Contains(string(script), "innerHTML") || strings.Contains(string(script), "localStorage") {
		t.Fatal("unsafe frontend")
	}
	for _, r := range []*http.Request{httptest.NewRequest("POST", "/login", strings.NewReader("{}")), httptest.NewRequest("GET", "/login", nil), httptest.NewRequest("GET", "/app.js?q=1", nil), httptest.NewRequest("GET", "/callback?code=x&code=y&iss=x", nil)} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("invalid admitted")
		}
	}
	cookie := loginWeb(t, s)
	if w := webCall(s, "/chat/unknown", "{}", cookie); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := webCall(s, "/chat/send", strings.Repeat("x", 32769), cookie); w.Code != 413 {
		t.Fatal(w.Code)
	}
	v := s.sessions[cookie.Value]
	v.gate <- struct{}{}
	if w := webCall(s, "/chat/self", "{}", cookie); w.Code != 503 {
		t.Fatal(w.Code)
	}
	<-v.gate
	for range cap(s.slots) {
		s.slots <- struct{}{}
	}
	if w := webCall(s, "/login", "{}", nil); w.Code != 503 {
		t.Fatal(w.Code)
	}
	for range cap(s.slots) {
		<-s.slots
	}
	s.clock = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if w := webCall(s, "/session", "{}", cookie); w.Code != 401 {
		t.Fatal("expiry")
	}
}
func TestWebCallbackBindsBrowserAndIssuerAndBoundedPending(t *testing.T) {
	s, _, _ := webFixture(t)
	w := webCall(s, "/login", "{}", nil)
	var link map[string]string
	json.Unmarshal(w.Body.Bytes(), &link)
	u, _ := url.Parse(link["url"])
	path := "/callback?" + url.Values{"code": {"code"}, "state": {u.Query().Get("state")}, "iss": {s.config.Issuer}}.Encode()
	r := httptest.NewRequest("GET", path, nil)
	r.AddCookie(&http.Cookie{Name: s.cookieName(true), Value: "wrong"})
	out := httptest.NewRecorder()
	s.ServeHTTP(out, r)
	if out.Code != 401 {
		t.Fatal("browser binding")
	}
	for len(s.pending) < 32 {
		s.pending[random()] = pending{expires: time.Now().Add(time.Minute)}
	}
	if w := webCall(s, "/login", "{}", nil); w.Code != 503 {
		t.Fatal("pending cap")
	}
	s.clock = func() time.Time { return time.Now().Add(6 * time.Minute) }
	s.mu.Lock()
	s.prune(s.clock())
	s.mu.Unlock()
	if len(s.pending) != 0 {
		t.Fatal("pending expiry")
	}
	credentialURL := (&url.URL{Scheme: "https", Host: "example.invalid", User: url.UserPassword("fixture", "not-a-secret")}).String()
	for _, raw := range []string{"http://example.invalid", credentialURL, "https://example.invalid/", "https://example.invalid?q=1", "https://example.invalid/#x"} {
		if validURL(raw, true, false) {
			t.Fatal("URL boundary")
		}
	}
	if !validURL("https://web.example.invalid", true, false) || !validURL("http://127.0.0.1:1234", true, true) {
		t.Fatal("valid URL")
	}
	if _, e := New(context.Background(), Config{}, nil); e == nil {
		t.Fatal("invalid config")
	}
}
func TestWebProofIsBoundToMethodURIKeyBodyAndNonce(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	raw := []byte(`{"test":true}`)
	token := "synthetic-access-token-0123456789"
	proof, e := sign(key, "POST", "https://api.example.invalid/v1/admin/chat/self", token, "nonce", raw, now)
	if e != nil {
		t.Fatal(e)
	}
	ctx := identity.ProofContext{Method: "POST", URI: "https://api.example.invalid/v1/admin/chat/self", Token: token, Nonce: "nonce", BodyHash: identity.Hash(raw), Now: now}
	if _, e = identity.VerifyProof(proof, ctx); e != nil {
		t.Fatal("valid proof", e)
	}
	ctx.BodyHash = identity.Hash([]byte("changed"))
	if _, e = identity.VerifyProof(proof, ctx); e == nil {
		t.Fatal("body substitution")
	}
	if safeNonce("bad\nnonce") || safeNonce(strings.Repeat("x", 257)) || safeNonce("") {
		t.Fatal("nonce")
	}
}
