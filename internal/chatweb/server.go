// Package chatweb hosts the support UI and a bounded OAuth BFF. Browser code never
// receives access/refresh tokens or a DPoP private key. Chat contents live in SQL
// behind the separately authenticated API; this process keeps only short sessions.
package chatweb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

//go:embed assets/*
var assets embed.FS
var invalid = errors.New("chat_web_invalid")

type Config struct {
	Listen         string `json:"listen"`
	Origin         string `json:"origin"`
	APIOrigin      string `json:"apiOrigin"`
	Issuer         string `json:"issuer"`
	ClientID       string `json:"clientId"`
	Audience       string `json:"audience"`
	Certificate    string `json:"certificate"`
	CertificateKey string `json:"certificateKey"`
	FixtureHTTP    bool   `json:"fixtureHttp"`
}
type verifier interface {
	Verify(context.Context, string, time.Time) (identity.Principal, error)
}
type pending struct {
	verifier, cookie string
	key              *ecdsa.PrivateKey
	expires          time.Time
}
type session struct {
	gate                   chan struct{}
	key                    *ecdsa.PrivateKey
	principal              identity.Principal
	access, refresh, nonce string
	accessUntil, expires   time.Time
	ctx                    context.Context
	cancel                 context.CancelFunc
}
type Server struct {
	config   Config
	verifier verifier
	client   *http.Client
	mu       sync.Mutex
	pending  map[string]pending
	sessions map[string]*session
	clock    func() time.Time
	slots    chan struct{}
}

func validURL(raw string, origin, fixture bool) bool {
	u, e := url.Parse(raw)
	return e == nil && len(raw) <= 2048 && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && !strings.HasSuffix(raw, "/") && (!origin || u.Path == "") &&
		(u.Scheme == "https" || fixture && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "")
}
func New(ctx context.Context, c Config, transport http.RoundTripper) (*Server, error) {
	if !validURL(c.Origin, true, c.FixtureHTTP) || !validURL(c.APIOrigin, true, c.FixtureHTTP) || !validURL(c.Issuer, false, c.FixtureHTTP) || c.ClientID == "" || len(c.ClientID) > 128 || c.Audience == "" || len(c.Audience) > 128 {
		return nil, invalid
	}
	p, e := identity.NewProvider(ctx, c.Issuer, c.Audience, c.ClientID, transport, c.FixtureHTTP)
	if e != nil {
		return nil, e
	}
	return newServer(c, p, transport), nil
}
func newServer(c Config, p verifier, transport http.RoundTripper) *Server {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	}
	return &Server{config: c, verifier: p, client: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, pending: map[string]pending{}, sessions: map[string]*session{}, clock: time.Now, slots: make(chan struct{}, 4)}
}
func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("random_unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func (s *Server) cookieName(login bool) string {
	name := "syn443-admin"
	if login {
		name += "-login"
	}
	if !s.config.FixtureHTTP {
		name = "__Host-" + name
	}
	return name
}
func (s *Server) cookie(w http.ResponseWriter, login bool, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(login), Value: value, Path: "/", MaxAge: age, Secure: !s.config.FixtureHTTP, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func (s *Server) prune(now time.Time) {
	for id, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, id)
		}
	}
	for id, v := range s.sessions {
		if !now.Before(v.expires) {
			v.cancel()
			delete(s.sessions, id)
		}
	}
}
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.sessions {
		v.cancel()
	}
	s.sessions = map[string]*session{}
	s.pending = map[string]pending{}
}
func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int) { http.Error(w, "chat_web_unavailable", status) }
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if r.URL.RawPath != "" || r.URL.Fragment != "" || (r.URL.RawQuery != "" && r.URL.Path != "/callback") {
		fail(w, 400)
		return
	}
	if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css") {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		b, e := assets.ReadFile("assets/" + name)
		if e != nil {
			fail(w, 404)
			return
		}
		kind := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
		w.Header().Set("Content-Type", kind[name])
		_, _ = w.Write(b)
		return
	}
	if r.URL.Path == "/callback" && r.Method == "GET" {
		s.callback(w, r)
		return
	}
	if r.Method != "POST" || r.Header.Get("Origin") != s.config.Origin || r.Header.Get("X-Syn443-CSRF") != "1" || r.Header.Get("Content-Type") != "application/json" {
		fail(w, 403)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(w, 503)
		return
	}
	if r.URL.Path == "/login" {
		s.login(w, r)
		return
	}
	cookie, e := r.Cookie(s.cookieName(false))
	if e != nil {
		fail(w, 401)
		return
	}
	s.mu.Lock()
	s.prune(s.clock())
	v := s.sessions[cookie.Value]
	if r.URL.Path == "/logout" {
		if v != nil {
			v.cancel()
			delete(s.sessions, cookie.Value)
		}
		s.mu.Unlock()
		s.cookie(w, false, "", -1)
		reply(w, map[string]bool{"ok": true})
		return
	}
	s.mu.Unlock()
	if v == nil {
		fail(w, 401)
		return
	}
	if r.URL.Path == "/session" {
		reply(w, map[string]bool{"authenticated": true})
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/chat/")
	allowed := map[string]bool{"self": true, "inbox": true, "messages": true, "send": true, "read": true, "uploads/begin": true, "uploads/part": true, "uploads/status": true, "uploads/complete": true, "uploads/cancel": true, "download": true}
	if !strings.HasPrefix(r.URL.Path, "/chat/") || !allowed[action] {
		fail(w, 404)
		return
	}
	limit := int64(32768)
	if action == "uploads/part" {
		limit = 352 * 1024
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		fail(w, 413)
		return
	}
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	default:
		fail(w, 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(v.ctx, cancel)
	defer stop()
	if v.ctx.Err() != nil {
		fail(w, 401)
		return
	}
	if !s.clock().Add(30 * time.Second).Before(v.accessUntil) {
		if v.refresh == "" || s.token(ctx, v, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {v.refresh}, "client_id": {s.config.ClientID}}) != nil {
			fail(w, 401)
			return
		}
	}
	uri := s.config.APIOrigin + "/v1/admin/chat/" + action
	for attempt := 0; attempt < 2; attempt++ {
		proof, e := sign(v.key, "POST", uri, v.access, v.nonce, raw, s.clock())
		if e != nil {
			fail(w, 503)
			return
		}
		req, e := http.NewRequestWithContext(ctx, "POST", uri, strings.NewReader(string(raw)))
		if e != nil {
			fail(w, 503)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+v.access)
		req.Header.Set("DPoP", proof)
		res, e := s.client.Do(req)
		if e != nil {
			fail(w, 503)
			return
		}
		data, e := io.ReadAll(io.LimitReader(res.Body, 524289))
		res.Body.Close()
		if e != nil || len(data) > 524288 {
			fail(w, 502)
			return
		}
		if res.StatusCode == 401 && attempt == 0 && safeNonce(res.Header.Get("DPoP-Nonce")) {
			v.nonce = res.Header.Get("DPoP-Nonce")
			continue
		}
		if res.StatusCode != 200 {
			if res.StatusCode == 429 {
				w.Header().Set("Retry-After", "60")
			}
			status := res.StatusCode
			if status < 400 || status > 599 {
				status = 502
			}
			fail(w, status)
			return
		}
		if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") || !json.Valid(data) {
			fail(w, 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
		return
	}
	fail(w, 401)
}
func safeNonce(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.IndexFunc(s, func(c rune) bool { return c < 33 || c > 126 }) < 0
}
func sign(key *ecdsa.PrivateKey, method, uri, token, nonce string, body []byte, now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": identity.PublicJWK(&key.PublicKey)})
	claims := identity.ProofClaims{Jti: random(), Htm: method, Htu: uri, Iat: now.Unix(), Nonce: nonce}
	if token != "" {
		claims.Ath = identity.Hash([]byte(token))
	}
	if body != nil {
		claims.RequestHash = identity.Hash(body)
	}
	payload, _ := json.Marshal(claims)
	b64 := base64.RawURLEncoding
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	hash := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, hash[:])
	if e != nil {
		return "", e
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + b64.EncodeToString(sig), nil
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		fail(w, 503)
		return
	}
	p := pending{random(), random(), key, s.clock().Add(5 * time.Minute)}
	state := random()
	s.mu.Lock()
	s.prune(s.clock())
	if len(s.pending) >= 32 || len(s.sessions) >= 32 {
		s.mu.Unlock()
		fail(w, 503)
		return
	}
	s.pending[state] = p
	s.mu.Unlock()
	thumb, _ := identity.PublicJWK(&key.PublicKey).Thumbprint()
	// Access-token identity is verified by the pinned API audience, issuer, client
	// and DPoP key. We request OAuth authorization, never use an unverified ID token.
	q := url.Values{"client_id": {s.config.ClientID}, "response_type": {"code"}, "redirect_uri": {s.config.Origin + "/callback"}, "state": {state}, "code_challenge": {identity.Hash([]byte(p.verifier))}, "code_challenge_method": {"S256"}, "dpop_jkt": {thumb}}
	s.cookie(w, true, p.cookie, 300)
	reply(w, map[string]string{"url": s.config.Issuer + "/protocol/openid-connect/auth?" + q.Encode()})
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 8192 {
		fail(w, 400)
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		fail(w, 400)
		return
	}
	for k, v := range q {
		if len(v) != 1 || (k != "code" && k != "state" && k != "iss" && k != "session_state") {
			fail(w, 400)
			return
		}
	}
	if q.Get("iss") != s.config.Issuer || len(q.Get("code")) < 1 || len(q.Get("code")) > 4096 {
		fail(w, 400)
		return
	}
	cookie, e := r.Cookie(s.cookieName(true))
	if e != nil {
		fail(w, 401)
		return
	}
	s.mu.Lock()
	s.prune(s.clock())
	p, ok := s.pending[q.Get("state")]
	if !ok || p.cookie != cookie.Value {
		s.mu.Unlock()
		fail(w, 401)
		return
	}
	delete(s.pending, q.Get("state"))
	s.mu.Unlock()
	s.cookie(w, true, "", -1)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	v := &session{gate: make(chan struct{}, 1), key: p.key, expires: s.clock().Add(time.Hour)}
	if s.token(ctx, v, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "code_verifier": {p.verifier}, "client_id": {s.config.ClientID}, "redirect_uri": {s.config.Origin + "/callback"}}) != nil {
		fail(w, 401)
		return
	}
	id := random()
	v.ctx, v.cancel = context.WithCancel(context.Background())
	s.mu.Lock()
	s.prune(s.clock())
	if len(s.sessions) >= 32 {
		s.mu.Unlock()
		v.cancel()
		fail(w, 503)
		return
	}
	if old, e := r.Cookie(s.cookieName(false)); e == nil {
		if oldSession := s.sessions[old.Value]; oldSession != nil {
			oldSession.cancel()
			delete(s.sessions, old.Value)
		}
	}
	s.sessions[id] = v
	s.mu.Unlock()
	s.cookie(w, false, id, 3600)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) token(ctx context.Context, v *session, form url.Values) error {
	endpoint := s.config.Issuer + "/protocol/openid-connect/token"
	nonce := ""
	for attempt := 0; attempt < 2; attempt++ {
		proof, e := sign(v.key, "POST", endpoint, "", nonce, nil, s.clock())
		if e != nil {
			return e
		}
		req, e := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
		if e != nil {
			return e
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", proof)
		res, e := s.client.Do(req)
		if e != nil {
			return invalid
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
		res.Body.Close()
		if e != nil || len(raw) > 65536 {
			return invalid
		}
		if attempt == 0 && (res.StatusCode == 400 || res.StatusCode == 401) && safeNonce(res.Header.Get("DPoP-Nonce")) {
			nonce = res.Header.Get("DPoP-Nonce")
			continue
		}
		var token struct {
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
			Type    string `json:"token_type"`
			Expires int64  `json:"expires_in"`
		}
		if res.StatusCode != 200 || identity.Decode(raw, &token, false) != nil || token.Type != "DPoP" || token.Expires < 1 || token.Expires > 600 || len(token.Access) > 16384 || len(token.Refresh) > 16384 {
			return invalid
		}
		p, e := s.verifier.Verify(ctx, token.Access, s.clock())
		if e != nil {
			return invalid
		}
		thumb, _ := identity.PublicJWK(&v.key.PublicKey).Thumbprint()
		if p.Thumbprint != thumb || (v.principal.Subject != "" && p != v.principal) {
			return invalid
		}
		v.access = token.Access
		v.refresh = token.Refresh
		v.principal = p
		v.accessUntil = s.clock().Add(time.Duration(token.Expires) * time.Second)
		return nil
	}
	return invalid
}
