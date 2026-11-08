// Package chatweb hosts the support UI and a bounded OAuth BFF. Browser code never
// receives access/refresh tokens or a DPoP private key. Chat contents live in SQL
// behind the separately authenticated API; this process keeps only short sessions.
package chatweb

import (
	"bytes"
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
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

//go:embed assets/*
var assets embed.FS
var invalid = errors.New("chat_web_invalid")
var consoleAsset = regexp.MustCompile("^[A-Z0-9]{8}$")

// ControlAssetsReady reports whether the console entry points were bundled before embedding.
func ControlAssetsReady() bool {
	for _, name := range []string{"console.js", "console.css"} {
		if _, err := fs.Stat(assets, "assets/control/ui/"+name); err != nil {
			return false
		}
	}
	return true
}

func staticAsset(path string, console bool) (string, string) {
	switch path {
	case "/":
		return "index.html", "text/html; charset=utf-8"
	case "/app.js", "/layer-merge.js":
		return path[1:], "text/javascript; charset=utf-8"
	case "/style.css":
		return "style.css", "text/css; charset=utf-8"
	}
	if !console {
		return "", ""
	}
	switch path {
	case "/ui/console.js":
		return path[1:], "text/javascript; charset=utf-8"
	case "/ui/console.css":
		return path[1:], "text/css; charset=utf-8"
	}
	name, ok := strings.CutPrefix(path, "/ui/asset-")
	hash, ext, found := strings.Cut(name, ".")
	if ok && found && consoleAsset.MatchString(hash) {
		switch ext {
		case "woff2":
			return path[1:], "font/woff2"
		case "svg":
			return path[1:], "image/svg+xml"
		}
	}
	return "", ""
}

var consoleDeviceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

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
	ControlConsole bool   `json:"controlConsole,omitempty"`
}
type verifier interface {
	Verify(context.Context, string, time.Time) (identity.Principal, error)
}
type pending struct {
	verifier, cookie, device string
	key                      *ecdsa.PrivateKey
	expires                  time.Time
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
	config        Config
	verifier      verifier
	client        *http.Client
	mu            sync.Mutex
	pending       map[string]pending
	sessions      map[string]*session
	clock         func() time.Time
	slots         chan struct{}
	sourceImports chan struct{}
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
	return &Server{config: c, verifier: p, client: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, pending: map[string]pending{}, sessions: map[string]*session{}, clock: time.Now, slots: make(chan struct{}, 4), sourceImports: make(chan struct{}, 1)}
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
	if s.config.ControlConsole {
		name = "syn443-control"
	}
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
	csp := "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	if s.config.ControlConsole {
		csp += "; font-src 'self'; img-src 'self'"
	}
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if r.URL.RawPath != "" || r.URL.Fragment != "" || (r.URL.RawQuery != "" && r.URL.Path != "/callback") {
		fail(w, 400)
		return
	}
	if name, kind := staticAsset(r.URL.Path, s.config.ControlConsole); r.Method == "GET" && name != "" {
		prefix := "assets/"
		if s.config.ControlConsole {
			prefix += "control/"
		}
		b, e := assets.ReadFile(prefix + name)
		if e != nil {
			fail(w, 404)
			return
		}
		w.Header().Set("Content-Type", kind)
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
	sourceImport := s.config.ControlConsole && r.URL.Path == "/control/source/import"
	control := s.config.ControlConsole && (r.URL.Path == "/control/action" || sourceImport)
	if !control && (s.config.ControlConsole || !strings.HasPrefix(r.URL.Path, "/chat/") || !allowed[action]) {
		fail(w, 404)
		return
	}
	limit := int64(32768)
	if action == "uploads/part" {
		limit = 352 * 1024
	}
	if control {
		limit = consoleActionLimit
	}
	if sourceImport {
		limit = consoleImportLimit
		select {
		case s.sourceImports <- struct{}{}:
			defer func() { <-s.sourceImports }()
		default:
			fail(w, 503)
			return
		}
	}
	if r.ContentLength > limit {
		fail(w, 413)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		fail(w, 413)
		return
	}
	if control && !validConsoleAction(raw, sourceImport) {
		fail(w, 400)
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
	if control {
		if !v.principal.HasScope("syn443.control") {
			fail(w, 403)
			return
		}
		uri = s.config.APIOrigin + "/v1/control/action"
	}
	for attempt := 0; attempt < 2; attempt++ {
		proof, e := sign(v.key, "POST", uri, v.access, v.nonce, raw, s.clock())
		if e != nil {
			fail(w, 503)
			return
		}
		req, e := http.NewRequestWithContext(ctx, "POST", uri, bytes.NewReader(raw))
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
	var device string
	if s.config.ControlConsole {
		const limit = 512
		var input struct {
			Device json.RawMessage `json:"device"`
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if e != nil || len(raw) > limit || identity.Decode(raw, &input, true) != nil {
			fail(w, 400)
			return
		}
		if len(input.Device) > 0 && (json.Unmarshal(input.Device, &device) != nil || !consoleDeviceID.MatchString(device)) {
			fail(w, 400)
			return
		}
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		fail(w, 503)
		return
	}
	p := pending{verifier: random(), cookie: random(), device: device, key: key, expires: s.clock().Add(5 * time.Minute)}
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
	if s.config.ControlConsole {
		q.Set("scope", "openid syn443.control")
	}
	s.cookie(w, true, p.cookie, 300)
	reply(w, map[string]string{"url": s.config.Issuer + "/protocol/openid-connect/auth?" + q.Encode()})
}

const consoleLoginRecovery = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><title>SYN443 - Вход не завершён</title><link rel="stylesheet" href="/style.css"></head>
<body><main><section class="wide"><h1>Вход не завершён</h1><p>Откройте панель и начните вход через Keycloak заново.</p>
<p><a href="/">Вернуться ко входу</a></p></section></main></body></html>`

func (s *Server) callbackFailure(w http.ResponseWriter, r *http.Request, status int) {
	if s.config.ControlConsole {
		for _, accept := range r.Header.Values("Accept") {
			for media := range strings.SplitSeq(accept, ",") {
				kind, params, e := mime.ParseMediaType(media)
				if e != nil || kind != "text/html" {
					continue
				}
				if value, hasQuality := params["q"]; hasQuality {
					q, e := strconv.ParseFloat(value, 64)
					if e != nil || !(q > 0 && q <= 1) {
						continue
					}
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, consoleLoginRecovery)
				return
			}
		}
	}
	fail(w, status)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 8192 {
		s.callbackFailure(w, r, 400)
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		s.callbackFailure(w, r, 400)
		return
	}
	for k, v := range q {
		if len(v) != 1 || (k != "code" && k != "state" && k != "iss" && k != "session_state") {
			s.callbackFailure(w, r, 400)
			return
		}
	}
	if q.Get("iss") != s.config.Issuer || len(q.Get("code")) < 1 || len(q.Get("code")) > 4096 {
		s.callbackFailure(w, r, 400)
		return
	}
	cookie, e := r.Cookie(s.cookieName(true))
	if e != nil {
		s.callbackFailure(w, r, 401)
		return
	}
	s.mu.Lock()
	s.prune(s.clock())
	p, ok := s.pending[q.Get("state")]
	if !ok || p.cookie != cookie.Value {
		s.mu.Unlock()
		s.callbackFailure(w, r, 401)
		return
	}
	delete(s.pending, q.Get("state"))
	s.mu.Unlock()
	s.cookie(w, true, "", -1)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	v := &session{gate: make(chan struct{}, 1), key: p.key, expires: s.clock().Add(time.Hour)}
	if s.token(ctx, v, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "code_verifier": {p.verifier}, "client_id": {s.config.ClientID}, "redirect_uri": {s.config.Origin + "/callback"}}) != nil {
		s.callbackFailure(w, r, 401)
		return
	}
	id := random()
	v.ctx, v.cancel = context.WithCancel(context.Background())
	s.mu.Lock()
	s.prune(s.clock())
	if len(s.sessions) >= 32 {
		s.mu.Unlock()
		v.cancel()
		s.callbackFailure(w, r, 503)
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
	location := "/"
	if p.device != "" {
		location += "#device=" + p.device
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
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
		if p.Thumbprint != thumb || s.config.ControlConsole && !p.HasScope("syn443.control") || (v.principal.Subject != "" && (p.Issuer != v.principal.Issuer || p.Subject != v.principal.Subject || p.Thumbprint != v.principal.Thumbprint)) {
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
