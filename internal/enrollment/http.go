package enrollment

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

type Verifier interface {
	Verify(context.Context, string, time.Time) (identity.Principal, error)
}
type API struct {
	Store    *Store
	Verifier Verifier
	Origin   string
	Roots    map[string]*ecdsa.PublicKey
	Clock    func() time.Time
	mu       sync.Mutex
	buckets  map[string]bucket
	slots    chan struct{}
}
type bucket struct {
	minute int64
	count  int
}

func NewAPI(store *Store, verifier Verifier, origin string, roots map[string]*ecdsa.PublicKey, fixture bool) (*API, error) {
	u, e := url.Parse(origin)
	if e != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Host == "" || u.Scheme != "https" && !(fixture && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "") || len(roots) == 0 || len(roots) > 4 {
		return nil, identity.ErrInvalid
	}
	return &API{Store: store, Verifier: verifier, Origin: origin, Roots: roots, Clock: time.Now, buckets: map[string]bucket{}, slots: make(chan struct{}, 16)}, nil
}
func (a *API) admit(ip string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	minute := now.Unix() / 60
	for k, b := range a.buckets {
		if b.minute < minute-1 {
			delete(a.buckets, k)
		}
	}
	b, exists := a.buckets[ip]
	if !exists && len(a.buckets) >= 512 {
		return false
	}
	if b.minute != minute {
		b = bucket{minute: minute}
	}
	b.count++
	a.buckets[ip] = b
	return b.count <= 120
}
func failure(w http.ResponseWriter, err error) {
	code, status := "temporarily_unavailable", http.StatusServiceUnavailable
	var nonce NonceRequired
	switch {
	case errors.As(err, &nonce):
		code, status = "use_dpop_nonce", 401
		w.Header().Set("DPoP-Nonce", nonce.Value)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
	case errors.Is(err, identity.ErrInvalid):
		code, status = "identity_invalid", 401
	case errors.Is(err, ErrDenied):
		code, status = "access_denied", 403
	case errors.Is(err, ErrConflict):
		code, status = "idempotency_conflict", 409
	case errors.Is(err, ErrReplay):
		code, status = "proof_replayed", 401
	case errors.Is(err, ErrReuse):
		code, status = "session_reuse", 401
	case errors.Is(err, ErrPending):
		code, status = "provisioning_pending", 202
		w.Header().Set("Retry-After", "2")
	case errors.Is(err, ErrReauth):
		code, status = "reauthentication_required", 409
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if len(r.URL.RawQuery) > 0 || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" {
		http.NotFound(w, r)
		return
	}
	path := r.URL.Path
	allowed := r.Method == "POST" && (path == "/v1/devices/enroll" || path == "/v1/device/session/refresh" || path == "/v1/device/revoke") || r.Method == "GET" && path == "/v1/device/policy"
	if !allowed {
		http.NotFound(w, r)
		return
	}
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		failure(w, identity.ErrInvalid)
		return
	}
	if !a.admit(ip, a.Clock()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate_limited", 429)
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		http.Error(w, "capacity_unavailable", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	now, e := a.Store.Now(ctx, a.Clock())
	if e != nil {
		failure(w, ErrUnavailable)
		return
	}
	w.Header().Set("Date", now.Format(http.TimeFormat))
	if len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("DPoP")) != 1 {
		failure(w, identity.ErrInvalid)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
	if token == r.Header.Get("Authorization") || len(token) < 24 || len(token) > 16384 {
		failure(w, identity.ErrInvalid)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 8193))
	if e != nil || len(raw) > 8192 || r.Method == "GET" && len(raw) != 0 {
		failure(w, identity.ErrInvalid)
		return
	}
	if r.Method == "POST" && r.Header.Get("Content-Type") != "application/json" {
		failure(w, identity.ErrInvalid)
		return
	}
	hash := ""
	if r.Method == "POST" {
		hash = identity.Hash(raw)
	}
	proof, e := identity.RequestProof(r.Header.Get("DPoP"), identity.ProofContext{Method: r.Method, URI: a.Origin + path, Token: token, BodyHash: hash, Now: now})
	if e != nil {
		failure(w, e)
		return
	}
	if path == "/v1/devices/enroll" {
		principal, e := a.Verifier.Verify(ctx, token, now)
		if e != nil {
			failure(w, identity.ErrInvalid)
			return
		}
		value, e := a.Store.Register(ctx, principal, proof, raw, Receipt{token, r.Header.Get("DPoP"), a.Origin + path, now.Unix()}, now)
		if e != nil {
			failure(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
		return
	}
	binding, e := a.Store.Lookup(ctx, token, path == "/v1/device/session/refresh")
	if e != nil {
		failure(w, e)
		return
	}
	if (!binding.Active && path != "/v1/device/revoke") || binding.Jkt != proof.Thumbprint {
		failure(w, ErrDenied)
		return
	}
	if path == "/v1/device/session/refresh" {
		var req struct {
			RequestID string `json:"requestId"`
		}
		if identity.Decode(raw, &req, true) != nil {
			failure(w, identity.ErrInvalid)
			return
		}
		value, e := a.Store.Refresh(ctx, binding, token, req.RequestID, hash, proof, now)
		if e != nil {
			failure(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
		return
	}
	if path == "/v1/device/revoke" {
		var req struct {
			RequestID string `json:"requestId"`
		}
		if identity.Decode(raw, &req, true) != nil || !idPattern.MatchString(req.RequestID) {
			failure(w, identity.ErrInvalid)
			return
		}
		if e = a.Store.Revoke(ctx, binding, token, req.RequestID, hash, proof, now); e != nil {
			failure(w, e)
			return
		}
		w.WriteHeader(204)
		return
	}
	bundle, e := a.Store.Publication(ctx, binding, token, proof, now)
	if e != nil {
		failure(w, e)
		return
	}
	if _, e = policy.Verify(bundle, a.Roots, binding.Device, now); e != nil {
		failure(w, ErrUnavailable)
		return
	}
	w.Header().Set("ETag", `"`+identity.Hash([]byte(bundle))+`"`)
	w.Header().Set("Content-Type", "application/jose")
	_, _ = w.Write([]byte(bundle))
}
