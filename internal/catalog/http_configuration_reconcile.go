package catalog

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const configurationReconcilePath = "/v1/control/configuration/reconcile"

// This fixed route cannot increase the mixed ordinary/source-upload body limit.
// One reserved concurrent reconciliation plus at most three ordinary handlers
// share the original four slots. Debt lives until the actual callback returns.
func (a *API) serveConfigurationReconcile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" || r.URL.Path != configurationReconcilePath || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("DPoP")) != 1 {
		apiFailure(w, ErrDenied)
		return
	}
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || !a.admit(ip, a.Clock()) {
		apiFailure(w, ErrQuota)
		return
	}
	select {
	case a.reconcileSlots <- struct{}{}:
		defer func() { <-a.reconcileSlots }()
	default:
		apiFailure(w, ErrUnavailable)
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		apiFailure(w, ErrUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	now, e := a.Store.Now(ctx, a.Clock())
	if e != nil {
		apiFailure(w, e)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
	if token == r.Header.Get("Authorization") || len(token) < 24 || len(token) > 16384 {
		apiFailure(w, ErrDenied)
		return
	}
	p, e := a.Verifier.Verify(ctx, token, now)
	if e != nil || !p.HasScope("syn443.control") || p.Expires <= now.Unix() {
		apiFailure(w, ErrDenied)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 524289))
	if e != nil || len(raw) > 524288 {
		apiFailure(w, ErrInvalid)
		return
	}
	proof, e := identity.VerifyProof(r.Header.Get("DPoP"), identity.ProofContext{Method: "POST", URI: a.Origin + configurationReconcilePath, Token: token, BodyHash: identity.Hash(raw), Now: now})
	if e != nil || proof.Thumbprint != p.Thumbprint {
		apiFailure(w, ErrDenied)
		return
	}
	actor := Actor{ID: identity.Hash([]byte(p.Issuer + "\x00" + p.Subject)), SessionUntil: p.Expires, MFAUntil: p.MFAUntil(a.AssuranceACR, now)}
	if e = a.Store.ConsumeAdminProof(ctx, actor, proof, now); e != nil {
		apiFailure(w, e)
		return
	}
	if a.ConfigurationReconcile == nil {
		apiFailure(w, ErrDenied)
		return
	}
	value, e := a.ConfigurationReconcile(ctx, token, r.Header.Get("DPoP"), raw, now)
	if e != nil {
		apiFailure(w, e)
		return
	}
	if ctx.Err() != nil {
		apiFailure(w, ErrUnavailable)
		return
	}
	json.NewEncoder(w).Encode(value)
}
