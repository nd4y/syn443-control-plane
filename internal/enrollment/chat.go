package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/supportchat"
)

// ChatSession shares enrollment's account/device/session/replay locks. It never
// grants administrative access from a device claim or from a request field.
func (s *Store) ChatSession(ctx context.Context, b Binding, token string, proof identity.Proof, action string, raw []byte, now time.Time) (any, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, _, e = s.lockSession(ctx, tx, b, proof, now.Unix(), false); e != nil {
		return nil, e
	}
	var hash string
	if e = tx.QueryRowContext(ctx, `SELECT access_hash FROM identity_sessions WHERE id=$1`, b.Session).Scan(&hash); e != nil {
		return nil, e
	}
	if hash != identity.Hash([]byte(token)) {
		return nil, ErrDenied
	}
	value, e := supportchat.Dispatch(ctx, tx, b.Owner, action, raw, now)
	if e != nil {
		return nil, e
	}
	return value, tx.Commit()
}

// ChatAdmin accepts only the separately verified web audience/client, and checks
// live owner-issued SQL authority before admitting a nonce or content operation.
func (s *Store) ChatAdmin(ctx context.Context, p identity.Principal, proof identity.Proof, action string, raw []byte, now time.Time) (any, error) {
	if p.Thumbprint != proof.Thumbprint {
		return nil, ErrDenied
	}
	owner := Owner(p.Issuer, p.Subject)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = lockAccount(ctx, tx, owner, now.Unix()); e != nil {
		return nil, e
	}
	var admin bool
	e = tx.QueryRowContext(ctx, `SELECT enabled FROM chat_admins WHERE owner=$1 FOR SHARE`, owner).Scan(&admin)
	if errors.Is(e, sql.ErrNoRows) || e == nil && !admin {
		return nil, ErrDenied
	}
	if e != nil {
		return nil, e
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM identity_challenges WHERE owner=$1 AND expires<=$2`, owner, now.Unix())
	if e != nil {
		return nil, e
	}
	var nonce string
	e = tx.QueryRowContext(ctx, `SELECT nonce FROM identity_challenges WHERE owner=$1 AND jkt=$2`, owner, p.Thumbprint).Scan(&nonce)
	if errors.Is(e, sql.ErrNoRows) {
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_challenges WHERE owner=$1`, owner).Scan(&count); e != nil {
			return nil, e
		}
		if count >= 32 {
			return nil, ErrDenied
		}
		nonce = random()
		_, e = tx.ExecContext(ctx, `INSERT INTO identity_challenges(owner,jkt,nonce,expires) VALUES($1,$2,$3,$4)`, owner, p.Thumbprint, nonce, now.Add(15*time.Minute).Unix())
	}
	if e != nil {
		return nil, e
	}
	if proof.Claims.Nonce != nonce {
		if e = tx.Commit(); e != nil {
			return nil, e
		}
		return nil, NonceRequired{nonce}
	}
	if e = replay(ctx, tx, proof, now.Unix()); e != nil {
		return nil, e
	}
	value, e := supportchat.Dispatch(ctx, tx, owner, action, raw, now)
	if e != nil {
		return nil, e
	}
	return value, tx.Commit()
}
func (a *API) chatHTTP(w http.ResponseWriter, r *http.Request) {
	if !a.ChatEnabled {
		http.NotFound(w, r)
		return
	}
	isAdmin := strings.HasPrefix(r.URL.Path, "/v1/admin/chat/")
	prefix := "/v1/chat/"
	if isAdmin {
		prefix = "/v1/admin/chat/"
	}
	action := strings.TrimPrefix(r.URL.Path, prefix)
	valid := map[string]bool{"self": true, "inbox": true, "messages": true, "send": true, "read": true, "uploads/begin": true, "uploads/part": true, "uploads/status": true, "uploads/complete": true, "uploads/cancel": true, "download": true}
	if !valid[action] {
		http.NotFound(w, r)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !isAdmin || origin != a.ChatWebOrigin {
			http.Error(w, "origin_denied", 403)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Expose-Headers", "DPoP-Nonce,Date,Retry-After")
	}
	if r.Method == "OPTIONS" && isAdmin && origin != "" {
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,DPoP,Content-Type")
		w.Header().Set("Access-Control-Max-Age", "300")
		w.WriteHeader(204)
		return
	}
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("DPoP")) != 1 {
		failure(w, identity.ErrInvalid)
		return
	}
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		failure(w, identity.ErrInvalid)
		return
	}
	if !a.admit("chat/"+ip, a.Clock()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate_limited", 429)
		return
	}
	select {
	case a.chatSlots <- struct{}{}:
		defer func() { <-a.chatSlots }()
	default:
		http.Error(w, "capacity_unavailable", 503)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
	if len(token) < 24 || len(token) > 16384 || token == r.Header.Get("Authorization") {
		failure(w, identity.ErrInvalid)
		return
	}
	limit := int64(32768)
	if action == "uploads/part" {
		limit = 352 * 1024
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		http.Error(w, "chat_size_limit", 413)
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
	proof, e := identity.RequestProof(r.Header.Get("DPoP"), identity.ProofContext{Method: "POST", URI: a.Origin + r.URL.Path, Token: token, BodyHash: identity.Hash(raw), Now: now})
	if e != nil {
		failure(w, e)
		return
	}
	var result any
	if isAdmin {
		if a.ChatVerifier == nil {
			failure(w, ErrDenied)
			return
		}
		p, err := a.ChatVerifier.Verify(ctx, token, now)
		if err != nil {
			failure(w, identity.ErrInvalid)
			return
		}
		result, e = a.Store.ChatAdmin(ctx, p, proof, action, raw, now)
	} else {
		b, err := a.Store.Lookup(ctx, token, false)
		if err != nil {
			failure(w, err)
			return
		}
		result, e = a.Store.ChatSession(ctx, b, token, proof, action, raw, now)
	}
	if e != nil {
		switch {
		case errors.Is(e, supportchat.ErrInvalid):
			http.Error(w, "chat_invalid", 400)
		case errors.Is(e, supportchat.ErrDenied):
			failure(w, ErrDenied)
		case errors.Is(e, supportchat.ErrConflict):
			failure(w, ErrConflict)
		case errors.Is(e, supportchat.ErrQuota):
			http.Error(w, "chat_quota", 413)
		case errors.Is(e, supportchat.ErrNotReady):
			http.Error(w, "chat_upload_incomplete", 409)
		default:
			failure(w, e)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if action == "download" {
		w.Header().Set("Content-Disposition", `attachment; filename="chunk.json"`)
	}
	_ = json.NewEncoder(w).Encode(result)
}
