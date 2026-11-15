package chatweb

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

var reauthenticationACR = regexp.MustCompile(`^[A-Za-z0-9:._/-]{1,128}$`)

func principalOwner(p identity.Principal) string {
	return identity.Hash([]byte(p.Issuer + "\x00" + p.Subject))
}

// Caller holds s.mu. Session identifiers are server-generated and never reused.
func (s *Server) liveParentLocked(id string) bool {
	v := s.sessions[id]
	return v != nil && s.clock().Before(v.expires) && v.ctx.Err() == nil
}

func (s *Server) sessionGate(w http.ResponseWriter, r *http.Request, id string, v *session, run func()) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	case <-v.ctx.Done():
		fail(w, 401)
		return
	case <-ctx.Done():
		fail(w, 503)
		return
	}
	s.mu.Lock()
	s.prune(s.clock())
	live := s.sessions[id] == v && s.liveParentLocked(id)
	s.mu.Unlock()
	if !live {
		fail(w, 401)
		return
	}
	run()
}

func (s *Server) sessionStatus(w http.ResponseWriter, r *http.Request, id string, v *session) {
	s.sessionGate(w, r, id, v, func() {
		result := map[string]any{"authenticated": true}
		if s.config.ControlConsole && s.config.ReauthenticationACR != "" {
			result["reauthenticationAvailable"] = true
			result["reauthenticationFresh"] = v.principal.MFAUntil(s.config.ReauthenticationACR, s.clock()) > s.clock().Unix()
			result["reauthenticationIssuer"] = s.config.Issuer
		}
		reply(w, result)
	})
}

func (s *Server) reauthenticate(w http.ResponseWriter, r *http.Request, id string, v *session) {
	if !s.config.ControlConsole || s.config.ReauthenticationACR == "" {
		fail(w, 404)
		return
	}
	s.sessionGate(w, r, id, v, func() { s.beginLogin(w, r, id, principalOwner(v.principal)) })
}

func reauthenticationChallenge(raw []byte) bool {
	var challenge struct {
		Code string `json:"code"`
	}
	return len(raw) <= 128 && identity.Decode(raw, &challenge, true) == nil && challenge.Code == "catalog_reauthentication_required"
}
