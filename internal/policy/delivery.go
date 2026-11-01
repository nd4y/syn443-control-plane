package policy

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

// One immutable publication snapshot. API has neither signing keys nor a signing endpoint.
type Publication struct {
	Device     string
	BearerHash [32]byte
	Bundle     string
	Roots      map[string]*ecdsa.PublicKey
	Clock      func() time.Time
}

func Delivery(p Publication) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" || r.URL.Path != "/v1/device/policy" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		authorization := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authorization, "Bearer ")
		digest := sha256.Sum256([]byte(token))
		if !strings.HasPrefix(authorization, "Bearer ") || len(token) < 24 || len(token) > 256 || subtle.ConstantTimeCompare(digest[:], p.BearerHash[:]) != 1 || r.Header.Get("X-SYN443-Device") != p.Device {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		now := time.Now()
		if p.Clock != nil {
			now = p.Clock()
		}
		if _, e := Verify(p.Bundle, p.Roots, p.Device, now); e != nil {
			http.Error(w, "publication unavailable", http.StatusServiceUnavailable)
			return
		}
		sum := sha256.Sum256([]byte(p.Bundle))
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(p.Bundle))
	})
}
