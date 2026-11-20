// Package health serves the process and database probes of the loopback HTTP APIs.
package health

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Wrap uses the same listener as the application. shutdown belongs to the
// process and ping checks the application's existing SQL connection pool.
func Wrap(shutdown context.Context, next http.Handler, ping func(context.Context) error) http.Handler {
	var mu sync.Mutex
	var validUntil time.Time
	var ready bool
	checkDatabase := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if shutdown.Err() != nil {
			return false
		}
		if !time.Now().Before(validUntil) {
			ctx, cancel := context.WithTimeout(shutdown, time.Second)
			err := ping(ctx)
			ready = err == nil && ctx.Err() == nil
			cancel()
			validUntil = time.Now().Add(2 * time.Second)
		}
		return ready && shutdown.Err() == nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/livez" && r.URL.Path != "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/readyz" && !checkDatabase() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}
