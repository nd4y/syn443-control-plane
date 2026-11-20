package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func probe(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestProbeRoutesAndDatabaseRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		shutdown, stop := context.WithCancel(t.Context())
		defer stop()
		var calls int
		var failure error
		h := Wrap(shutdown, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}), func(context.Context) error {
			calls++
			return failure
		})
		for _, path := range []string{"/livez", "/readyz"} {
			r := probe(h, "POST", path)
			if r.Code != 405 || r.Header().Get("Allow") != "GET, HEAD" || r.Body.Len() != 0 {
				t.Fatalf("unsupported method on %s: %d", path, r.Code)
			}
		}
		if probe(h, "GET", "/v1/device/policy").Code != 401 || probe(h, "GET", "/readyz/").Code != 401 {
			t.Fatal("probe shadowed an application route")
		}
		check := func(method, path string, want int) {
			t.Helper()
			r := probe(h, method, path)
			if r.Code != want || r.Body.Len() != 0 || r.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s %s: got %d, want empty %d with cache disabled", method, path, r.Code, want)
			}
		}
		check("GET", "/livez", 200)
		if calls != 0 {
			t.Fatal("liveness touched the database")
		}
		check("HEAD", "/readyz", 200)
		failure = errors.New("private database detail")
		check("GET", "/readyz", 200)
		time.Sleep(2 * time.Second)
		check("GET", "/readyz", 503)
		check("HEAD", "/livez", 200)
		failure = nil
		check("GET", "/readyz", 503)
		time.Sleep(2 * time.Second)
		check("GET", "/readyz", 200)
		stop()
		check("GET", "/readyz", 503)
		if calls != 3 {
			t.Fatalf("database called %d times", calls)
		}
	})
}

func TestProbeRejectsLateDatabaseSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := Wrap(t.Context(), http.NotFoundHandler(), func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		})
		start := time.Now()
		if r := probe(h, "HEAD", "/readyz"); r.Code != 503 || time.Since(start) != time.Second {
			t.Fatalf("timed-out database returned %d in %s", r.Code, time.Since(start))
		}
	})
}

func TestConcurrentProbesShareOnePing(t *testing.T) {
	var calls atomic.Int32
	var started, done sync.WaitGroup
	const clients = 16
	started.Add(clients)
	h := Wrap(t.Context(), http.NotFoundHandler(), func(ctx context.Context) error {
		calls.Add(1)
		started.Wait()
		return nil
	})
	for range clients {
		done.Go(func() {
			started.Done()
			if r := probe(h, "GET", "/readyz"); r.Code != 200 {
				t.Errorf("healthy database returned %d", r.Code)
			}
		})
	}
	done.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent probes issued %d pings", calls.Load())
	}
}
