package main

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestLocalReadinessTLSUsesOnlyTheBoundIngestListener(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.RequestURI() != "/readyz" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected readiness request")
		}
		hits.Add(1)
		w.Header().Set("X-SYN443-Service", "telemetry-ingest")
	}))
	defer server.Close()
	cert := filepath.Join(t.TempDir(), "tls.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c := config{Listen: server.Listener.Addr().String(), Origin: "https://external.example.invalid", Certificate: cert, ReadinessServerName: server.Certificate().DNSNames[0]}
	if err := checkReady(t.Context(), c); err != nil || hits.Load() != 1 {
		t.Fatal("trusted local TLS probe did not reach the listener")
	}
	for _, change := range []func(*config){
		func(c *config) { c.ReadinessServerName = "wrong.example.invalid" },
		func(c *config) { c.Certificate = filepath.Join(t.TempDir(), "missing") },
		func(c *config) { c.Listen = "192.0.2.4:443" },
		func(c *config) { c.Listen = "127.0.0.1:0" },
		func(c *config) { c.Origin = "http://127.0.0.1:443" },
		func(c *config) { c.Origin += "/extra" },
	} {
		bad := c
		change(&bad)
		if checkReady(t.Context(), bad) == nil {
			t.Fatal("invalid readiness configuration accepted")
		}
	}
	if hits.Load() != 1 {
		t.Fatal("invalid probe reached application")
	}
}

func TestLocalReadinessRequiresOwnHealthyResponseAndNeverFollowsRedirect(t *testing.T) {
	for _, tc := range []struct {
		status int
		role   string
		want   bool
	}{
		{200, "telemetry-ingest", true}, {200, "control-api", false}, {503, "telemetry-ingest", false}, {302, "telemetry-ingest", false},
	} {
		var hits atomic.Int32
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("X-SYN443-Service", tc.role)
			if tc.status == 302 {
				w.Header().Set("Location", "/next")
			}
			w.WriteHeader(tc.status)
		}))
		c := config{Listen: s.Listener.Addr().String(), Origin: s.URL, FixtureHTTP: true}
		err := checkReady(t.Context(), c)
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		cancelErr := checkReady(cancelled, c)
		s.Close()
		if (err == nil) != tc.want || cancelErr == nil || hits.Load() != 1 {
			t.Fatal("incorrect readiness or redirect outcome", tc.status, tc.role)
		}
	}
}
