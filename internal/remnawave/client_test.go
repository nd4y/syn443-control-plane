package remnawave

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/resources"
)

const fixtureToken = "synthetic-owner-token-only"

var fixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const expiry = "2026-01-02T00:00:00Z"

func userBody() string {
	return `{"response":{"id":42,"shortUuid":"synthetic-short","status":"ACTIVE","expireAt":"` + expiry + `"}}`
}
func subscriptionBody() string {
	return `{"response":{"isFound":true,"user":{"shortUuid":"synthetic-short","isActive":true,"userStatus":"ACTIVE","expiresAt":"` + expiry + `","trafficUsedBytes":"9007199254740993","trafficLimitBytes":"0"},"links":["https://proxy.example.invalid/synthetic-profile"]}}`
}
func binding() resources.Binding {
	return resources.Binding{ResourceID: "panel-a", ExternalUserID: "42"}
}

func fixture(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+fixtureToken {
			t.Error("unexpected method or authorization")
			http.Error(w, "denied", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if handler != nil {
			handler(w, r)
			return
		}
		switch r.URL.Path {
		case "/api/users/42":
			io.WriteString(w, userBody())
		case "/api/subscriptions/by-id/42":
			io.WriteString(w, subscriptionBody())
		default:
			t.Error("unexpected API path")
			http.NotFound(w, r)
		}
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c, e := New(Config{Instance: resources.Instance{ResourceID: "panel-a", ProviderType: resources.Remnawave, APIVersion: "3.4", Endpoint: s.URL, CredentialRef: "owner-config", Enabled: true}, Token: fixtureToken, Roots: pool, AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		t.Fatal("fixture adapter construction failed")
	}
	c.now = func() time.Time { return fixedTime }
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s, calls
}
func code(t *testing.T, err error, want string) {
	t.Helper()
	var f *resources.Error
	if !errors.As(err, &f) || f.Code != want {
		t.Fatalf("error code expected %s, got %v", want, err)
	}
	if strings.Contains(err.Error(), fixtureToken) || strings.Contains(err.Error(), "https://") {
		t.Fatal("error leaked privileged input")
	}
}

func TestReadAssignmentUsesScopedProtectedAPI(t *testing.T) {
	c, _, calls := fixture(t, nil)
	s, e := c.ReadAssignment(context.Background(), binding())
	if e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 2 || s.Ref.ResourceID != "panel-a" || s.Ref.ExternalObjectID != "42" || s.TrafficUsedBytes != 9007199254740993 || len(s.Links) != 1 || !s.ExpiresAt.After(s.ObservedAt) {
		t.Fatal("assignment metadata mismatch")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", s, s), "synthetic-profile") {
		t.Fatal("snapshot logging leaked profile")
	}
	b, e := json.Marshal(s)
	if e != nil || !strings.Contains(string(b), "9007199254740993") {
		t.Fatal("integer precision lost")
	}
	for _, b := range []resources.Binding{{ResourceID: "panel-b", ExternalUserID: "42"}, {ResourceID: "panel-a", ExternalUserID: "042"}, {ResourceID: "panel-a", ExternalUserID: "../42"}, {ResourceID: "panel-a", ExternalUserID: "42?x=1"}, {ResourceID: "panel-a", ExternalUserID: "9007199254740993"}} {
		_, e := c.ReadAssignment(context.Background(), b)
		code(t, e, "invalid_binding")
	}
	if calls.Load() != 2 {
		t.Fatal("unassigned identity caused API request")
	}
}
func TestConstructionAndDestinationPolicy(t *testing.T) {
	valid := Config{Instance: resources.Instance{ResourceID: "p", ProviderType: resources.Remnawave, APIVersion: "3.4", CredentialRef: "c", Endpoint: "https://panel.example.invalid", Enabled: true}, Token: fixtureToken}
	for _, endpoint := range []string{"http://panel.example.invalid", "https://" + "synthetic:placeholder@" + "panel.example.invalid", "https://panel.example.invalid/path", "https://panel.example.invalid?code=example", "https://panel.example.invalid/#fragment", "https://panel.example.invalid:99999"} {
		c := valid
		c.Instance.Endpoint = endpoint
		if x, e := New(c); e == nil {
			x.Close()
			t.Fatal("invalid endpoint accepted")
		}
	}
	for _, token := range []string{"", "short", fixtureToken + "\n", strings.Repeat("x", 4097)} {
		c := valid
		c.Token = token
		if x, e := New(c); e == nil {
			x.Close()
			t.Fatal("invalid token accepted")
		}
	}
	addresses := []string{"127.0.0.1", "::ffff:127.0.0.1", "::1", "192.0.2.1", "203.0.113.2", "fc00::1", "fe80::1", "2002:7f00:1::", "64:ff9b::7f00:1"}
	// Synthetic private/special addresses, following the public-data test convention.
	for _, o := range [][4]byte{{10, 0, 0, 1}, {100, 64, 0, 1}, {169, 254, 169, 254}, {198, 18, 0, 1}, {0, 1, 2, 3}} {
		addresses = append(addresses, netip.AddrFrom4(o).String())
	}
	for _, v := range addresses {
		if allowedIP(netip.MustParseAddr(v), nil) {
			t.Fatal("nonpublic destination allowed without grant")
		}
	}
	if !publicIP(netip.MustParseAddr("8.8.8.8")) || !publicIP(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("public address rejected")
	}
	c, _, calls := fixture(t, nil)
	c.transport.CloseIdleConnections()
	// A fresh client without the explicit loopback grant cannot send the bearer.
	cfg := valid
	cfg.Instance.Endpoint = c.origin
	x, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer x.Close()
	_, e = x.ReadAssignment(context.Background(), resources.Binding{ResourceID: "p", ExternalUserID: "42"})
	code(t, e, "address_not_allowed")
	if calls.Load() != 0 {
		t.Fatal("denied destination received credentials")
	}
}

func FuzzProviderJSON(f *testing.F) {
	for _, s := range []string{userBody(), subscriptionBody(), `{"a":1,"a":2}`, `[1,null]`, "{"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxBody {
			return
		}
		_ = validateJSON(b)
	})
}
func TestProviderStatusAndSchemaErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"unauthorized", "", "access_denied", 401}, {"forbidden", "", "access_denied", 403}, {"missing", "", "assignment_not_found", 404}, {"limited", "", "rate_limited", 429}, {"server", "", "provider_unavailable", 503}, {"redirect", "", "unexpected_response", 302},
		{"duplicate", `{"response":{"id":42,"id":42}}`, "invalid_response", 200}, {"trailing", userBody() + `{}`, "invalid_response", 200}, {"string-id", strings.Replace(userBody(), `"id":42`, `"id":"42"`, 1), "identity_mismatch", 200}, {"foreign", strings.Replace(userBody(), `"id":42`, `"id":43`, 1), "identity_mismatch", 200}, {"inactive", strings.Replace(userBody(), "ACTIVE", "DISABLED", 1), "access_denied", 200}, {"unknown-status", strings.Replace(userBody(), "ACTIVE", "OTHER", 1), "invalid_response", 200}, {"bad-expiry", strings.Replace(userBody(), expiry, "invalid", 1), "invalid_response", 200}, {"expired", strings.Replace(userBody(), expiry, "2025-01-01T00:00:00Z", 1), "access_denied", 200}, {"large", strings.Repeat(" ", maxBody+1), "invalid_response", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) })
			_, e := c.ReadAssignment(context.Background(), binding())
			code(t, e, tc.want)
			if calls.Load() != 1 {
				t.Fatal("error retried or permission crossed")
			}
		})
	}
}
func TestSubscriptionCannotCrossIdentityOrSilentlyEmpty(t *testing.T) {
	for _, tc := range []struct{ old, new, want string }{
		{`"shortUuid":"synthetic-short"`, `"shortUuid":"foreign"`, "identity_mismatch"}, {`"isFound":true`, `"isFound":false`, "assignment_not_found"}, {`"isFound":true,`, "", "invalid_response"}, {`"isActive":true`, `"isActive":false`, "access_denied"}, {expiry, "2026-01-03T00:00:00Z", "inconsistent_snapshot"}, {`"trafficUsedBytes":"9007199254740993"`, `"trafficUsedBytes":"-1"`, "invalid_response"}, {`["https://proxy.example.invalid/synthetic-profile"]`, `[]`, "empty_snapshot"}, {`https://proxy.example.invalid/synthetic-profile`, `file:///etc/passwd`, "invalid_response"},
	} {
		t.Run(tc.want+tc.old, func(t *testing.T) {
			c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/users/") {
					io.WriteString(w, userBody())
				} else {
					io.WriteString(w, strings.Replace(subscriptionBody(), tc.old, tc.new, 1))
				}
			})
			_, e := c.ReadAssignment(context.Background(), binding())
			code(t, e, tc.want)
		})
	}
}
func TestRedirectAndTLSNeverExposeCredentials(t *testing.T) {
	var followed atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer other.Close()
	c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL)
		w.WriteHeader(302)
	})
	_, e := c.ReadAssignment(context.Background(), binding())
	code(t, e, "unexpected_response")
	if followed.Load() != 0 {
		t.Fatal("followed redirect")
	}
	c2, _, _ := fixture(t, nil)
	c2.transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	_, e = c2.ReadAssignment(context.Background(), binding())
	code(t, e, "tls_validation_failed")
}
func TestAdmissionCancellationAndClose(t *testing.T) {
	entered := make(chan struct{}, 2)
	c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() })
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, e := c.ReadAssignment(context.Background(), binding()); errs <- e }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("fixture request missing")
		}
	}
	_, e := c.ReadAssignment(context.Background(), binding())
	code(t, e, "adapter_busy")
	c.Close()
	for i := 0; i < 2; i++ {
		select {
		case e := <-errs:
			code(t, e, "cancelled")
		case <-time.After(3 * time.Second):
			t.Fatal("close did not cancel in-flight request")
		}
	}
	_, e = c.ReadAssignment(context.Background(), binding())
	code(t, e, "adapter_closed")
	c2, _, calls := fixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = c2.ReadAssignment(ctx, binding())
	code(t, e, "cancelled")
	if calls.Load() != 0 {
		t.Fatal("cancelled work transmitted")
	}
}
func TestJSONStructureBounds(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":[1,]}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), "[" + strings.Repeat("0,", 4096) + "0]", "", "{}{}"} {
		if validateJSON([]byte(raw)) == nil {
			t.Fatal("malformed or excessive JSON accepted")
		}
	}
	if validateJSON([]byte(`{"a":[null,true,1,"x"],"b":{}}`)) != nil {
		t.Fatal("valid bounded JSON rejected")
	}
}
