package netbirdapi

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const token = "synthetic-netbird-management-token"

var now = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func tag() string { return base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }
func keyExample() keyWire {
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		panic("fixture entropy")
	}
	name, _ := operationName(tag())
	return keyWire{ID: "key-a", Name: name, Key: fmt.Sprintf("%x-%x-%x-%x-%x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:]), Type: "one-off", Expires: now.Add(24 * time.Hour), Valid: true, Groups: []string{"group-a"}, UsageLimit: 1}
}
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func fixture(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	example := keyExample()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Token "+token || r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" {
			t.Error("management credential boundary")
			w.WriteHeader(403)
			return
		}
		if handler != nil {
			handler(w, r)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/accounts":
			writeJSON(w, []map[string]string{{"id": "account-a"}})
		case "GET /api/setup-keys":
			writeJSON(w, []keyWire{example})
		case "GET /api/setup-keys/key-a":
			writeJSON(w, example)
		case "POST /api/setup-keys":
			var request map[string]any
			if json.NewDecoder(r.Body).Decode(&request) != nil || len(request) != 7 || request["name"] != example.Name || request["type"] != "one-off" || request["expires_in"] != float64(86400) || request["usage_limit"] != float64(1) || request["ephemeral"] != false || request["allow_extra_dns_labels"] != false {
				t.Error("unsafe setup key parameters")
				w.WriteHeader(400)
				return
			}
			writeJSON(w, example)
		case "DELETE /api/setup-keys/key-a":
			w.WriteHeader(204)
		default:
			t.Error("unexpected management path")
			w.WriteHeader(404)
		}
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	c, e := New(Config{ResourceID: "mesh-a", APIOrigin: s.URL, AccountID: "account-a", Token: token, Roots: roots, AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, FixtureLoopback: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c, s, calls
}
func wantError(t *testing.T, e error, unknown bool) *Error {
	t.Helper()
	var v *Error
	if !errors.As(e, &v) || v.OutcomeUnknown != unknown {
		t.Fatal("incorrect mutation outcome", e, unknown)
	}
	if strings.Contains(e.Error(), token) || strings.Contains(e.Error(), "https://") {
		t.Fatal("error leaked management data")
	}
	return v
}
func TestOneOffAccountBoundSetupCreationMetadataAndOwnershipCheckedRevocation(t *testing.T) {
	c, _, calls := fixture(t, nil)
	created, e := c.CreateOneOff(context.Background(), tag(), []string{"group-a"}, now)
	if e != nil || created.ID != "key-a" || !setupValue.MatchString(created.Secret) || !created.Expires.Equal(now.Add(24*time.Hour)) || calls.Load() != 2 {
		t.Fatal("one-off creation", e)
	}
	data, _ := json.Marshal(created)
	config, _ := json.Marshal(c.config)
	if strings.Contains(string(data), created.Secret) || strings.Contains(fmt.Sprintf("%v %#v %v %#v %v %#v", created, created, c, c, c.config, c.config), created.Secret) || string(config) != "{}" {
		t.Fatal("secret diagnostics/serialization")
	}
	found, e := c.FindOperation(context.Background(), tag())
	if e != nil || len(found) != 1 || found[0].ID != created.ID || found[0].Secret != "" {
		t.Fatal("metadata exposed setup value", e)
	}
	if e = c.RevokeOwned(context.Background(), tag(), created.ID); e != nil {
		t.Fatal("owned revoke", e)
	}
	c.Close()
	wantError(t, func() error { _, e := c.FindOperation(context.Background(), tag()); return e }(), false)
}
func TestAccountAndKeyOwnershipAreRecheckedBeforeEveryMutation(t *testing.T) {
	for _, scenario := range []string{"account", "other-account", "name", "id", "missing", "revoked-delete"} {
		t.Run(scenario, func(t *testing.T) {
			var writes atomic.Int32
			c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" || r.Method == "POST" {
					writes.Add(1)
					w.WriteHeader(404)
					return
				}
				if r.URL.Path == "/api/accounts" {
					if scenario == "account" {
						writeJSON(w, []map[string]string{{"id": "foreign"}})
					} else if scenario == "other-account" {
						writeJSON(w, []map[string]string{{"id": "account-a"}, {"id": "foreign"}})
					} else {
						writeJSON(w, []map[string]string{{"id": "account-a"}})
					}
					return
				}
				key := keyExample()
				if scenario == "name" {
					key.Name = "unrelated"
				}
				if scenario == "id" {
					key.ID = "other-key"
				}
				if scenario == "missing" {
					w.WriteHeader(404)
					return
				}
				writeJSON(w, key)
			})
			e := c.RevokeOwned(context.Background(), tag(), "key-a")
			if scenario == "missing" || scenario == "revoked-delete" {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				wantError(t, e, false)
			}
			want := int32(0)
			if scenario == "revoked-delete" {
				want = 1
			}
			if writes.Load() != want {
				t.Fatal("foreign key mutated")
			}
		})
	}
}
func TestCreateFailureIsNotRetriedAndRemainsUnknownAfterDispatch(t *testing.T) {
	for _, scenario := range []string{"lost-reply", "malformed", "duplicate", "wrong-groups", "used", "expiry", "masked", "redirect", "denied", "rate", "server", "oversize", "compressed", "missing-count", "null-count"} {
		t.Run(scenario, func(t *testing.T) {
			var creates atomic.Int32
			c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/accounts" {
					writeJSON(w, []map[string]string{{"id": "account-a"}})
					return
				}
				if r.Method != "POST" {
					t.Error("mutation reconciliation must be explicit")
					w.WriteHeader(400)
					return
				}
				creates.Add(1)
				key := keyExample()
				switch scenario {
				case "lost-reply":
					conn, _, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
						return
					}
					conn.Close()
					return
				case "malformed":
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, "{")
					return
				case "duplicate":
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `{"id":"a","id":"b"}`)
					return
				case "wrong-groups":
					key.Groups = []string{"foreign"}
				case "used":
					key.UsedTimes = 1
				case "expiry":
					key.Expires = now.Add(48 * time.Hour)
				case "masked":
					key.Key = "masked"
				case "redirect":
					w.Header().Set("Location", "https://foreign.example.invalid")
					w.WriteHeader(302)
					return
				case "denied":
					w.WriteHeader(403)
					return
				case "rate":
					w.WriteHeader(429)
					return
				case "server":
					w.WriteHeader(503)
					return
				case "oversize":
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, strings.Repeat("x", maxBody+1))
					return
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "missing-count", "null-count":
					raw, _ := json.Marshal(key)
					var obj map[string]any
					json.Unmarshal(raw, &obj)
					if scenario == "missing-count" {
						delete(obj, "used_times")
					} else {
						obj["used_times"] = nil
					}
					writeJSON(w, obj)
					return
				}
				writeJSON(w, key)
			})
			value, e := c.CreateOneOff(context.Background(), tag(), []string{"group-a"}, now)
			wantError(t, e, true)
			if value.Secret != "" || creates.Load() != 1 {
				t.Fatal("uncertain creation retried or leaked key")
			}
		})
	}
}
func TestInvalidConfigOperationsTLSAndCancellationCannotSendSetupRequest(t *testing.T) {
	c, s, calls := fixture(t, nil)
	for _, change := range []func(*Config){
		func(c *Config) { c.ResourceID = "../escape" }, func(c *Config) { c.AccountID = "" }, func(c *Config) { c.Token = "short" }, func(c *Config) { c.Token = token + "\n" },
		func(c *Config) { c.APIOrigin = "http://example.invalid" }, func(c *Config) {
			u := url.URL{Scheme: "https", Host: "example.invalid", User: url.UserPassword("synthetic-user", "synthetic-password")}
			c.APIOrigin = u.String()
		}, func(c *Config) { c.APIOrigin = "https://example.invalid/path" }, func(c *Config) { c.APIOrigin = "https://example.invalid/?query" }, func(c *Config) { c.APIOrigin = "https://example.invalid/#fragment" }, func(c *Config) { c.APIOrigin = "https://example.invalid:0" },
	} {
		copy := c.config
		change(&copy)
		if invalid, e := New(copy); e == nil {
			invalid.Close()
			t.Fatal("unsafe config accepted")
		}
	}
	for _, groups := range [][]string{nil, {"group-a", "group-a"}, {"../group"}, make([]string, 17)} {
		_, e := c.CreateOneOff(context.Background(), tag(), groups, now)
		wantError(t, e, false)
	}
	_, e := c.CreateOneOff(context.Background(), "invalid", []string{"group-a"}, now)
	wantError(t, e, false)
	_, e = c.CreateOneOff(context.Background(), tag(), []string{"group-a"}, time.Time{})
	wantError(t, e, false)
	_, e = c.FindOperation(nil, tag())
	wantError(t, e, false)
	_, e = c.FindOperation(context.Background(), "invalid")
	wantError(t, e, false)
	wantError(t, c.RevokeOwned(context.Background(), tag(), "../foreign"), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = c.FindOperation(ctx, tag())
	wantError(t, e, false)
	if calls.Load() != 0 {
		t.Fatal("invalid operation reached provider")
	}
	for _, kind := range []string{"wrong-root", "production-loopback"} {
		copy := c.config
		if kind == "wrong-root" {
			copy.Roots = x509.NewCertPool()
		} else {
			copy.FixtureLoopback = false
		}
		other, e := New(copy)
		if e != nil {
			t.Fatal(e)
		}
		_, e = other.CreateOneOff(context.Background(), tag(), []string{"group-a"}, now)
		other.Close()
		wantError(t, e, false)
		if calls.Load() != 0 {
			t.Fatal("TLS/address boundary bypassed")
		}
	}
	if !strings.HasPrefix(s.URL, "https://") {
		t.Fatal("fixture transport")
	}
}
func TestMetadataRejectsNullDuplicateAndUnsafeRemoteIDsWithoutTreatingThemAsUnused(t *testing.T) {
	for _, raw := range []string{`null`, `{"id":null}`, `{"id":true}`, `{"id":1.5}`, `{"id":-1}`, `{"id":"../x"}`} {
		var key keyWire
		if json.Unmarshal([]byte(raw), &key) == nil {
			t.Fatal("invalid key metadata accepted")
		}
	}
	for _, raw := range []string{`42`, `"key-a"`} {
		var id remoteID
		if json.Unmarshal([]byte(raw), &id) != nil {
			t.Fatal("documented external ID encoding")
		}
	}
	var key keyWire
	encoded, _ := json.Marshal(keyExample())
	if json.Unmarshal(encoded, &key) != nil {
		t.Fatal("key fixture")
	}
	key.UsedTimes = -1
	if _, e := metadata(key); e == nil {
		t.Fatal("negative use count")
	}
}

func TestCloseCancelsBoundedReadersAndMutationBodyCancellationRemainsUnknown(t *testing.T) {
	entered := make(chan struct{}, 2)
	c, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() })
	finished := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, e := c.FindOperation(context.Background(), tag()); finished <- e }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("reader did not enter")
		}
	}
	_, e := c.FindOperation(context.Background(), tag())
	if wantError(t, e, false).Code != "busy" {
		t.Fatal("unbounded parallel requests")
	}
	c.Close()
	for i := 0; i < 2; i++ {
		select {
		case e := <-finished:
			if wantError(t, e, false).Code != "cancelled" {
				t.Fatal("Close lost cancellation")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not cancel reads")
		}
	}
	posted := make(chan struct{})
	mutating, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/accounts" {
			writeJSON(w, []map[string]string{{"id": "account-a"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.(http.Flusher).Flush()
		close(posted)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, e := mutating.CreateOneOff(ctx, tag(), []string{"group-a"}, now); result <- e }()
	select {
	case <-posted:
	case <-time.After(2 * time.Second):
		t.Fatal("mutation did not enter")
	}
	cancel()
	select {
	case e := <-result:
		if wantError(t, e, true).Code != "cancelled" {
			t.Fatal("mutation cancellation was treated as a safe retry")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("body read ignored cancellation")
	}
}
