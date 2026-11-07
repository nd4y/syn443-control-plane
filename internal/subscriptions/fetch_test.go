package subscriptions

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
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

	"github.com/nd4y/syn443-control-plane/internal/egress"
)

var fetchNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func fetchFixture(t *testing.T, handler http.HandlerFunc) (FetchConfig, *httptest.Server) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return FetchConfig{URL: s.URL, Network: egress.Options{Roots: roots, Fixture: true, Networks: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 32)}}}, s
}
func TestHTTPSGzipQuotaAndConditionalCache(t *testing.T) {
	calls := atomic.Int32{}
	config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-source-token" {
			t.Error("authorization missing")
		}
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("unsupported encoding negotiation")
		}
		w.Header().Set("ETag", `"synthetic-version"`)
		w.Header().Set("Subscription-Userinfo", "upload=10; download=20; total=1000; expire=0")
		if r.Header.Get("If-None-Match") == `"synthetic-version"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		io.WriteString(z, "http://proxy.example.invalid:443")
		z.Close()
	})
	config.Headers = map[string]string{"Authorization": "Bearer synthetic-source-token"}
	first, e := Fetch(context.Background(), config, Cache{}, fetchNow)
	if e != nil || len(first.Raw) == 0 || first.NotModified || !first.Quota.Known || first.Quota.Used != 30 {
		t.Fatal("gzip/quota fetch")
	}
	second, e := Fetch(context.Background(), config, first.Cache, fetchNow)
	if e != nil || !second.NotModified || len(second.Raw) != 0 || calls.Load() != 2 {
		t.Fatal("conditional cache")
	}
	if bytes.Contains([]byte(fmt.Sprintf("%v %#v %v %#v", config, config, first, first)), []byte("synthetic-source-token")) {
		t.Fatal("fetch formatting disclosed credential")
	}
}
func TestFetchFailuresNeverReturnBodyOrURL(t *testing.T) {
	for _, c := range []struct {
		status                      int
		body, contentType, encoding string
		want                        error
	}{
		{401, "synthetic-source-body-denied", "text/plain", "", ErrAccess}, {403, "synthetic-source-body-denied", "text/plain", "", ErrAccess}, {410, "synthetic-source-body-revoked", "text/plain", "", ErrRevoked}, {500, "synthetic-source-body-retry", "text/plain", "", ErrFetch},
		{200, "", "text/plain", "", ErrEmpty}, {200, "   ", "text/plain", "", ErrEmpty}, {200, "<html>synthetic</html>", "text/plain", "", ErrInvalid}, {200, "not html", "text/html", "", ErrInvalid},
		{200, "synthetic", "text/plain", "br", ErrUnsupported}, {200, "broken-gzip", "text/plain", "gzip", ErrInvalid}, {304, "", "text/plain", "", ErrInvalid},
	} {
		config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", c.contentType)
			if c.encoding != "" {
				w.Header().Set("Content-Encoding", c.encoding)
			}
			w.WriteHeader(c.status)
			io.WriteString(w, c.body)
		})
		p, e := Fetch(context.Background(), config, Cache{}, fetchNow)
		if !errors.Is(e, c.want) || len(p.Raw) != 0 {
			t.Fatal("failure classification")
		}
		if strings.Contains(e.Error(), config.URL) || strings.Contains(e.Error(), c.body) && c.body != "" {
			t.Fatal("untrusted response escaped fixed errors")
		}
	}
}
func TestSourceSizeAndCompressedBombAreBounded(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
			var out io.Writer = w
			var zipped *gzip.Writer
			if compressed {
				w.Header().Set("Content-Encoding", "gzip")
				zipped = gzip.NewWriter(w)
				out = zipped
			}
			io.Copy(out, strings.NewReader(strings.Repeat("a", MaxBytes+1)))
			if zipped != nil {
				zipped.Close()
			}
		})
		p, e := Fetch(context.Background(), config, Cache{}, fetchNow)
		if !errors.Is(e, ErrSize) || len(p.Raw) != 0 {
			t.Fatal("body/decompression size limit")
		}
	}
}
func TestRedirectValidationAndNoCrossOriginCredentialOrCache(t *testing.T) {
	seen := atomic.Int32{}
	other, otherServer := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("If-None-Match") != "" {
			t.Error("cross-origin credential or cache")
		}
		w.Header().Set("ETag", `"not-an-original-url-validator"`)
		io.WriteString(w, "synthetic-profile")
	})
	config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL)
		w.WriteHeader(302)
	})
	config.Network.Roots.AddCert(otherServer.Certificate())
	config.Headers = map[string]string{"Authorization": "Bearer synthetic-source-token"}
	if _, e := Fetch(context.Background(), config, Cache{ETag: `"original"`}, fetchNow); !errors.Is(e, ErrAccess) || seen.Load() != 0 {
		t.Fatal("unapproved redirect")
	}
	config.RedirectOrigins = []string{other.URL}
	p, e := Fetch(context.Background(), config, Cache{ETag: `"original"`}, fetchNow)
	if e != nil || seen.Load() != 1 || len(p.Raw) == 0 || p.Cache.ETag != "" {
		t.Fatal("approved origin or URL cache binding")
	}
}
func TestRedirectCycleAndUnsolicited304CannotRebindCache(t *testing.T) {
	calls := atomic.Int32{}
	config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/again")
		w.WriteHeader(302)
	})
	if _, e := Fetch(context.Background(), config, Cache{}, fetchNow); !errors.Is(e, ErrAccess) || calls.Load() != 4 {
		t.Fatal("redirect bound")
	}
	config, _ = fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/new-resource")
			w.WriteHeader(302)
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			t.Error("cache header rebound to another URL")
		}
		w.WriteHeader(304)
	})
	if _, e := Fetch(context.Background(), config, Cache{ETag: `"old-resource"`}, fetchNow); !errors.Is(e, ErrInvalid) {
		t.Fatal("unsolicited new-resource cache hit")
	}
}
func TestQuotaExpiryOverflowDuplicatesAndUnknown(t *testing.T) {
	q, e := ParseQuota("", fetchNow)
	if e != nil || q.Known || q.ObservedAt != fetchNow.Unix() {
		t.Fatal("unknown quota is not zero")
	}
	for _, raw := range []string{"upload=1;download=2", "upload=1;download=2;total=0;upload=1", "upload=-1;download=2;total=0", "upload=1;download=2;total=0;arbitrary=1", "upload=18446744073709551615;download=1;total=0", "upload=1;download=2;total=0;expire=9007199254740992"} {
		if _, e := ParseQuota(raw, fetchNow); e == nil {
			t.Fatal("invalid quota")
		}
	}
	config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=1;download=2;total=0;expire=%d", fetchNow.Unix()-1))
		io.WriteString(w, "synthetic")
	})
	if p, e := Fetch(context.Background(), config, Cache{}, fetchNow); !errors.Is(e, ErrExpired) || len(p.Raw) != 0 {
		t.Fatal("confirmed expiry kept eligible bytes")
	}
}
func TestFetchInputAndCancellationBounds(t *testing.T) {
	config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "synthetic") })
	for _, headers := range []map[string]string{{"Host": "untrusted"}, {"X-HWID": "synthetic"}, {"Authorization": "bad\r\nheader"}, {"Authorization": "one", "authorization": "two"}} {
		c := config
		c.Headers = headers
		if _, e := Fetch(context.Background(), c, Cache{}, fetchNow); e == nil {
			t.Fatal("request header boundary")
		}
	}
	if _, e := Fetch(context.Background(), config, Cache{ETag: "bad\r\nvalue"}, fetchNow); e == nil {
		t.Fatal("cache header injection")
	}
	c := config
	c.RedirectOrigins = []string{config.URL + "/not-an-origin"}
	if _, e := Fetch(context.Background(), c, Cache{}, fetchNow); e == nil {
		t.Fatal("redirect grant must be origin")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Fetch(ctx, config, Cache{}, fetchNow); !errors.Is(e, ErrFetch) {
		t.Fatal("cancellation")
	}
	c = config
	c.Network.Fixture = false
	if _, e := Fetch(context.Background(), c, Cache{}, fetchNow); !errors.Is(e, ErrAccess) {
		t.Fatal("ungranted actual address")
	}
	c = config
	c.Network.Roots = nil
	if _, e := Fetch(context.Background(), c, Cache{}, fetchNow); !errors.Is(e, ErrTLS) {
		t.Fatal("TLS authority failure was not classified")
	}
}

func TestFetchPreflightHasNoNetworkSideEffects(t *testing.T) {
	calls := atomic.Int32{}
	config, _ := fetchFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "synthetic") })
	if e := ValidateFetchConfig(config); e != nil || calls.Load() != 0 {
		t.Fatal("validation sent provider traffic")
	}
	config.Headers = map[string]string{"Host": "not-authorized"}
	if e := ValidateFetchConfig(config); e == nil {
		t.Fatal("unsafe header preflight")
	}
	config.Headers = nil
	config.Network.Networks = []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0)}
	if e := ValidateFetchConfig(config); e == nil {
		t.Fatal("broad network grant preflight")
	}
}
