package subscriptions

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/egress"
)

var ErrFetch = errors.New("subscription_fetch_unavailable")
var ErrTLS = errors.New("subscription_tls_failed")
var ErrAccess = errors.New("subscription_access_denied")
var ErrRevoked = errors.New("subscription_access_revoked")
var ErrExpired = errors.New("subscription_expired")
var ErrEmpty = errors.New("subscription_empty_response")
var ErrSize = errors.New("subscription_size_limit")

type FetchConfig struct {
	URL             string
	Headers         map[string]string
	RedirectOrigins []string
	Network         egress.Options
}

func (FetchConfig) String() string   { return "SubscriptionFetch([redacted])" }
func (FetchConfig) GoString() string { return "SubscriptionFetch([redacted])" }

type Cache struct{ ETag, LastModified string }
type Quota struct {
	Known      bool   `json:"known"`
	Used       uint64 `json:"used"`
	Limit      uint64 `json:"limit"`
	ExpiresAt  int64  `json:"expiresAt"`
	ObservedAt int64  `json:"observedAt"`
}
type Fetched struct {
	Raw         []byte `json:"-"`
	Cache       Cache
	NotModified bool
	Quota       Quota
}

func (Fetched) String() string   { return "SubscriptionFetched([redacted])" }
func (Fetched) GoString() string { return "SubscriptionFetched([redacted])" }
func safeHeader(s string, max int) bool {
	return len(s) <= max && strings.IndexFunc(s, func(r rune) bool { return r < 32 && r != '\t' || r == 127 }) < 0
}
func origin(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || len(raw) > 8192 {
		return "", ErrInvalid
	}
	return "https://" + strings.ToLower(u.Host), nil
}
func ParseQuota(raw string, now time.Time) (Quota, error) {
	q := Quota{ObservedAt: now.Unix()}
	if raw == "" {
		return q, nil
	}
	if len(raw) > 1024 {
		return q, ErrInvalid
	}
	fields := map[string]uint64{}
	for _, part := range strings.Split(raw, ";") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) != 2 {
			return q, ErrInvalid
		}
		name := pair[0]
		if name != "upload" && name != "download" && name != "total" && name != "expire" {
			return q, ErrUnsupported
		}
		if _, ok := fields[name]; ok {
			return q, ErrInvalid
		}
		value := pair[1]
		if value == "" || len(value) > 20 || strings.Trim(value, "0123456789") != "" {
			return q, ErrInvalid
		}
		n, e := strconv.ParseUint(value, 10, 64)
		if e != nil {
			return q, ErrInvalid
		}
		fields[name] = n
	}
	up, u := fields["upload"]
	down, d := fields["download"]
	limit, l := fields["total"]
	if !u || !d || !l || up+down < up || fields["expire"] > 9007199254740991 {
		return q, ErrInvalid
	}
	q.Known = true
	q.Used = up + down
	q.Limit = limit
	q.ExpiresAt = int64(fields["expire"])
	return q, nil
}

// Fetch never includes URL, response text or credentials in an error. A caller
// owns source-specific backoff, expiry, immutable snapshots and promotion review.
func prepareFetch(config FetchConfig) (string, map[string]bool, http.Header, error) {
	initial, e := origin(config.URL)
	if e != nil || len(config.Headers) > 16 || len(config.RedirectOrigins) > 3 {
		return "", nil, nil, ErrInvalid
	}
	allowed := map[string]bool{initial: true}
	for _, raw := range config.RedirectOrigins {
		o, e := origin(raw)
		if e != nil || o != raw {
			return "", nil, nil, ErrInvalid
		}
		allowed[o] = true
	}
	headers := http.Header{}
	for k, v := range config.Headers {
		name := http.CanonicalHeaderKey(k)
		if name == "" || headers.Get(name) != "" || len(name) > 128 || !safeHeader(k, 128) || !safeHeader(v, 4096) || v == "" {
			return "", nil, nil, ErrInvalid
		}
		switch name {
		case "Authorization", "X-Api-Key", "User-Agent", "Accept":
		default:
			return "", nil, nil, ErrUnsupported
		}
		headers.Set(name, v)
	}
	return initial, allowed, headers, nil
}

// ValidateFetchConfig performs no DNS lookup or network request.
func ValidateFetchConfig(config FetchConfig) error {
	_, allowed, _, e := prepareFetch(config)
	if e != nil {
		return e
	}
	for endpoint := range allowed {
		tr, e := egress.NewTransport(endpoint, config.Network)
		if e != nil {
			return ErrInvalid
		}
		tr.CloseIdleConnections()
	}
	return nil
}
func Fetch(ctx context.Context, config FetchConfig, cached Cache, now time.Time) (Fetched, error) {
	var result Fetched
	initial, allowed, headers, e := prepareFetch(config)
	if e != nil {
		return result, e
	}
	if !safeHeader(cached.ETag, 1024) || !safeHeader(cached.LastModified, 128) {
		return result, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	current := config.URL
	redirected := false
	for redirects := 0; redirects <= 3; redirects++ {
		o, e := origin(current)
		if e != nil || !allowed[o] {
			return result, ErrAccess
		}
		transport, e := egress.NewTransport(current, config.Network)
		if e != nil {
			return result, ErrAccess
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, "GET", current, nil)
		if e != nil {
			return result, ErrInvalid
		}
		req.Header.Set("User-Agent", "SYN443/1")
		req.Header.Set("Accept-Encoding", "gzip")
		if o == initial {
			for k, v := range headers {
				req.Header[k] = append([]string(nil), v...)
			}
			if !redirected {
				if cached.ETag != "" {
					req.Header.Set("If-None-Match", cached.ETag)
				}
				if cached.LastModified != "" {
					req.Header.Set("If-Modified-Since", cached.LastModified)
				}
			}
		}
		res, e := client.Do(req)
		if e != nil {
			if errors.Is(e, egress.ErrAddress) {
				return result, ErrAccess
			}
			var certificate *tls.CertificateVerificationError
			if errors.As(e, &certificate) {
				return result, ErrTLS
			}
			return result, ErrFetch
		}
		if res.StatusCode == 301 || res.StatusCode == 302 || res.StatusCode == 303 || res.StatusCode == 307 || res.StatusCode == 308 {
			location := res.Header.Get("Location")
			res.Body.Close()
			if redirects == 3 || location == "" || len(location) > 8192 {
				return result, ErrAccess
			}
			u, e := url.Parse(location)
			if e != nil {
				return result, ErrAccess
			}
			current = req.URL.ResolveReference(u).String()
			redirected = true
			continue
		}
		if res.StatusCode != 200 && res.StatusCode != 304 {
			res.Body.Close()
			switch res.StatusCode {
			case 401, 403:
				return result, ErrAccess
			case 410:
				return result, ErrRevoked
			default:
				return result, ErrFetch
			}
		}
		result.Quota, e = ParseQuota(res.Header.Get("Subscription-Userinfo"), now)
		if e != nil {
			res.Body.Close()
			return Fetched{}, e
		}
		if result.Quota.ExpiresAt > 0 && result.Quota.ExpiresAt <= now.Unix() {
			res.Body.Close()
			return Fetched{}, ErrExpired
		}
		result.Cache = Cache{ETag: res.Header.Get("ETag"), LastModified: res.Header.Get("Last-Modified")}
		if !safeHeader(result.Cache.ETag, 1024) || !safeHeader(result.Cache.LastModified, 128) {
			res.Body.Close()
			return Fetched{}, ErrInvalid
		}
		if res.StatusCode == 304 {
			res.Body.Close()
			if redirected || cached.ETag == "" && cached.LastModified == "" {
				return Fetched{}, ErrInvalid
			}
			result.NotModified = true
			if result.Cache.ETag == "" {
				result.Cache.ETag = cached.ETag
			}
			if result.Cache.LastModified == "" {
				result.Cache.LastModified = cached.LastModified
			}
			return result, nil
		}
		// Cache validators belong to a resource URL, not just its HTTPS origin.
		// Redirected sources are fetched fully instead of rebinding old validators.
		if redirected {
			result.Cache = Cache{}
		}
		kind, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if kind == "text/html" {
			res.Body.Close()
			return Fetched{}, ErrInvalid
		}
		reader := io.Reader(io.LimitReader(res.Body, MaxBytes+1))
		var zipped *gzip.Reader
		encoding := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding")))
		if encoding == "gzip" {
			zipped, e = gzip.NewReader(reader)
			if e != nil {
				res.Body.Close()
				return Fetched{}, ErrInvalid
			}
			reader = zipped
		} else if encoding != "" && encoding != "identity" {
			res.Body.Close()
			return Fetched{}, ErrUnsupported
		}
		raw, e := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
		if zipped != nil {
			zipped.Close()
		}
		res.Body.Close()
		if e != nil {
			return Fetched{}, ErrFetch
		}
		if len(raw) > MaxBytes {
			return Fetched{}, ErrSize
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			return Fetched{}, ErrEmpty
		}
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "<") {
			return Fetched{}, ErrInvalid
		}
		result.Raw = raw
		return result, nil
	}
	return Fetched{}, ErrAccess
}
