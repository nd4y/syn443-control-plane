// Package remnawave implements the pinned 3.4 read-only protected API subset.
package remnawave

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/egress"
	"github.com/nd4y/syn443-control-plane/internal/resources"
)

const maxBody = 2 * 1024 * 1024

var numericID = regexp.MustCompile(`^[1-9][0-9]{0,14}$`)
var shortID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Config struct {
	FixtureLoopback bool // Owner-only isolated literal-loopback test context.
	Instance        resources.Instance
	Token           string
	// Optional owner-installed trust roots still require ordinary TLS verification.
	Roots *x509.CertPool
	// Non-public IPs require an explicit owner network grant. Tests use loopback /32.
	AllowedNetworks []netip.Prefix
}

func (Config) String() string     { return "RemnawaveConfig([redacted])" }
func (c Config) GoString() string { return c.String() }

type Client struct {
	instance  resources.Instance
	origin    string
	token     string
	http      *http.Client
	transport *http.Transport
	now       func() time.Time
	slots     chan struct{}
	closed    atomic.Bool
	lifetime  context.Context
	stop      context.CancelFunc
}

func (*Client) String() string     { return "RemnawaveClient([redacted])" }
func (c *Client) GoString() string { return c.String() }

func New(c Config) (*Client, error) {
	if err := c.Instance.Validate(); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.Instance.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, resources.Failure("invalid_endpoint", false)
	}
	if len(c.Token) < 16 || len(c.Token) > 4096 || strings.IndexFunc(c.Token, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return nil, resources.Failure("invalid_credential", false)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, resources.Failure("invalid_endpoint", false)
	}
	tr, e := egress.NewTransport(c.Instance.Endpoint, egress.Options{Roots: c.Roots, Networks: c.AllowedNetworks, Fixture: c.FixtureLoopback})
	if e != nil {
		return nil, resources.Failure("invalid_network_grant", false)
	}

	h := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	lifetime, stop := context.WithCancel(context.Background())
	return &Client{instance: c.Instance, origin: "https://" + u.Host, token: c.Token, http: h, transport: tr, now: time.Now, slots: make(chan struct{}, 2), lifetime: lifetime, stop: stop}, nil
}
func (c *Client) Close() {
	if c.closed.CompareAndSwap(false, true) {
		c.stop()
		c.transport.CloseIdleConnections()
	}
}
func (c *Client) Binding(externalUserID string) resources.Binding {
	return resources.Binding{ResourceID: c.instance.ResourceID, ExternalUserID: externalUserID}
}

// Duplicate fields and excessive JSON structure are rejected even in ignored fields.
func validateJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return resources.Failure("invalid_response", false)
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if del, ok := t.(json.Delim); ok {
			count := 0
			seen := map[string]bool{}
			for d.More() {
				count++
				if count > 4096 {
					return resources.Failure("invalid_response", false)
				}
				if del == '{' {
					key, e := d.Token()
					if e != nil {
						return e
					}
					k, ok := key.(string)
					if !ok || seen[k] {
						return resources.Failure("invalid_response", false)
					}
					seen[k] = true
				}
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return resources.Failure("invalid_response", false)
	}
	return nil
}
func (c *Client) get(ctx context.Context, path string, out any) error {
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if e != nil {
		return resources.Failure("invalid_request", false)
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Accept", "application/json")
	response, e := c.http.Do(r)
	if e != nil {
		if ctx.Err() != nil {
			return resources.Failure("cancelled", false)
		}
		if errors.Is(e, egress.ErrAddress) {
			return resources.Failure("address_not_allowed", false)
		}
		var f *resources.Error
		if errors.As(e, &f) {
			return f
		}
		var cert *tls.CertificateVerificationError
		if errors.As(e, &cert) {
			return resources.Failure("tls_validation_failed", false)
		}
		return resources.Failure("provider_unavailable", true)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case 200:
	case 401, 403:
		return resources.Failure("access_denied", false)
	case 404:
		return resources.Failure("assignment_not_found", false)
	case 429:
		return resources.Failure("rate_limited", true)
	default:
		if response.StatusCode >= 500 {
			return resources.Failure("provider_unavailable", true)
		}
		return resources.Failure("unexpected_response", false)
	}
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return resources.Failure("invalid_response", false)
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if e != nil {
		if ctx.Err() != nil {
			return resources.Failure("cancelled", false)
		}
		return resources.Failure("provider_unavailable", true)
	}
	if len(b) > maxBody || validateJSON(b) != nil || json.Unmarshal(b, out) != nil {
		return resources.Failure("invalid_response", false)
	}
	return nil
}

func (c *Client) ReadAssignment(ctx context.Context, b resources.Binding) (resources.Snapshot, error) {
	var empty resources.Snapshot
	if b.ResourceID != c.instance.ResourceID || !numericID.MatchString(b.ExternalUserID) {
		return empty, resources.Failure("invalid_binding", false)
	}
	if c.closed.Load() {
		return empty, resources.Failure("adapter_closed", false)
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return empty, resources.Failure("adapter_busy", true)
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	if ctx.Err() != nil || c.lifetime.Err() != nil {
		return empty, resources.Failure("cancelled", false)
	}
	var user struct {
		Response struct {
			ID     json.RawMessage `json:"id"`
			Short  string          `json:"shortUuid"`
			Status string          `json:"status"`
			Expire string          `json:"expireAt"`
		} `json:"response"`
	}
	if e := c.get(ctx, "/api/users/"+b.ExternalUserID, &user); e != nil {
		return empty, e
	}
	if string(user.Response.ID) != b.ExternalUserID || !shortID.MatchString(user.Response.Short) {
		return empty, resources.Failure("identity_mismatch", false)
	}
	expires, e := time.Parse(time.RFC3339Nano, user.Response.Expire)
	if e != nil {
		return empty, resources.Failure("invalid_response", false)
	}
	if !knownStatus(user.Response.Status) {
		return empty, resources.Failure("invalid_response", false)
	}
	if !expires.After(c.now()) || user.Response.Status == "EXPIRED" {
		return empty, resources.Failure("assignment_expired", false)
	}
	if user.Response.Status != "ACTIVE" {
		return empty, resources.Failure("assignment_revoked", false)
	}
	var sub struct {
		Response struct {
			Found *bool `json:"isFound"`
			User  struct {
				Short   string `json:"shortUuid"`
				Active  *bool  `json:"isActive"`
				Status  string `json:"userStatus"`
				Expires string `json:"expiresAt"`
				Used    string `json:"trafficUsedBytes"`
				Limit   string `json:"trafficLimitBytes"`
			} `json:"user"`
			Links []string `json:"links"`
		} `json:"response"`
	}
	if e := c.get(ctx, "/api/subscriptions/by-id/"+b.ExternalUserID, &sub); e != nil {
		return empty, e
	}
	s := sub.Response
	if s.Found == nil {
		return empty, resources.Failure("invalid_response", false)
	}
	if !*s.Found {
		return empty, resources.Failure("assignment_not_found", false)
	}
	if s.User.Short != user.Response.Short {
		return empty, resources.Failure("identity_mismatch", false)
	}
	exp, e := time.Parse(time.RFC3339Nano, s.User.Expires)
	if e != nil || !exp.Equal(expires) {
		return empty, resources.Failure("inconsistent_snapshot", true)
	}
	if s.User.Active == nil || !knownStatus(s.User.Status) {
		return empty, resources.Failure("invalid_response", false)
	}
	if !exp.After(c.now()) || s.User.Status == "EXPIRED" {
		return empty, resources.Failure("assignment_expired", false)
	}
	if !*s.User.Active || s.User.Status != "ACTIVE" {
		return empty, resources.Failure("assignment_revoked", false)
	}
	used, e := strconv.ParseUint(s.User.Used, 10, 63)
	limit, e2 := strconv.ParseUint(s.User.Limit, 10, 63)
	if e != nil || e2 != nil || len(s.Links) > 4096 {
		return empty, resources.Failure("invalid_response", false)
	}
	if len(s.Links) == 0 {
		return empty, resources.Failure("empty_snapshot", true)
	}
	for _, link := range s.Links {
		u, e := url.Parse(link)
		if e != nil || len(link) < 1 || len(link) > 8192 || !linkScheme(u.Scheme) || strings.IndexFunc(link, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return empty, resources.Failure("invalid_response", false)
		}
	}
	if c.closed.Load() || ctx.Err() != nil {
		return empty, resources.Failure("cancelled", false)
	}
	return resources.Snapshot{Ref: resources.ObjectRef{ResourceID: b.ResourceID, ExternalObjectID: b.ExternalUserID}, ObservedAt: c.now().UTC(), ExpiresAt: exp.UTC(), TrafficUsedBytes: used, TrafficLimitBytes: limit, Links: append([]string(nil), s.Links...)}, nil
}
func knownStatus(s string) bool {
	return s == "ACTIVE" || s == "DISABLED" || s == "LIMITED" || s == "EXPIRED"
}
func linkScheme(s string) bool {
	switch s {
	case "vless", "vmess", "trojan", "ss", "socks", "http", "https":
		return true
	}
	return false
}
