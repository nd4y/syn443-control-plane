// Package netbirdapi implements a bounded single-account management API subset.
// It does not itself authorize enrollment, sign credentials or retry mutations.
package netbirdapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/egress"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const maxBody = 65536

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var numericID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var setupValue = regexp.MustCompile(`^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$`)

type Config struct {
	ResourceID      string         `json:"-"`
	APIOrigin       string         `json:"-"`
	AccountID       string         `json:"-"`
	Token           string         `json:"-"`
	Roots           *x509.CertPool `json:"-"`
	AllowedNetworks []netip.Prefix `json:"-"`
	FixtureLoopback bool           `json:"-"`
}

func (Config) String() string   { return "NetBirdAPIConfig([redacted])" }
func (Config) GoString() string { return "NetBirdAPIConfig([redacted])" }

// OutcomeUnknown means a mutation may have reached the provider. A durable
// broker must reconcile the same operation; it must not blindly issue again.
// No URL, credential, response body or underlying transport error is retained.
type Error struct {
	Code           string
	OutcomeUnknown bool
}

func (e *Error) Error() string                { return e.Code }
func failure(code string, unknown bool) error { return &Error{code, unknown} }

type remoteID string

func (id *remoteID) UnmarshalJSON(raw []byte) error {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if !identifier.MatchString(text) {
			return failure("invalid_response", false)
		}
	} else {
		text = string(raw)
		if !numericID.MatchString(text) {
			return failure("invalid_response", false)
		}
	}
	*id = remoteID(text)
	return nil
}

type keyWire struct {
	ID         remoteID  `json:"id"`
	Name       string    `json:"name"`
	Key        string    `json:"key"`
	Type       string    `json:"type"`
	Expires    time.Time `json:"expires"`
	Valid      bool      `json:"valid"`
	Revoked    bool      `json:"revoked"`
	UsedTimes  int64     `json:"used_times"`
	Groups     []string  `json:"auto_groups"`
	UsageLimit int64     `json:"usage_limit"`
	Ephemeral  bool      `json:"ephemeral"`
	ExtraDNS   bool      `json:"allow_extra_dns_labels"`
}

func (w *keyWire) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return failure("invalid_response", false)
	}
	for _, name := range []string{"id", "name", "expires", "valid", "revoked", "used_times", "auto_groups"} {
		v, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return failure("invalid_response", false)
		}
	}
	type plain keyWire
	var value plain
	if json.Unmarshal(raw, &value) != nil {
		return failure("invalid_response", false)
	}
	*w = keyWire(value)
	return nil
}

// Secret is returned only by a successful creation and is never JSON-exported.
// Get/list intentionally discard the provider's key or key mask.
type SetupKey struct {
	ID, Name       string
	Expires        time.Time
	UsedTimes      int64
	Valid, Revoked bool
	Secret         string `json:"-"`
}

func (SetupKey) String() string   { return "NetBirdSetupKey([redacted])" }
func (SetupKey) GoString() string { return "NetBirdSetupKey([redacted])" }

type Client struct {
	config    Config
	http      *http.Client
	transport *http.Transport
	ctx       context.Context
	stop      context.CancelFunc
	closed    atomic.Bool
	slots     chan struct{}
}

func (*Client) String() string   { return "NetBirdAPIClient([redacted])" }
func (*Client) GoString() string { return "NetBirdAPIClient([redacted])" }

func New(c Config) (*Client, error) {
	u, e := url.Parse(c.APIOrigin)
	if !identifier.MatchString(c.ResourceID) || !identifier.MatchString(c.AccountID) || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" || len(c.APIOrigin) > 2048 || len(c.Token) < 16 || len(c.Token) > 4096 || strings.IndexFunc(c.Token, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return nil, failure("invalid_config", false)
	}
	tr, e := egress.NewTransport(c.APIOrigin, egress.Options{Roots: c.Roots, Networks: c.AllowedNetworks, Fixture: c.FixtureLoopback})
	if e != nil {
		return nil, failure("invalid_network_grant", false)
	}
	c.APIOrigin = "https://" + u.Host
	c.AllowedNetworks = append([]netip.Prefix(nil), c.AllowedNetworks...)
	ctx, stop := context.WithCancel(context.Background())
	return &Client{config: c, transport: tr, http: &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ctx: ctx, stop: stop, slots: make(chan struct{}, 2)}, nil
}
func (c *Client) Close() {
	if c.closed.CompareAndSwap(false, true) {
		c.stop()
		c.transport.CloseIdleConnections()
	}
}
func operationName(tag string) (string, error) {
	raw, e := base64.RawURLEncoding.DecodeString(tag)
	if e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != tag {
		return "", failure("invalid_operation", false)
	}
	return "syn443-" + tag, nil
}
func validGroups(groups []string) bool {
	if len(groups) < 1 || len(groups) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, g := range groups {
		if !identifier.MatchString(g) || seen[g] {
			return false
		}
		seen[g] = true
	}
	return true
}
func (c *Client) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, failure("invalid_context", false)
	}
	if ctx.Err() != nil || c.closed.Load() {
		return nil, nil, failure("cancelled", false)
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, nil, failure("busy", false)
	}
	owned, cancel := context.WithTimeout(ctx, 12*time.Second)
	stop := context.AfterFunc(c.ctx, cancel)
	return owned, func() { stop(); cancel(); <-c.slots }, nil
}
func (c *Client) request(ctx context.Context, method, path string, body []byte, out any) error {
	mutating := method != "GET"
	if ctx.Err() != nil || c.closed.Load() {
		return failure("cancelled", false)
	}
	r, e := http.NewRequestWithContext(ctx, method, c.config.APIOrigin+path, bytes.NewReader(body))
	if e != nil {
		return failure("invalid_request", false)
	}
	r.Header.Set("Authorization", "Token "+c.config.Token)
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, e := c.http.Do(r)
	if e != nil {
		if ctx.Err() != nil || c.closed.Load() {
			return failure("cancelled", mutating)
		}
		return failure("provider_unavailable", mutating)
	}
	defer response.Body.Close()
	if ctx.Err() != nil || c.closed.Load() {
		return failure("cancelled", mutating)
	}
	if method == "DELETE" && response.StatusCode == 404 {
		return nil
	}
	if response.StatusCode != 200 && !(method == "POST" && response.StatusCode == 201) && !(method == "DELETE" && response.StatusCode == 204) {
		code := "unexpected_response"
		switch response.StatusCode {
		case 401, 403:
			code = "access_denied"
		case 404:
			code = "not_found"
		case 429:
			code = "rate_limited"
		default:
			if response.StatusCode >= 500 {
				code = "provider_unavailable"
			}
		}
		return failure(code, mutating)
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if ctx.Err() != nil || c.closed.Load() {
		return failure("cancelled", mutating)
	}
	if e != nil {
		return failure("provider_unavailable", mutating)
	}
	if len(data) > maxBody {
		return failure("response_limit", mutating)
	}
	if method == "DELETE" && len(data) == 0 {
		return nil
	}
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	trimmed := bytes.TrimSpace(data)
	if e != nil || media != "application/json" || response.Header.Get("Content-Encoding") != "" || len(trimmed) == 0 || trimmed[0] != '{' && trimmed[0] != '[' || identity.Decode(data, out, false) != nil {
		return failure("invalid_response", mutating)
	}
	return nil
}
func (c *Client) account(ctx context.Context) error {
	var accounts []struct {
		ID remoteID `json:"id"`
	}
	if e := c.request(ctx, "GET", "/api/accounts", nil, &accounts); e != nil {
		return e
	}
	if len(accounts) != 1 || string(accounts[0].ID) != c.config.AccountID {
		return failure("account_mismatch", false)
	}
	return nil
}
func metadata(w keyWire) (SetupKey, error) {
	if !identifier.MatchString(string(w.ID)) || len(w.Name) < 1 || len(w.Name) > 128 || w.Expires.IsZero() || w.UsedTimes < 0 || w.UsedTimes > 9007199254740991 || len(w.Groups) > 16 {
		return SetupKey{}, failure("invalid_response", false)
	}
	return SetupKey{ID: string(w.ID), Name: w.Name, Expires: w.Expires, UsedTimes: w.UsedTimes, Valid: w.Valid, Revoked: w.Revoked}, nil
}

// CreateOneOff is deliberately one attempt. The broker must first persist a
// dispatched marker and use the same opaque operation tag after a lost reply.
// Provider expiry is one day; a separate durable cleanup job must revoke at the
// much shorter addressed-credential deadline, after use, or on authorization loss.
func (c *Client) CreateOneOff(ctx context.Context, tag string, groups []string, now time.Time) (SetupKey, error) {
	name, e := operationName(tag)
	if e != nil || !validGroups(groups) || now.IsZero() {
		return SetupKey{}, failure("invalid_operation", false)
	}
	groups = append([]string(nil), groups...)
	slices.Sort(groups)
	ctx, done, e := c.begin(ctx)
	if e != nil {
		return SetupKey{}, e
	}
	defer done()
	if e = c.account(ctx); e != nil {
		return SetupKey{}, e
	}
	body, _ := json.Marshal(map[string]any{"name": name, "type": "one-off", "expires_in": 86400, "auto_groups": groups, "usage_limit": 1, "ephemeral": false, "allow_extra_dns_labels": false})
	var wire keyWire
	if e = c.request(ctx, "POST", "/api/setup-keys", body, &wire); e != nil {
		return SetupKey{}, e
	}
	result, e := metadata(wire)
	actual := append([]string(nil), wire.Groups...)
	slices.Sort(actual)
	if e != nil || result.Name != name || wire.Type != "one-off" || !wire.Valid || wire.Revoked || wire.UsedTimes != 0 || wire.UsageLimit != 1 || wire.Ephemeral || wire.ExtraDNS || !slices.Equal(actual, groups) || !setupValue.MatchString(wire.Key) || wire.Expires.Before(now.Add(23*time.Hour)) || wire.Expires.After(now.Add(25*time.Hour)) {
		return SetupKey{}, failure("create_response_mismatch", true)
	}
	result.Secret = wire.Key
	return result, nil
}

// FindOperation reads metadata only. Missing/multiple results are never an
// instruction to create another key: the durable broker decides reconciliation.
func (c *Client) FindOperation(ctx context.Context, tag string) ([]SetupKey, error) {
	name, e := operationName(tag)
	if e != nil {
		return nil, e
	}
	ctx, done, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	if e = c.account(ctx); e != nil {
		return nil, e
	}
	var wire []keyWire
	if e = c.request(ctx, "GET", "/api/setup-keys", nil, &wire); e != nil {
		return nil, e
	}
	result := []SetupKey{}
	for _, w := range wire {
		if w.Name == name {
			m, e := metadata(w)
			if e != nil {
				return nil, e
			}
			result = append(result, m)
		}
	}
	return result, nil
}

// RevokeOwned rechecks both the addressed ID and unguessable operation name.
// It cannot remove a key merely because a caller supplied an external ID.
func (c *Client) RevokeOwned(ctx context.Context, tag, id string) error {
	name, e := operationName(tag)
	if e != nil || !identifier.MatchString(id) {
		return failure("invalid_operation", false)
	}
	ctx, done, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	if e = c.account(ctx); e != nil {
		return e
	}
	var wire keyWire
	if e = c.request(ctx, "GET", "/api/setup-keys/"+id, nil, &wire); e != nil {
		if v, ok := e.(*Error); ok && v.Code == "not_found" {
			return nil
		}
		return e
	}
	m, e := metadata(wire)
	if e != nil || m.ID != id || m.Name != name {
		return failure("ownership_mismatch", false)
	}
	var response map[string]any
	return c.request(ctx, "DELETE", "/api/setup-keys/"+id, nil, &response)
}
