package identity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider only contacts the operator-pinned issuer. No JWT jku/x5u or request-supplied URL is used.
type Provider struct {
	gate      chan struct{}
	oidc      OIDC
	client    *http.Client
	loaded    time.Time
	attempted time.Time
}

func NewProvider(ctx context.Context, issuer, audience, clientID string, transport http.RoundTripper, loopbackFixture bool) (*Provider, error) {
	u, e := url.Parse(issuer)
	if audience == "" || clientID == "" || len(audience) > 128 || len(clientID) > 128 || e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Host == "" || strings.HasSuffix(issuer, "/") || u.Scheme != "https" && !(loopbackFixture && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "") {
		return nil, ErrInvalid
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, ResponseHeaderTimeout: 3 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	}
	p := &Provider{gate: make(chan struct{}, 1), oidc: OIDC{Issuer: issuer, Audience: audience, Client: clientID}, client: &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if e = p.reload(ctx, time.Now()); e != nil {
		return nil, e
	}
	return p, nil
}
func (p *Provider) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return nil, ErrInvalid
	}
	r, e := p.client.Do(req)
	if e != nil {
		return nil, ErrInvalid
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return nil, ErrInvalid
	}
	return raw, nil
}
func (p *Provider) reload(ctx context.Context, now time.Time) error {
	p.attempted = now
	raw, e := p.get(ctx, p.oidc.Issuer+"/.well-known/openid-configuration")
	if e != nil {
		return e
	}
	var doc struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if Decode(raw, &doc, false) != nil || doc.Issuer != p.oidc.Issuer || doc.JWKS != p.oidc.Issuer+"/protocol/openid-connect/certs" {
		return ErrInvalid
	}
	raw, e = p.get(ctx, doc.JWKS)
	if e != nil {
		return e
	}
	keys, e := ParseJWKS(raw)
	if e != nil {
		return e
	}
	p.oidc.Keys = keys
	p.loaded = now
	return nil
}
func (p *Provider) Verify(ctx context.Context, token string, now time.Time) (Principal, error) {
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return Principal{}, ErrInvalid
	}
	if time.Since(p.loaded) > 5*time.Minute {
		if time.Since(p.attempted) < 30*time.Second {
			return Principal{}, ErrInvalid
		}
		if e := p.reload(ctx, time.Now()); e != nil {
			return Principal{}, ErrInvalid
		}
	}
	result, e := p.oidc.Verify(token, now)
	if e == nil {
		return result, nil
	}
	// A rotating key may be fetched at most once in 30 seconds; invalid tokens cannot cause a fetch storm.
	if time.Since(p.attempted) > 30*time.Second {
		if e = p.reload(ctx, time.Now()); e != nil {
			return result, ErrInvalid
		}
		return p.oidc.Verify(token, now)
	}
	return result, e
}

// RequestProof verifies signature and all request bindings; the durable store validates nonce atomically.
func RequestProof(raw string, ctx ProofContext) (Proof, error) {
	_, claims, _, _, e := parts(raw)
	if e != nil {
		return Proof{}, e
	}
	var peek struct {
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(claims, &peek) != nil {
		return Proof{}, ErrInvalid
	}
	ctx.Nonce = peek.Nonce
	return VerifyProof(raw, ctx)
}
