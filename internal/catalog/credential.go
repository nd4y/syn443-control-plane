package catalog

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/netip"

	"github.com/nd4y/syn443-control-plane/internal/egress"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

type FetchCredential struct {
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	RedirectOrigins []string          `json:"redirectOrigins,omitempty"`
	AllowedNetworks []string          `json:"allowedNetworks,omitempty"`
	RootCA          string            `json:"rootCa,omitempty"`
}

func (FetchCredential) String() string   { return "FetchCredential([redacted])" }
func (FetchCredential) GoString() string { return "FetchCredential([redacted])" }
func ReadFetchCredential(raw []byte) (FetchCredential, error) {
	var c FetchCredential
	if len(raw) == 0 || len(raw) > 65536 || identity.DecodeConfiguration(raw, &c) != nil {
		return c, ErrInvalid
	}
	config, e := c.Config(false)
	if e != nil {
		return c, e
	}
	if subscriptions.ValidateFetchConfig(config) != nil {
		return c, ErrInvalid
	}
	return c, nil
}
func (c FetchCredential) Config(fixture bool) (subscriptions.FetchConfig, error) {
	if len(c.AllowedNetworks) > 8 || len(c.RedirectOrigins) > 3 || len(c.Headers) > 16 {
		return subscriptions.FetchConfig{}, ErrInvalid
	}
	options := egress.Options{Fixture: fixture}
	for _, raw := range c.AllowedNetworks {
		p, e := netip.ParsePrefix(raw)
		if e != nil {
			return subscriptions.FetchConfig{}, ErrInvalid
		}
		options.Networks = append(options.Networks, p)
	}
	if c.RootCA != "" {
		if len(c.RootCA) > 32768 {
			return subscriptions.FetchConfig{}, ErrInvalid
		}
		pool := x509.NewCertPool()
		rest := bytes.TrimSpace([]byte(c.RootCA))
		count := 0
		for len(rest) > 0 {
			block, next := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return subscriptions.FetchConfig{}, ErrInvalid
			}
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				return subscriptions.FetchConfig{}, ErrInvalid
			}
			pool.AddCert(cert)
			count++
			if count > 16 {
				return subscriptions.FetchConfig{}, ErrInvalid
			}
			rest = bytes.TrimSpace(next)
		}
		options.Roots = pool
	}
	return subscriptions.FetchConfig{URL: c.URL, Headers: c.Headers, RedirectOrigins: c.RedirectOrigins, Network: options}, nil
}
