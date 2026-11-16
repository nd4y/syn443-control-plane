package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Owner-protected process configuration, never an administrative API payload.
// This file contains no provider credential or private signing key. Database
// connections retain the role of their owning API/publication process.
type ConfigurationRuntimeConfig struct {
	ControlOrigin       string            `json:"controlOrigin"`
	Issuer              string            `json:"issuer"` // Pinned administrative issuer, independent of device enrollment.
	Audience            string            `json:"audience"`
	ClientIDs           []string          `json:"clientIds"`
	AssuranceACR        string            `json:"assuranceAcr"`
	LayerEncryptionKey  string            `json:"layerEncryptionKey"`
	SourceEncryptionKey string            `json:"sourceEncryptionKey"`
	Roots               map[string]string `json:"roots"`
}

func (ConfigurationRuntimeConfig) String() string   { return "ConfigurationRuntimeConfig([redacted])" }
func (ConfigurationRuntimeConfig) GoString() string { return "ConfigurationRuntimeConfig([redacted])" }

func ParseConfigurationRuntime(raw []byte) (ConfigurationRuntimeConfig, error) {
	var c ConfigurationRuntimeConfig
	if len(raw) > 65536 || identity.Decode(raw, &c, true) != nil {
		return c, enrollment.ErrDenied
	}
	u, e := url.Parse(c.ControlOrigin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ToLower(u.Hostname()) != u.Hostname() || len(c.ControlOrigin) > 2048 || len(c.AssuranceACR) > 128 {
		return c, enrollment.ErrDenied
	}
	admin := catalog.RuntimeConfig{Issuer: c.Issuer, Audience: c.Audience, ClientIDs: c.ClientIDs, AssuranceACR: c.AssuranceACR}
	if admin.ValidateAdmin() != nil {
		return c, enrollment.ErrDenied
	}
	issuer, e := url.Parse(c.Issuer)
	if e != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || strings.HasSuffix(c.Issuer, "/") || len(c.Issuer) > 2048 {
		return c, enrollment.ErrDenied
	}
	for _, key := range []string{c.LayerEncryptionKey, c.SourceEncryptionKey} {
		b, e := base64.StdEncoding.Strict().DecodeString(key)
		if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != key {
			return c, enrollment.ErrDenied
		}
	}
	if c.LayerEncryptionKey == c.SourceEncryptionKey {
		return c, enrollment.ErrDenied
	}
	for id := range c.Roots {
		if !configurationObjectID.MatchString(id) {
			return c, enrollment.ErrDenied
		}
	}
	if _, e = c.PublicRoots(); e != nil {
		return c, enrollment.ErrDenied
	}
	return c, nil
}

func ReadConfigurationRuntime(path string) (ConfigurationRuntimeConfig, error) {
	raw, e := enrollment.PrivateFile(path, 65536)
	if e != nil {
		return ConfigurationRuntimeConfig{}, e
	}
	return ParseConfigurationRuntime(raw)
}

func (c ConfigurationRuntimeConfig) PublicRoots() (map[string]*ecdsa.PublicKey, error) {
	return enrollment.PublicRoots(enrollment.Config{Roots: c.Roots})
}

// AdminVerifier uses only the owner-pinned control issuer and clients. It never
// borrows device-enrollment authority or tries a second issuer on rejection.
// A nil transport retains ordinary verified HTTPS; tests can inject their TLS
// client's trust store without enabling an HTTP/insecure production mode.
func (c ConfigurationRuntimeConfig) AdminVerifier(ctx context.Context, transport http.RoundTripper) (catalog.VerifierGroup, error) {
	if ctx == nil {
		return nil, enrollment.ErrDenied
	}
	if e := c.validate(); e != nil {
		return nil, e
	}
	var providers catalog.VerifierGroup
	for _, client := range c.ClientIDs {
		provider, e := identity.NewProvider(ctx, c.Issuer, c.Audience, client, transport, false)
		if e != nil {
			return nil, e
		}
		providers = append(providers, provider)
	}
	return providers, nil
}

func (c ConfigurationRuntimeConfig) LayerStore(ctx context.Context, db *sql.DB, publisher bool) (*enrollment.Store, error) {
	if ctx == nil || db == nil {
		return nil, enrollment.ErrDenied
	}
	if e := c.validate(); e != nil {
		return nil, e
	}
	key, _ := base64.StdEncoding.Strict().DecodeString(c.LayerEncryptionKey)
	s, e := enrollment.NewStore(db, key)
	if e != nil {
		return nil, e
	}
	if e = ConfigurationRuntimeRole(ctx, db, publisher); e != nil {
		return nil, e
	}
	return s, nil
}

func (c ConfigurationRuntimeConfig) SourceStore(ctx context.Context, db *sql.DB) (*catalog.Store, error) {
	if ctx == nil || db == nil {
		return nil, enrollment.ErrDenied
	}
	if e := c.validate(); e != nil {
		return nil, e
	}
	key, _ := base64.StdEncoding.Strict().DecodeString(c.SourceEncryptionKey)
	s, e := catalog.NewStore(db, key)
	if e != nil {
		return nil, e
	}
	if e = s.PublicationRole(ctx); e != nil {
		return nil, e
	}
	return s, nil
}

func (c ConfigurationRuntimeConfig) validate() error {
	raw, e := json.Marshal(c)
	if e != nil {
		return enrollment.ErrDenied
	}
	_, e = ParseConfigurationRuntime(raw)
	return e
}
