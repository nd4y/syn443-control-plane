package catalog

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// RuntimeConfig is read only from an owner-protected process file. It is never
// an administrative API DTO. Neither runtime role owns migrations or ACL grants.
type RuntimeConfig struct {
	Database        string   `json:"database"`
	EncryptionKey   string   `json:"encryptionKey"`
	Listen          string   `json:"listen,omitempty"`
	Origin          string   `json:"origin,omitempty"`
	Issuer          string   `json:"issuer,omitempty"`
	Audience        string   `json:"audience,omitempty"`
	ClientIDs       []string `json:"clientIds,omitempty"`
	AssuranceACR    string   `json:"assuranceAcr,omitempty"`
	Certificate     string   `json:"certificate,omitempty"`
	CertificateKey  string   `json:"certificateKey,omitempty"`
	FixtureHTTP     bool     `json:"fixtureHttp,omitempty"`
	FixtureLoopback bool     `json:"fixtureLoopback,omitempty"`
	DeviceFetchEnabled bool  `json:"deviceFetchEnabled,omitempty"`
}

func (RuntimeConfig) String() string   { return "CatalogRuntimeConfig([redacted])" }
func (RuntimeConfig) GoString() string { return "CatalogRuntimeConfig([redacted])" }
func ParseRuntimeConfig(raw []byte) (RuntimeConfig, error) {
	var c RuntimeConfig
	if len(raw) > 65536 || identity.Decode(raw, &c, true) != nil {
		return c, ErrInvalid
	}
	return c, nil
}
func OpenStore(c RuntimeConfig) (*Store, error) {
	key, e := base64.StdEncoding.Strict().DecodeString(c.EncryptionKey)
	if e != nil || len(key) != 32 {
		return nil, ErrInvalid
	}
	parsed, e := pgx.ParseConfig(c.Database)
	if e != nil || parsed.User == "" || parsed.Database == "" {
		return nil, ErrInvalid
	}
	if parsed.Host != "127.0.0.1" {
		if parsed.TLSConfig == nil || parsed.TLSConfig.InsecureSkipVerify || parsed.TLSConfig.ServerName == "" {
			return nil, ErrInvalid
		}
		for _, fallback := range parsed.Fallbacks {
			if fallback.TLSConfig == nil || fallback.TLSConfig.InsecureSkipVerify || fallback.TLSConfig.ServerName == "" {
				return nil, ErrInvalid
			}
		}
	}
	parsed.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*parsed)
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	s, e := NewStore(db, key)
	if e != nil {
		db.Close()
	} else {
		s.DeviceFetchEnabled = c.DeviceFetchEnabled
	}
	return s, e
}
func (c RuntimeConfig) ValidateAdmin() error {
	if c.Audience != "syn443-control-api" || len(c.ClientIDs) < 1 || len(c.ClientIDs) > 2 || c.Issuer == "" || c.AssuranceACR == "" {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, client := range c.ClientIDs {
		if client != "syn443-control-mobile" && client != "syn443-control-web" || seen[client] {
			return ErrInvalid
		}
		seen[client] = true
	}
	return nil
}

type VerifierGroup []Verifier

func (v VerifierGroup) Verify(ctx context.Context, token string, now time.Time) (identity.Principal, error) {
	for _, verifier := range v {
		p, e := verifier.Verify(ctx, token, now)
		if e == nil {
			return p, nil
		}
	}
	return identity.Principal{}, identity.ErrInvalid
}
