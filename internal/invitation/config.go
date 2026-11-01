package invitation

import (
	"context"
	"encoding/base64"
	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"time"
)

type Config struct {
	EncryptionKey  string           `json:"encryptionKey"`
	ControlOrigin  string           `json:"controlOrigin"`
	IdentityOrigin string           `json:"identityOrigin"`
	Issuer         string           `json:"issuer"`
	Audience       string           `json:"audience"`
	ClientIDs      []string         `json:"clientIds"`
	AssuranceACR   string           `json:"assuranceAcr"`
	Anchor         bootstrap.Anchor `json:"anchor"`
	Descriptor     string           `json:"descriptor"`
}

func (Config) String() string   { return "InvitationRuntimeConfig([redacted])" }
func (Config) GoString() string { return "InvitationRuntimeConfig([redacted])" }
func ParseConfig(raw []byte, now time.Time) (Config, error) {
	var c Config
	if len(raw) > 65536 || identity.DecodeConfiguration(raw, &c) != nil {
		return c, ErrDenied
	}
	key, e := base64.StdEncoding.Strict().DecodeString(c.EncryptionKey)
	if e != nil || len(key) != 32 || c.Audience != "syn443-control-api" || len(c.ClientIDs) < 1 || len(c.ClientIDs) > 2 || c.AssuranceACR == "" || len(c.AssuranceACR) > 128 {
		return c, ErrDenied
	}
	// Reuse the closed bootstrap origin canonicalizer, not a browser URL parser.
	d, _, e := bootstrap.VerifyDescriptor(c.Descriptor, c.Anchor, bootstrap.Floor{}, now)
	if e != nil || d.APIOrigin != c.IdentityOrigin || d.Issuer != c.Issuer {
		return c, ErrDenied
	}
	if !bootstrap.ValidOrigin(c.ControlOrigin) {
		return c, ErrDenied
	}
	seen := map[string]bool{}
	for _, client := range c.ClientIDs {
		if client != "syn443-control-mobile" && client != "syn443-control-web" || seen[client] {
			return c, ErrDenied
		}
		seen[client] = true
	}
	return c, nil
}
func ReadConfig(path string, now time.Time) (Config, error) {
	raw, e := enrollment.PrivateFile(path, 65536)
	if e != nil {
		return Config{}, e
	}
	return ParseConfig(raw, now)
}
func (c Config) Key() []byte {
	key, _ := base64.StdEncoding.Strict().DecodeString(c.EncryptionKey)
	return key
}

type verifierGroup []Verifier

func (v verifierGroup) Verify(ctx context.Context, token string, now time.Time) (identity.Principal, error) {
	for _, p := range v {
		value, e := p.Verify(ctx, token, now)
		if e == nil {
			return value, nil
		}
	}
	return identity.Principal{}, identity.ErrInvalid
}
func (c Config) Verification(ctx context.Context) (Verification, error) {
	var group verifierGroup
	for _, client := range c.ClientIDs {
		p, e := identity.NewProvider(ctx, c.Issuer, c.Audience, client, nil, false)
		if e != nil {
			return Verification{}, e
		}
		group = append(group, p)
	}
	return Verification{AdminVerifier: group, ControlOrigin: c.ControlOrigin, IdentityOrigin: c.IdentityOrigin, AssuranceACR: c.AssuranceACR, Anchor: c.Anchor}, nil
}
