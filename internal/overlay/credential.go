package overlay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

const credentialType = "syn443-overlay-credential+jws"
const credentialAudience = "syn443-overlay-credential"

var setupKey = regexp.MustCompile(`^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$`)

// Credential is an independently signed, addressed enrollment secret. It never
// includes the provider management API token or an SDK/WireGuard private key.
// Transport mode and physical network are deliberately absent from the address.
type Credential struct {
	SchemaVersion int     `json:"schemaVersion"`
	Audience      string  `json:"audience"`
	Address       Address `json:"address"`
	KeyThumbprint string  `json:"keyThumbprint"`
	Reference     string  `json:"reference"`
	Version       int64   `json:"version"`
	SecurityEpoch int64   `json:"securityEpoch"`
	Kind          string  `json:"kind"`
	IssuedAtMs    int64   `json:"issuedAtMs"`
	NotBeforeMs   int64   `json:"notBeforeMs"`
	ExpiresMs     int64   `json:"expiresMs"`
	Value         string  `json:"value"`
}

func (Credential) String() string   { return "AddressedOverlayCredential([redacted])" }
func (Credential) GoString() string { return "AddressedOverlayCredential([redacted])" }

type CredentialBinding struct {
	Address                                Address
	KeyThumbprint, Reference               string
	Version, SecurityEpoch, OfflineUntilMs int64
}

func (CredentialBinding) String() string   { return "OverlayCredentialBinding([redacted])" }
func (CredentialBinding) GoString() string { return "OverlayCredentialBinding([redacted])" }
func canonicalDigest(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	decoded, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	return e == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == raw
}
func (c Credential) validate(now time.Time) error {
	if c.SchemaVersion != 1 || c.Audience != credentialAudience || !canonicalDigest(c.KeyThumbprint) || !canonicalDigest(c.Reference) || c.Version < 1 || c.Version > 9007199254740991 || c.SecurityEpoch < 0 || c.SecurityEpoch > 9007199254740991 || c.Kind != "netbird.setup-key" || !setupKey.MatchString(c.Value) {
		return ErrInvalid
	}
	if _, e := Namespace(c.Address); e != nil {
		return e
	}
	n := now.UnixMilli()
	if c.IssuedAtMs <= 0 || c.IssuedAtMs > n+30000 || c.NotBeforeMs < c.IssuedAtMs || c.NotBeforeMs > n || c.ExpiresMs <= n || c.ExpiresMs <= c.NotBeforeMs || c.ExpiresMs-c.IssuedAtMs > 1800000 {
		return ErrInvalid
	}
	return nil
}
func credentialScope(c Credential, b CredentialBinding, now time.Time) error {
	if c.validate(now) != nil || !canonicalDigest(b.KeyThumbprint) || !canonicalDigest(b.Reference) || b.OfflineUntilMs <= now.UnixMilli() || c.ExpiresMs > b.OfflineUntilMs || c.KeyThumbprint != b.KeyThumbprint || c.Reference != b.Reference || c.Version != b.Version || c.SecurityEpoch != b.SecurityEpoch {
		return ErrInvalid
	}
	actual, e := Namespace(c.Address)
	if e != nil {
		return e
	}
	expected, e := Namespace(b.Address)
	if e != nil || actual != expected {
		return ErrInvalid
	}
	return nil
}
func validCredentialPublic(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}

// Signing this envelope is a separate authority step. A parser/worker cannot
// turn a setup-key string or SQL ready flag into a credential signature.
func SignCredential(c Credential, b CredentialBinding, kid string, key *ecdsa.PrivateKey, now time.Time) (string, error) {
	if credentialScope(c, b, now) != nil || !identifier.MatchString(kid) || key == nil || !validCredentialPublic(&key.PublicKey) || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return "", ErrInvalid
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return "", ErrInvalid
	}
	payload, e := json.Marshal(c)
	if e != nil || len(payload) > 8192 {
		return "", ErrInvalid
	}
	payload, e = policy.Canonical(payload)
	if e != nil {
		return "", ErrInvalid
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": kid, "typ": credentialType})
	header, _ = policy.Canonical(header)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, sum[:])
	if e != nil {
		return "", ErrInvalid
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
func VerifyCredential(raw string, roots map[string]*ecdsa.PublicKey, b CredentialBinding, now time.Time) (Credential, error) {
	var c Credential
	if len(raw) < 1 || len(raw) > 16384 {
		return c, ErrInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(parts[0]) > 1024 {
		return c, ErrInvalid
	}
	decode := func(raw string) ([]byte, error) {
		out, e := base64.RawURLEncoding.Strict().DecodeString(raw)
		if e != nil || base64.RawURLEncoding.EncodeToString(out) != raw {
			return nil, ErrInvalid
		}
		return out, nil
	}
	header, e := decode(parts[0])
	if e != nil {
		return c, ErrInvalid
	}
	clean, e := policy.Canonical(header)
	if e != nil || !bytes.Equal(clean, header) {
		return c, ErrInvalid
	}
	var h struct {
		Alg  string `json:"alg"`
		Kid  string `json:"kid"`
		Type string `json:"typ"`
	}
	if identity.Decode(header, &h, true) != nil || h.Alg != "ES256" || h.Type != credentialType || !identifier.MatchString(h.Kid) {
		return c, ErrInvalid
	}
	key := roots[h.Kid]
	if !validCredentialPublic(key) {
		return c, ErrInvalid
	}
	signature, e := decode(parts[2])
	if e != nil || len(signature) != 64 {
		return c, ErrInvalid
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return c, ErrInvalid
	}
	payload, e := decode(parts[1])
	if e != nil || len(payload) > 8192 {
		return c, ErrInvalid
	}
	clean, e = policy.Canonical(payload)
	if e != nil || !bytes.Equal(clean, payload) || identity.Decode(payload, &c, true) != nil {
		return Credential{}, ErrInvalid
	}
	if credentialScope(c, b, now) != nil {
		return Credential{}, ErrInvalid
	}
	return c, nil
}
