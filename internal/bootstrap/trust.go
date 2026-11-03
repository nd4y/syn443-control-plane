// Package bootstrap authenticates service metadata and invitation links against
// an installation root. A link cannot install its own root or authorize a user.
package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

var ErrUntrusted = errors.New("bootstrap_untrusted")
var ErrRollback = errors.New("bootstrap_rollback")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var digestID = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

const MaxManifest = 6144

type Anchor struct {
	ID             string `json:"id"`
	SPKI           string `json:"spki"`
	Epoch          int64  `json:"epoch"`
	LastTransition string `json:"lastTransition"`
}
type Floor struct {
	ServiceID string `json:"serviceId"`
	Revision  int64  `json:"revision"`
	Hash      string `json:"hash"`
}
type Descriptor struct {
	SchemaVersion      int               `json:"schemaVersion"`
	Audience           string            `json:"audience"`
	RootEpoch          int64             `json:"rootEpoch"`
	Revision           int64             `json:"revision"`
	ServiceID          string            `json:"serviceId"`
	Issuer             string            `json:"issuer"`
	ClientID           string            `json:"clientId"`
	APIOrigin          string            `json:"apiOrigin"`
	ControlPanelOrigin string            `json:"controlPanelOrigin,omitempty"`
	Roots              map[string]string `json:"roots"`
	IssuedAt           int64             `json:"issuedAt"`
	NotBefore          int64             `json:"notBefore"`
	Expires            int64             `json:"expires"`
}

func (Descriptor) String() string   { return "BootstrapDescriptor([redacted])" }
func (Descriptor) GoString() string { return "BootstrapDescriptor([redacted])" }
func ascii(raw string) bool {
	for _, r := range raw {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

// ValidOrigin accepts only canonical HTTPS origins used by authenticated bootstrap.
func ValidOrigin(raw string) bool { return secureURL(raw, false) }

func secureURL(raw string, allowPath bool) bool {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || !ascii(raw) || !strings.HasPrefix(raw, "https://") || u.Scheme != "https" || u.Hostname() == "" || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(u.Host, ":") || u.Port() == "443" || !allowPath && u.Path != "" || allowPath && strings.HasSuffix(u.Path, "/") {
		return false
	}
	if u.Port() != "" {
		n, e := strconv.Atoi(u.Port())
		if e != nil || n < 1 || n > 65535 || n == 443 {
			return false
		}
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return !strings.Contains(u.Path, "//")
}
func public(raw string) (*ecdsa.PublicKey, error) {
	der, e := base64.StdEncoding.Strict().DecodeString(raw)
	if e != nil || len(der) > 256 || base64.StdEncoding.EncodeToString(der) != raw {
		return nil, ErrUntrusted
	}
	parsed, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return nil, ErrUntrusted
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrUntrusted
	}
	return key, nil
}
func Public(key *ecdsa.PublicKey) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", ErrUntrusted
	}
	raw, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		return "", ErrUntrusted
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
func (a Anchor) Validate() error {
	if !identifier.MatchString(a.ID) || a.Epoch < 1 || a.Epoch > 9007199254740991 || a.LastTransition != "" && !digestID.MatchString(a.LastTransition) {
		return ErrUntrusted
	}
	_, e := public(a.SPKI)
	return e
}
func (d Descriptor) validate(anchor Anchor, now time.Time) error {
	if d.ControlPanelOrigin != "" && !secureURL(d.ControlPanelOrigin, false) {
		return ErrUntrusted
	}
	if d.SchemaVersion != 1 || d.Audience != "syn443-client-bootstrap" || d.RootEpoch != anchor.Epoch || d.Revision < 1 || d.Revision > 9007199254740991 || !identifier.MatchString(d.ServiceID) || !identifier.MatchString(d.ClientID) || !secureURL(d.APIOrigin, false) || !secureURL(d.Issuer, true) || len(d.Roots) < 1 || len(d.Roots) > 4 || d.IssuedAt < 1 || d.IssuedAt > now.Unix()+30 || d.NotBefore < d.IssuedAt || d.NotBefore > now.Unix() || d.Expires <= now.Unix() || d.Expires-d.IssuedAt > 30*86400 {
		return ErrUntrusted
	}
	for id, key := range d.Roots {
		if !identifier.MatchString(id) || key == anchor.SPKI {
			return ErrUntrusted
		}
		if _, e := public(key); e != nil {
			return e
		}
	}
	return nil
}
func sign(value any, kind string, anchor Anchor, key *ecdsa.PrivateKey) (string, error) {
	if anchor.Validate() != nil || key == nil || key.Curve != elliptic.P256() {
		return "", ErrUntrusted
	}
	encoded, e := Public(&key.PublicKey)
	if e != nil || encoded != anchor.SPKI {
		return "", ErrUntrusted
	}
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 4096 {
		return "", ErrUntrusted
	}
	payload, e := policy.Canonical(raw)
	if e != nil {
		return "", ErrUntrusted
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": anchor.ID, "typ": kind})
	header, e = policy.Canonical(header)
	if e != nil {
		return "", ErrUntrusted
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, digest[:])
	if e != nil {
		return "", ErrUntrusted
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	out := input + "." + enc.EncodeToString(signature)
	if len(out) > MaxManifest {
		return "", ErrUntrusted
	}
	return out, nil
}
func verify(raw, kind string, anchor Anchor, dst any) ([]byte, error) {
	if len(raw) < 1 || len(raw) > MaxManifest || anchor.Validate() != nil {
		return nil, ErrUntrusted
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(parts[0]) > 512 {
		return nil, ErrUntrusted
	}
	decode := func(raw string) ([]byte, error) {
		v, e := base64.RawURLEncoding.Strict().DecodeString(raw)
		if e != nil || base64.RawURLEncoding.EncodeToString(v) != raw {
			return nil, ErrUntrusted
		}
		return v, nil
	}
	header, e := decode(parts[0])
	if e != nil {
		return nil, e
	}
	var h struct {
		Algorithm string `json:"alg"`
		ID        string `json:"kid"`
		Kind      string `json:"typ"`
	}
	if identity.Decode(header, &h, true) != nil || h.Algorithm != "ES256" || h.ID != anchor.ID || h.Kind != kind {
		return nil, ErrUntrusted
	}
	clean, e := policy.Canonical(header)
	if e != nil || !bytes.Equal(clean, header) {
		return nil, ErrUntrusted
	}
	signature, e := decode(parts[2])
	if e != nil || len(signature) != 64 {
		return nil, ErrUntrusted
	}
	key, _ := public(anchor.SPKI)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, ErrUntrusted
	}
	payload, e := decode(parts[1])
	if e != nil || len(payload) > 4096 {
		return nil, ErrUntrusted
	}
	clean, e = policy.Canonical(payload)
	if e != nil || !bytes.Equal(clean, payload) || identity.Decode(payload, dst, true) != nil {
		return nil, ErrUntrusted
	}
	return payload, nil
}
func SignDescriptor(d Descriptor, anchor Anchor, key *ecdsa.PrivateKey, now time.Time) (string, error) {
	if d.validate(anchor, now) != nil {
		return "", ErrUntrusted
	}
	return sign(d, "syn443-bootstrap+jws", anchor, key)
}
func VerifyDescriptor(raw string, anchor Anchor, floor Floor, now time.Time) (Descriptor, Floor, error) {
	var d Descriptor
	payload, e := verify(raw, "syn443-bootstrap+jws", anchor, &d)
	if e != nil || d.validate(anchor, now) != nil {
		return Descriptor{}, floor, ErrUntrusted
	}
	hash := identity.Hash(payload)
	if floor.Revision < 0 || floor.Revision > 9007199254740991 || floor.Revision == 0 && (floor.Hash != "" || floor.ServiceID != "") || floor.Revision > 0 && (!digestID.MatchString(floor.Hash) || floor.ServiceID != d.ServiceID) {
		return Descriptor{}, floor, ErrRollback
	}
	if d.Revision < floor.Revision || d.Revision == floor.Revision && hash != floor.Hash {
		return Descriptor{}, floor, ErrRollback
	}
	return d, Floor{d.ServiceID, d.Revision, hash}, nil
}

type Transition struct {
	SchemaVersion int    `json:"schemaVersion"`
	Audience      string `json:"audience"`
	From          string `json:"from"`
	To            string `json:"to"`
	SPKI          string `json:"spki"`
	Epoch         int64  `json:"epoch"`
	IssuedAt      int64  `json:"issuedAt"`
	NotBefore     int64  `json:"notBefore"`
	Expires       int64  `json:"expires"`
}
type Rotation struct {
	Previous string `json:"previous"`
	Next     string `json:"next"`
}

func (t Transition) validate(current Anchor, now time.Time) error {
	if t.SchemaVersion != 1 || t.Audience != "syn443-root-transition" || t.From != current.ID || !identifier.MatchString(t.To) || t.To == current.ID || t.SPKI == current.SPKI || t.Epoch != current.Epoch+1 || t.Epoch > 9007199254740991 || t.IssuedAt < 1 || t.IssuedAt > now.Unix()+30 || t.NotBefore < t.IssuedAt || t.NotBefore > now.Unix() || t.Expires <= now.Unix() || t.Expires-t.IssuedAt > 7*86400 {
		return ErrUntrusted
	}
	_, e := public(t.SPKI)
	return e
}
func SignRotation(t Transition, current Anchor, old, new *ecdsa.PrivateKey, now time.Time) (Rotation, error) {
	if t.validate(current, now) != nil {
		return Rotation{}, ErrUntrusted
	}
	next := Anchor{ID: t.To, SPKI: t.SPKI, Epoch: t.Epoch}
	a, e := sign(t, "syn443-root-transition+jws", current, old)
	if e != nil {
		return Rotation{}, e
	}
	b, e := sign(t, "syn443-root-transition+jws", next, new)
	if e != nil {
		return Rotation{}, e
	}
	return Rotation{a, b}, nil
}

// AdvanceRoot requires both the previous authority and possession of the next
// private root. Retired roots cannot authorize new manifests. Persist this state
// atomically before accepting links; a failed write must leave the old state.
func AdvanceRoot(rotation Rotation, current Anchor, now time.Time) (Anchor, error) {
	if current.Validate() != nil || len(rotation.Previous) > MaxManifest || len(rotation.Next) > MaxManifest {
		return current, ErrUntrusted
	}
	raw, _ := json.Marshal(rotation)
	raw, _ = policy.Canonical(raw)
	hash := identity.Hash(raw)
	if hash == current.LastTransition {
		return current, nil
	}
	var t, next Transition
	first, e := verify(rotation.Previous, "syn443-root-transition+jws", current, &t)
	if e != nil || t.validate(current, now) != nil {
		return current, ErrUntrusted
	}
	candidate := Anchor{ID: t.To, SPKI: t.SPKI, Epoch: t.Epoch, LastTransition: hash}
	second, e := verify(rotation.Next, "syn443-root-transition+jws", candidate, &next)
	if e != nil || !bytes.Equal(first, second) {
		return current, ErrUntrusted
	}
	return candidate, nil
}
