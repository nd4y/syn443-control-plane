package configuration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const previewType = "syn443-configuration-preview+jws"

var previewOpaque = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var previewDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var previewRequest = regexp.MustCompile(`^[A-Za-z0-9_-]{24,128}$`)
var previewCapability = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// PreviewRecipient is resolved from actual account/device and assignment rows.
// These are configuration-head revisions, not periodically renewed VPN policy
// revisions. Capability/source/assignment changes must invalidate the ticket.
type PreviewRecipient struct {
	Owner            string `json:"owner"`
	Device           string `json:"device"`
	Thumbprint       string `json:"thumbprint"`
	GrantHash        string `json:"grantHash"`
	BaseRevision     int64  `json:"baseRevision"`
	BaseHash         string `json:"baseHash"`
	CapabilitiesHash string `json:"capabilitiesHash"`
}

// Preview contains hashes and recipient bindings, never native configuration,
// provider credentials or a caller-controlled approval boolean. Signing belongs
// exclusively to the independent publisher after live resolution/compilation.
type Preview struct {
	SchemaVersion  int                `json:"schemaVersion"`
	Origin         string             `json:"origin"`
	Actor          string             `json:"actor"`
	RequestID      string             `json:"requestId"`
	DraftID        string             `json:"draftId"`
	DraftRevision  int64              `json:"draftRevision"`
	DraftHash      string             `json:"draftHash"`
	TargetKind     string             `json:"targetKind"`
	TargetID       string             `json:"targetId"`
	Mode           string             `json:"mode"`
	DependencyHash string             `json:"dependencyHash"`
	EffectiveHash  string             `json:"effectiveHash"`
	Recipients     []PreviewRecipient `json:"recipients"`
	IssuedAtMs     int64              `json:"issuedAtMs"`
	ExpiresAtMs    int64              `json:"expiresAtMs"`
}

func (Preview) String() string            { return "ConfigurationPreview([redacted])" }
func (Preview) GoString() string          { return "ConfigurationPreview([redacted])" }
func (PreviewRecipient) String() string   { return "ConfigurationRecipient([redacted])" }
func (PreviewRecipient) GoString() string { return "ConfigurationRecipient([redacted])" }

func (p Preview) validate(now time.Time) error {
	u, e := url.Parse(p.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(p.Origin) > 2048 || strings.ToLower(u.Hostname()) != u.Hostname() {
		return ErrInvalid
	}
	if p.SchemaVersion != 1 || !previewOpaque.MatchString(p.Actor) || !previewRequest.MatchString(p.RequestID) || !id.MatchString(p.DraftID) || p.DraftRevision < 1 || p.DraftRevision > 9007199254740991 || !previewDigest.MatchString(p.DraftHash) || !previewDigest.MatchString(p.DependencyHash) || !previewDigest.MatchString(p.EffectiveHash) || !id.MatchString(p.TargetID) || len(p.Recipients) < 1 || len(p.Recipients) > 64 || p.IssuedAtMs <= 0 || p.IssuedAtMs > now.UnixMilli() || p.ExpiresAtMs <= now.UnixMilli() || p.ExpiresAtMs-p.IssuedAtMs > 180000 || p.ExpiresAtMs > 9007199254740991 {
		return ErrInvalid
	}
	switch p.TargetKind {
	case "template", "group", "user", "device":
	default:
		return ErrInvalid
	}
	switch p.Mode {
	case "home_wifi", "wifi", "cellular_restricted", "cellular":
	default:
		return ErrInvalid
	}
	seen := map[string]bool{}
	previous := ""
	for _, r := range p.Recipients {
		if !previewOpaque.MatchString(r.Owner) || !id.MatchString(r.Device) || !previewOpaque.MatchString(r.Thumbprint) || !previewOpaque.MatchString(r.GrantHash) || !previewDigest.MatchString(r.CapabilitiesHash) || r.BaseRevision < 0 || r.BaseRevision > 9007199254740991 || r.BaseRevision == 0 && r.BaseHash != "" || r.BaseRevision > 0 && !previewDigest.MatchString(r.BaseHash) || seen[r.Device] {
			return ErrInvalid
		}
		order := r.Owner + "/" + r.Device
		if order <= previous || p.TargetKind == "device" && (len(p.Recipients) != 1 || p.TargetID != r.Device) || p.TargetKind == "user" && p.TargetID != r.Owner {
			return ErrInvalid
		}
		previous = order
		seen[r.Device] = true
	}
	return nil
}

type previewHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

func previewPublicKey(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}

// SignPreview does not authorize anything by itself. Its caller must resolve the
// complete impact manifest, check current ACL/MFA and compile before signing.
func SignPreview(ctx context.Context, p Preview, kid string, key *ecdsa.PrivateKey, now time.Time) (string, error) {
	if ctx == nil || ctx.Err() != nil || p.validate(now) != nil || !id.MatchString(kid) || key == nil || !previewPublicKey(&key.PublicKey) || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return "", ErrInvalid
	}
	x, y := elliptic.P256().ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return "", ErrInvalid
	}
	header, _ := json.Marshal(previewHeader{"ES256", previewType, kid})
	body, e := json.Marshal(p)
	if e != nil || len(body) > 65536 {
		return "", ErrInvalid
	}
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(message))
	r, s, e := ecdsa.Sign(rand.Reader, key, digest[:])
	if e != nil {
		return "", ErrInvalid
	}
	// A single canonical signature representation makes ticket identity stable.
	half := new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(key.Params().N, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyPreview verifies the publisher's statement and the expected current
// actor/origin. Publication must additionally repeat live dependency, recipient,
// ACL and head-CAS checks; this short-lived ticket never extends an offline lease.
func VerifyPreview(ctx context.Context, ticket string, roots map[string]*ecdsa.PublicKey, origin, actor string, now time.Time) (Preview, error) {
	deny := func() (Preview, error) { return Preview{}, ErrInvalid }
	if ctx == nil || ctx.Err() != nil || len(ticket) > 90000 || len(roots) < 1 || len(roots) > 8 {
		return deny()
	}
	parts := strings.Split(ticket, ".")
	if len(parts) != 3 {
		return deny()
	}
	decode := func(s string) ([]byte, error) {
		v, e := base64.RawURLEncoding.Strict().DecodeString(s)
		if e != nil || base64.RawURLEncoding.EncodeToString(v) != s {
			return nil, ErrInvalid
		}
		return v, nil
	}
	header, e := decode(parts[0])
	if e != nil || len(header) > 512 {
		return deny()
	}
	var h previewHeader
	if identity.Decode(header, &h, true) != nil || h.Algorithm != "ES256" || h.Type != previewType || !id.MatchString(h.KeyID) {
		return deny()
	}
	key := roots[h.KeyID]
	if !previewPublicKey(key) {
		return deny()
	}
	raw, e := decode(parts[1])
	if e != nil || len(raw) > 65536 {
		return deny()
	}
	var p Preview
	if identity.DecodeConfiguration(raw, &p) != nil || p.validate(now) != nil || p.Origin != origin || p.Actor != actor {
		return deny()
	}
	sig, e := decode(parts[2])
	if e != nil || len(sig) != 64 {
		return deny()
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || s.Cmp(new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)) > 0 {
		return deny()
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], r, s) {
		return deny()
	}
	if ctx.Err() != nil {
		return Preview{}, ctx.Err()
	}
	return p, nil
}

// PreviewCapabilitiesHash binds a sorted, closed advertised capability set.
// It does not interpret a capability as a permission or grant.
func PreviewCapabilitiesHash(capabilities []string) (string, error) {
	if len(capabilities) < 1 || len(capabilities) > 16 {
		return "", ErrInvalid
	}
	copy := append([]string(nil), capabilities...)
	slices.Sort(copy)
	for i, c := range copy {
		if !previewCapability.MatchString(c) || i > 0 && copy[i-1] == c {
			return "", ErrInvalid
		}
	}
	raw, _ := json.Marshal(copy)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}
