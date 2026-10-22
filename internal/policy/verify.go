package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Verify prevents the delivery role from disclosing a misfiled/forged recipient's
// artifact. Root authority comes from a separate, operator-owned read-only file.
func Verify(envelope string, keys map[string]*ecdsa.PublicKey, device string, now time.Time) (Payload, error) {
	var p Payload
	bad := errors.New("untrusted publication")
	parts := strings.Split(envelope, ".")
	if len(envelope) > MaxBundle || len(parts) != 3 || len(parts[0]) > 1024 {
		return p, bad
	}
	decode := func(s string) ([]byte, error) {
		b, e := base64.RawURLEncoding.Strict().DecodeString(s)
		if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
			return nil, bad
		}
		return b, nil
	}
	header, e := decode(parts[0])
	if e != nil {
		return p, bad
	}
	canonical, e := Canonical(header)
	if e != nil || !bytes.Equal(canonical, header) {
		return p, bad
	}
	var h struct {
		Alg  string `json:"alg"`
		Kid  string `json:"kid"`
		Type string `json:"typ"`
	}
	decoder := json.NewDecoder(bytes.NewReader(header))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&h) != nil || h.Alg != "ES256" || h.Type != "syn443-policy+jws" || !identifier.MatchString(h.Kid) {
		return p, bad
	}
	key := keys[h.Kid]
	if key == nil || key.Curve != elliptic.P256() {
		return p, bad
	}
	signature, e := decode(parts[2])
	if e != nil || len(signature) != 64 {
		return p, bad
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return p, bad
	}
	payload, e := decode(parts[1])
	if e != nil {
		return p, bad
	}
	canonical, e = Canonical(payload)
	if e != nil || !bytes.Equal(canonical, payload) {
		return p, bad
	}
	p, e = Decode(payload, now)
	if e != nil || p.TargetDevice != device {
		return p, bad
	}
	return p, nil
}
