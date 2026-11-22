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

// VerifyBound rejects identity substitution through an otherwise valid signed device ID.
// The caller derives the expected thumbprint from its own key, never the delivery response.
func VerifyBound(envelope string, keys map[string]*ecdsa.PublicKey, device, jkt string, now time.Time) (Payload, error) {
	p, e := Verify(envelope, keys, device, now)
	if e != nil || p.SchemaVersion != 2 || p.KeyThumbprint != jkt {
		return Payload{}, errors.New("untrusted key-bound publication")
	}
	return p, nil
}

// Verify prevents the delivery role from disclosing a misfiled/forged recipient's
// artifact. Root authority comes from a separate, operator-owned read-only file.
func Verify(envelope string, keys map[string]*ecdsa.PublicKey, device string, now time.Time) (Payload, error) {
	var p Payload
	bad := errors.New("untrusted publication")
	payload, e := verifiedDocument(envelope, keys, "syn443-policy+jws", MaxBundle)
	if e != nil {
		return p, bad
	}
	p, e = Decode(payload, now)
	if e != nil || p.TargetDevice != device || verifyDecisionBundle(p, keys, now) != nil {
		return p, bad
	}
	return p, nil
}

func verifiedDocument(envelope string, keys map[string]*ecdsa.PublicKey, kind string, limit int) ([]byte, error) {
	bad := errors.New("untrusted signed document")
	if len(envelope) == 0 || len(envelope) > limit {
		return nil, bad
	}
	parts := strings.SplitN(envelope, ".", 4)
	if len(parts) != 3 || len(parts[0]) > 1024 || len(parts[2]) != base64.RawURLEncoding.EncodedLen(64) {
		return nil, bad
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
		return nil, bad
	}
	canonical, e := Canonical(header)
	if e != nil || !bytes.Equal(canonical, header) {
		return nil, bad
	}
	var h map[string]string
	if json.Unmarshal(header, &h) != nil || len(h) != 3 || h["alg"] != "ES256" || h["typ"] != kind || !identifier.MatchString(h["kid"]) {
		return nil, bad
	}
	key := keys[h["kid"]]
	if key == nil || key.Curve != elliptic.P256() {
		return nil, bad
	}
	signature, e := decode(parts[2])
	if e != nil || len(signature) != 64 {
		return nil, bad
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, bad
	}
	payload, e := decode(parts[1])
	if e != nil {
		return nil, bad
	}
	canonical, e = Canonical(payload)
	if e != nil || !bytes.Equal(canonical, payload) {
		return nil, bad
	}
	return payload, nil
}
