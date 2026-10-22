// Package policy is the M1 bounded signed-policy publisher. It is not an enrollment service.
package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxBundle = 524288

type Check struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Expected string `json:"expected"`
	Required bool   `json:"required"`
}
type Gate struct {
	TimeoutSeconds int     `json:"timeoutSeconds"`
	AllowDegraded  bool    `json:"allowDegraded"`
	Checks         []Check `json:"checks"`
}
type Payload struct {
	SchemaVersion        int      `json:"schemaVersion"`
	Revision             int64    `json:"revision"`
	SecurityEpoch        int64    `json:"securityEpoch"`
	RevocationFloor      int64    `json:"revocationFloor"`
	TargetDevice         string   `json:"targetDevice"`
	Audience             string   `json:"audience"`
	IssuedAtMs           int64    `json:"issuedAtMs"`
	NotBeforeMs          int64    `json:"notBeforeMs"`
	RefreshAfterMs       int64    `json:"refreshAfterMs"`
	OfflineUntilMs       int64    `json:"offlineUntilMs"`
	RequiredCapabilities []string `json:"requiredCapabilities"`
	AlgorithmRevision    string   `json:"algorithmRevision"`
	EngineConfigB64      string   `json:"engineConfigB64"`
	ContentHash          string   `json:"contentHash"`
	Activation           Gate     `json:"activation"`
	Operation            string   `json:"operation"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var safeHost = regexp.MustCompile(`^[a-zA-Z0-9.:-]{1,253}$`)

func ascii(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
func (p Payload) Validate(now time.Time) error {
	bad := errors.New("invalid policy")
	if p.Operation != "configure" && p.Operation != "release" {
		return bad
	}
	if p.SchemaVersion != 1 || p.Revision < 1 || p.Revision > 9007199254740991 || p.SecurityEpoch < 0 || p.SecurityEpoch > 9007199254740991 || p.RevocationFloor < 0 || p.RevocationFloor > p.Revision || !identifier.MatchString(p.TargetDevice) || len(p.TargetDevice) < 8 || p.Audience != "syn443-device" {
		return bad
	}
	n := now.UnixMilli()
	if p.IssuedAtMs < 1 || p.IssuedAtMs > n+300000 || p.NotBeforeMs < p.IssuedAtMs || p.NotBeforeMs > n || p.RefreshAfterMs < p.NotBeforeMs || p.RefreshAfterMs > p.OfflineUntilMs || p.OfflineUntilMs <= n || p.OfflineUntilMs-p.IssuedAtMs > 604800000 {
		return bad
	}
	caps := map[string]bool{}
	allowed := map[string]bool{"engine-config.v1": true, "policy.es256.v1": true, "tun.lease.v1": true, "netbird.direct": true, "netbird.vless": true}
	if len(p.RequiredCapabilities) < 1 || len(p.RequiredCapabilities) > 16 || p.AlgorithmRevision != "m1-local-v1" {
		return bad
	}
	for _, c := range p.RequiredCapabilities {
		if !allowed[c] || caps[c] {
			return bad
		}
		caps[c] = true
	}
	if !caps["engine-config.v1"] || !caps["tun.lease.v1"] {
		return bad
	}
	engine, err := base64.RawURLEncoding.Strict().DecodeString(p.EngineConfigB64)
	sum := sha256.Sum256(engine)
	if err != nil || len(engine) < 1 || len(engine) > 262144 || !utf8.Valid(engine) || !json.Valid(engine) || hex.EncodeToString(sum[:]) != p.ContentHash {
		return bad
	}
	if p.Activation.TimeoutSeconds < 30 || p.Activation.TimeoutSeconds > 120 || len(p.Activation.Checks) < 1 || len(p.Activation.Checks) > 8 {
		return bad
	}
	ids := map[string]bool{}
	requiredHTTPS := false
	for _, c := range p.Activation.Checks {
		if !identifier.MatchString(c.ID) || len(c.ID) > 48 || ids[c.ID] {
			return bad
		}
		ids[c.ID] = true
		switch c.Type {
		case "https_204":
			u, e := url.Parse(c.Target)
			if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || !ascii(c.Target) || len(c.Target) > 2048 || c.Port != 0 || c.Expected != "" {
				return bad
			}
			requiredHTTPS = requiredHTTPS || c.Required
		case "tcp_banner":
			if !safeHost.MatchString(c.Target) || c.Port < 1 || c.Port > 65535 || len(c.Expected) < 1 || len(c.Expected) > 64 || !ascii(c.Expected) {
				return bad
			}
		default:
			return bad
		}
	}
	if !requiredHTTPS {
		return bad
	}
	return nil
}

// Strict JSON preflight preserves duplicate keys, rejects floats and bounds all containers.
func read(d *json.Decoder, depth int) (any, error) {
	if depth > 24 {
		return nil, errors.New("JSON depth")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		if v == '{' {
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok || len(m) >= 64 {
					return nil, errors.New("object limit")
				}
				if _, exists := m[key]; exists {
					return nil, errors.New("duplicate key")
				}
				x, e := read(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = x
			}
			t, e := d.Token()
			if e != nil || t != json.Delim('}') {
				return nil, errors.New("object end")
			}
			return m, nil
		}
		if v == '[' {
			a := []any{}
			for d.More() {
				if len(a) >= 128 {
					return nil, errors.New("array limit")
				}
				x, e := read(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			t, e := d.Token()
			if e != nil || t != json.Delim(']') {
				return nil, errors.New("array end")
			}
			return a, nil
		}
		return nil, errors.New("delimiter")
	case json.Number:
		n, e := v.Int64()
		if e != nil || n < -9007199254740991 || n > 9007199254740991 {
			return nil, errors.New("safe integers only")
		}
		return n, nil
	case string:
		if !ascii(v) {
			return nil, errors.New("M1 metadata strings are ASCII")
		}
		return v, nil
	case bool, nil:
		return v, nil
	}
	return nil, errors.New("JSON type")
}
func Canonical(raw []byte) ([]byte, error) {
	if len(raw) > MaxBundle || !utf8.Valid(raw) {
		return nil, errors.New("JSON size/encoding")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := read(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if e = encoder.Encode(v); e != nil {
		return nil, e
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{10}), nil
}
func Decode(raw []byte, now time.Time) (Payload, error) {
	var p Payload
	clean, e := Canonical(raw)
	if e != nil {
		return p, e
	}
	if e = validateSchema(clean); e != nil {
		return p, e
	}
	d := json.NewDecoder(bytes.NewReader(clean))
	d.DisallowUnknownFields()
	if e = d.Decode(&p); e != nil {
		return p, errors.New("policy schema")
	}
	return p, p.Validate(now)
}
func Sign(raw []byte, kid string, key *ecdsa.PrivateKey, device string, revision int64, now time.Time) (string, error) {
	p, e := Decode(raw, now)
	if e != nil {
		return "", e
	}
	if key == nil || key.Curve != elliptic.P256() || !identifier.MatchString(kid) || p.TargetDevice != device || p.Revision != revision {
		return "", errors.New("publication scope mismatch")
	}
	payload, _ := Canonical(raw)
	header, _ := Canonical([]byte(fmt.Sprintf(`{"alg":"ES256","kid":%q,"typ":"syn443-policy+jws"}`, kid)))
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, digest[:])
	if e != nil {
		return "", e
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + enc.EncodeToString(signature), nil
}
func Inspect(envelope, device string) (Payload, error) {
	var p Payload
	parts := strings.Split(envelope, ".")
	if len(envelope) > MaxBundle || len(parts) != 3 {
		return p, errors.New("bundle format")
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return p, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(&p); e != nil || p.TargetDevice != device {
		return p, errors.New("bundle audience")
	}
	return p, nil
}
