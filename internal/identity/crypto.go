// Package identity implements bounded OIDC/DPoP verification, not administrative authority.
package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("identity_invalid")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,128}$`)
var digest = regexp.MustCompile(`^[a-zA-Z0-9_-]{43}$`)
var b64 = base64.RawURLEncoding.Strict()

// Decode rejects duplicate fields everywhere, excessive shapes and unknown request members.
// OIDC claims may contain Unicode display names; they are never used as account identifiers.
func Decode(raw []byte, dst any, closed bool) error {
	return decode(raw, dst, closed, 65536, 16384)
}

// DecodeOperatorDocument is only for an owner-only grant file, never a network request.
func DecodeOperatorDocument(raw []byte, dst any) error { return decode(raw, dst, true, 524288, 350000) }
func decode(raw []byte, dst any, closed bool, limit, maxString int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || dst == nil || reflect.TypeOf(dst).Kind() != reflect.Pointer || reflect.ValueOf(dst).IsNil() {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) error
	read = func(depth int) error {
		if depth > 16 {
			return ErrInvalid
		}
		v, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		switch x := v.(type) {
		case json.Delim:
			if x == '{' {
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] || len(seen) >= 128 || len(s) > 256 {
						return ErrInvalid
					}
					seen[s] = true
					if e = read(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return ErrInvalid
				}
			} else if x == '[' {
				n := 0
				for d.More() {
					n++
					if n > 256 {
						return ErrInvalid
					}
					if e := read(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return ErrInvalid
				}
			} else {
				return ErrInvalid
			}
		case string:
			if len(x) > maxString {
				return ErrInvalid
			}
		}
		return nil
	}
	if read(0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	if closed {
		d.DisallowUnknownFields()
		if exactShape(raw, reflect.TypeOf(dst)) != nil {
			return ErrInvalid
		}
	}
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	return nil
}

// encoding/json accepts case-insensitive struct names even with DisallowUnknownFields.
// Protocol request members are exact, including in nested public keys.
func exactShape(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return ErrInvalid
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			if name != "-" && f.IsExported() {
				fields[name] = f.Type
			}
		}
		for k, v := range object {
			field, ok := fields[k]
			if !ok || exactShape(v, field) != nil {
				return ErrInvalid
			}
		}
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return ErrInvalid
		}
		for _, v := range values {
			if exactShape(v, typ.Elem()) != nil {
				return ErrInvalid
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return ErrInvalid
		}
		for _, v := range values {
			if exactShape(v, typ.Elem()) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}
func Hash(raw []byte) string { sum := sha256.Sum256(raw); return b64.EncodeToString(sum[:]) }

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (j JWK) Public() (*ecdsa.PublicKey, error) {
	x, e := b64.DecodeString(j.X)
	y, f := b64.DecodeString(j.Y)
	if e != nil || f != nil || len(x) != 32 || len(y) != 32 || j.Kty != "EC" || j.Crv != "P-256" {
		return nil, ErrInvalid
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, ErrInvalid
	}
	return key, nil
}
func (j JWK) Thumbprint() (string, error) {
	if _, e := j.Public(); e != nil {
		return "", e
	}
	raw, _ := json.Marshal(map[string]string{"crv": j.Crv, "kty": j.Kty, "x": j.X, "y": j.Y})
	return Hash(raw), nil
}
func PublicJWK(key *ecdsa.PublicKey) JWK {
	return JWK{"EC", "P-256", b64.EncodeToString(key.X.FillBytes(make([]byte, 32))), b64.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
}
func parts(raw string) ([]byte, []byte, []byte, string, error) {
	if len(raw) > 16384 {
		return nil, nil, nil, "", ErrInvalid
	}
	p := strings.Split(raw, ".")
	if len(p) != 3 {
		return nil, nil, nil, "", ErrInvalid
	}
	h, e := b64.DecodeString(p[0])
	c, f := b64.DecodeString(p[1])
	s, g := b64.DecodeString(p[2])
	if e != nil || f != nil || g != nil {
		return nil, nil, nil, "", ErrInvalid
	}
	return h, c, s, p[0] + "." + p[1], nil
}

type ProofClaims struct {
	Jti         string `json:"jti"`
	Htm         string `json:"htm"`
	Htu         string `json:"htu"`
	Iat         int64  `json:"iat"`
	Ath         string `json:"ath,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	RequestHash string `json:"req_hash,omitempty"`
}
type Proof struct {
	Key        JWK
	Thumbprint string
	Claims     ProofClaims
}
type ProofContext struct {
	Method, URI, Token, Nonce, BodyHash string
	Now                                 time.Time
}

func VerifyProof(raw string, ctx ProofContext) (Proof, error) {
	var result Proof
	h, c, s, input, e := parts(raw)
	if e != nil {
		return result, e
	}
	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Jwk JWK    `json:"jwk"`
	}
	if Decode(h, &header, true) != nil || header.Typ != "dpop+jwt" || header.Alg != "ES256" || len(s) != 64 {
		return result, ErrInvalid
	}
	key, e := header.Jwk.Public()
	if e != nil {
		return result, e
	}
	sum := sha256.Sum256([]byte(input))
	if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(s[:32]), new(big.Int).SetBytes(s[32:])) {
		return result, ErrInvalid
	}
	var claims ProofClaims
	if Decode(c, &claims, true) != nil {
		return result, ErrInvalid
	}
	u, e := url.Parse(ctx.URI)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Host == "" || u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "127.0.0.1") {
		return result, ErrInvalid
	}
	if !identifier.MatchString(claims.Jti) || claims.Htm != ctx.Method || claims.Htu != ctx.URI || claims.Iat < ctx.Now.Unix()-60 || claims.Iat > ctx.Now.Unix()+10 || claims.Nonce != ctx.Nonce || claims.RequestHash != ctx.BodyHash {
		return result, ErrInvalid
	}
	if ctx.Token == "" {
		if claims.Ath != "" {
			return result, ErrInvalid
		}
	} else if claims.Ath != Hash([]byte(ctx.Token)) {
		return result, ErrInvalid
	}
	thumb, e := header.Jwk.Thumbprint()
	if e != nil {
		return result, e
	}
	return Proof{header.Jwk, thumb, claims}, nil
}

type Principal struct {
	Issuer     string
	Subject    string
	Thumbprint string
}
type OIDC struct {
	Issuer, Audience, Client string
	Keys                     map[string]*rsa.PublicKey
}

func (o OIDC) Verify(raw string, now time.Time) (Principal, error) {
	var p Principal
	h, c, s, input, e := parts(raw)
	if e != nil {
		return p, e
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if Decode(h, &header, true) != nil || header.Alg != "RS256" || (header.Typ != "JWT" && header.Typ != "at+jwt") {
		return p, ErrInvalid
	}
	key := o.Keys[header.Kid]
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E != 65537 {
		return p, ErrInvalid
	}
	sum := sha256.Sum256([]byte(input))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], s) != nil {
		return p, ErrInvalid
	}
	var claims struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Azp string          `json:"azp"`
		Exp int64           `json:"exp"`
		Iat int64           `json:"iat"`
		Nbf int64           `json:"nbf"`
		Cnf struct {
			Jkt string `json:"jkt"`
		} `json:"cnf"`
	}
	if Decode(c, &claims, false) != nil || claims.Iss != o.Issuer || claims.Azp != o.Client || claims.Sub == "" || len(claims.Sub) > 256 || strings.IndexFunc(claims.Sub, unicode.IsControl) >= 0 || claims.Exp <= now.Unix() || claims.Iat > now.Unix()+30 || claims.Iat < now.Unix()-600 || claims.Exp-claims.Iat > 600 || claims.Exp <= claims.Iat || claims.Nbf > now.Unix()+30 || !digest.MatchString(claims.Cnf.Jkt) {
		return p, ErrInvalid
	}
	var audiences []string
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		audiences = []string{one}
	} else if json.Unmarshal(claims.Aud, &audiences) != nil {
		return p, ErrInvalid
	}
	found := false
	for _, a := range audiences {
		if a == o.Audience {
			found = true
		}
	}
	if !found {
		return p, ErrInvalid
	}
	return Principal{claims.Iss, claims.Sub, claims.Cnf.Jkt}, nil
}
func ParseJWKS(raw []byte) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
	}
	if Decode(raw, &doc, false) != nil || len(doc.Keys) < 1 || len(doc.Keys) > 16 {
		return nil, ErrInvalid
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
			continue
		}
		n, e := b64.DecodeString(k.N)
		ex, f := b64.DecodeString(k.E)
		if e != nil || f != nil || len(n) < 256 || len(n) > 512 || len(ex) > 4 || k.Kid == "" || len(k.Kid) > 128 || keys[k.Kid] != nil {
			return nil, ErrInvalid
		}
		exponent := new(big.Int).SetBytes(ex)
		if !exponent.IsInt64() || exponent.Int64() != 65537 {
			return nil, ErrInvalid
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
		if key.N.BitLen() < 2048 {
			return nil, ErrInvalid
		}
		keys[k.Kid] = key
	}
	if len(keys) == 0 {
		return nil, ErrInvalid
	}
	return keys, nil
}
