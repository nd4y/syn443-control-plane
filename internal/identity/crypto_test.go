package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func ec(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func proofRaw(t *testing.T, k *ecdsa.PrivateKey, header, claims []byte) string {
	t.Helper()
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	h := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, k, h[:])
	if e != nil {
		t.Fatal(e)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + b64.EncodeToString(sig)
}
func proofToken(t *testing.T, k *ecdsa.PrivateKey, c ProofClaims) string {
	return proofRaw(t, k, jsonBytes(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": PublicJWK(&k.PublicKey)}), jsonBytes(t, c))
}

func TestStrictJSON(t *testing.T) {
	var out struct {
		Key  JWK    `json:"key"`
		Name string `json:"name"`
	}
	if Decode([]byte(`{"name":"Иван"}`), &out, true) != nil || out.Name != "Иван" {
		t.Fatal("Unicode display field")
	}
	for _, raw := range []string{``, `null`, `{} {}`, `{"name":"a","name":"b"}`, `{"Name":"case"}`, `{"name":"a","NAME":"b"}`, `{"unknown":1}`, `{"key":{"kty":"EC","KTY":"EC"}}`, strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18), `{"name":"` + strings.Repeat("x", 16385) + `"}`, `{"key":null}`} {
		if Decode([]byte(raw), &out, true) == nil {
			t.Errorf("accepted invalid shape length=%d", len(raw))
		}
	}
	var open map[string]any
	if Decode([]byte(`{"x":{"n":1,"n":2}}`), &open, false) == nil {
		t.Fatal("duplicate nested field")
	}
	if Decode([]byte{0xff}, &open, false) == nil {
		t.Fatal("invalid UTF8")
	}
	if Decode([]byte(strings.Repeat(" ", 65537)), &open, false) == nil {
		t.Fatal("byte limit")
	}
	if Decode([]byte("["+strings.Repeat("0,", 256)+"0]"), &open, false) == nil {
		t.Fatal("array limit")
	}
}
func TestProofBinding(t *testing.T) {
	k := ec(t)
	now := time.Unix(1800000000, 0)
	ctx := ProofContext{"POST", "https://api.example.invalid/v1/devices/enroll", "synthetic-token", "server-nonce", Hash([]byte("{}")), now}
	c := ProofClaims{"unique-proof-identifier", "POST", ctx.URI, now.Unix(), Hash([]byte(ctx.Token)), ctx.Nonce, ctx.BodyHash}
	valid := proofToken(t, k, c)
	p, e := VerifyProof(valid, ctx)
	if e != nil {
		t.Fatal(e)
	}
	thumb, _ := PublicJWK(&k.PublicKey).Thumbprint()
	if p.Thumbprint != thumb {
		t.Fatal("thumbprint")
	}
	mutations := map[string]func(*ProofContext){"method": func(v *ProofContext) { v.Method = "GET" }, "uri": func(v *ProofContext) { v.URI += "/" }, "token": func(v *ProofContext) { v.Token += "x" }, "nonce": func(v *ProofContext) { v.Nonce = "different" }, "body": func(v *ProofContext) { v.BodyHash = Hash([]byte("[]")) }, "old": func(v *ProofContext) { v.Now = now.Add(61 * time.Second) }, "future": func(v *ProofContext) { v.Now = now.Add(-11 * time.Second) }, "query": func(v *ProofContext) { v.URI += "?x=y" }, "fragment": func(v *ProofContext) { v.URI += "#x" }, "insecure": func(v *ProofContext) { v.URI = "http://api.example.invalid/x" }}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			v := ctx
			change(&v)
			if _, e := VerifyProof(valid, v); e == nil {
				t.Fatal("binding accepted")
			}
		})
	}
	for _, offset := range []time.Duration{60 * time.Second, -10 * time.Second} {
		v := ctx
		v.Now = now.Add(offset)
		if _, e := VerifyProof(valid, v); e != nil {
			t.Fatal("inclusive clock boundary", e)
		}
	}
	bad := c
	bad.Jti = "short"
	if _, e := VerifyProof(proofToken(t, k, bad), ctx); e == nil {
		t.Fatal("short jti")
	}
	bad = c
	bad.Ath = ""
	if _, e := VerifyProof(proofToken(t, k, bad), ctx); e == nil {
		t.Fatal("missing ath")
	}
	parts := strings.Split(valid, ".")
	sig, _ := b64.DecodeString(parts[2])
	sig[0] ^= 1
	parts[2] = b64.EncodeToString(sig)
	if _, e := VerifyProof(strings.Join(parts, "."), ctx); e == nil {
		t.Fatal("tampered signature")
	}
	jwk := PublicJWK(&k.PublicKey)
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	for _, member := range []string{"jku", "crit", "x5u"} {
		h := map[string]any{}
		for a, b := range header {
			h[a] = b
		}
		h[member] = "https://untrusted.example.invalid"
		if _, e := VerifyProof(proofRaw(t, k, jsonBytes(t, h), jsonBytes(t, c)), ctx); e == nil {
			t.Fatal("untrusted header", member)
		}
	}
	private := map[string]any{"kty": jwk.Kty, "crv": jwk.Crv, "x": jwk.X, "y": jwk.Y, "d": b64.EncodeToString(k.D.Bytes())}
	header["jwk"] = private
	if _, e := VerifyProof(proofRaw(t, k, jsonBytes(t, header), jsonBytes(t, c)), ctx); e == nil {
		t.Fatal("private key in proof")
	}
	if _, e := VerifyProof(proofRaw(t, k, []byte(`{"typ":"dpop+jwt","alg":"none","alg":"ES256"}`), jsonBytes(t, c)), ctx); e == nil {
		t.Fatal("duplicate alg")
	}
	without := ctx
	without.Token = ""
	bad = c
	bad.Ath = ""
	if _, e := VerifyProof(proofToken(t, k, bad), without); e != nil {
		t.Fatal("token endpoint proof", e)
	}
	if _, e := VerifyProof(valid, without); e == nil {
		t.Fatal("unexpected token hash")
	}
	if _, e := RequestProof(valid, ProofContext{Method: ctx.Method, URI: ctx.URI, Token: ctx.Token, BodyHash: ctx.BodyHash, Now: now}); e != nil {
		t.Fatal("nonce peek", e)
	}
}
func TestJWKStrict(t *testing.T) {
	j := PublicJWK(&ec(t).PublicKey)
	for _, change := range []func(*JWK){func(j *JWK) { j.Kty = "RSA" }, func(j *JWK) { j.Crv = "P-384" }, func(j *JWK) { j.X += "=" }, func(j *JWK) { j.X = b64.EncodeToString(make([]byte, 32)); j.Y = j.X }, func(j *JWK) { j.Y = "" }} {
		v := j
		change(&v)
		if _, e := v.Thumbprint(); e == nil {
			t.Fatal("invalid key")
		}
	}
	raw := `{"crv":"P-256","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`
	thumb, e := j.Thumbprint()
	if e != nil || thumb != Hash([]byte(raw)) {
		t.Fatal("RFC7638 canonical members")
	}
}
func jwt(t *testing.T, k *rsa.PrivateKey, header, claims []byte) string {
	t.Helper()
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	h := sha256.Sum256([]byte(input))
	s, e := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + b64.EncodeToString(s)
}
func rsaFixture(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	return k, jsonBytes(t, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture", "alg": "RS256", "use": "sig", "n": b64.EncodeToString(k.N.Bytes()), "e": b64.EncodeToString(big.NewInt(65537).Bytes())}}})
}
func TestOIDCBindings(t *testing.T) {
	k, jwks := rsaFixture(t)
	keys, e := ParseJWKS(jwks)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	thumb, _ := PublicJWK(&ec(t).PublicKey).Thumbprint()
	o := OIDC{"https://id.example.invalid/realms/test", "syn443-api", "syn443-android", keys}
	h := jsonBytes(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "fixture"})
	claims := map[string]any{"iss": o.Issuer, "sub": "synthetic-user", "aud": []string{"account", o.Audience}, "azp": o.Client, "exp": now.Unix() + 300, "iat": now.Unix(), "cnf": map[string]string{"jkt": thumb}, "name": "Иван"}
	verify := func(v map[string]any) error { _, e := o.Verify(jwt(t, k, h, jsonBytes(t, v)), now); return e }
	if e := verify(claims); e != nil {
		t.Fatal(e)
	}
	badValues := map[string][]any{"iss": {"https://other.example.invalid"}, "sub": {"", "user\x00id"}, "aud": {"other", []string{}}, "azp": {"other"}, "exp": {now.Unix(), now.Unix() + 601}, "iat": {now.Unix() + 31, now.Unix() - 601}, "nbf": {now.Unix() + 31}, "cnf": {map[string]string{}, map[string]string{"jkt": "invalid"}}}
	for name, values := range badValues {
		for index, value := range values {
			t.Run(fmt.Sprintf("%s/%d", name, index), func(t *testing.T) {
				v := map[string]any{}
				for a, b := range claims {
					v[a] = b
				}
				v[name] = value
				if verify(v) == nil {
					t.Fatal("binding accepted")
				}
			})
		}
	}
	for _, name := range []string{"iss", "sub", "aud", "azp", "exp", "iat", "cnf"} {
		v := map[string]any{}
		for a, b := range claims {
			v[a] = b
		}
		delete(v, name)
		if verify(v) == nil {
			t.Fatal("missing", name)
		}
	}
	if _, e := o.Verify(jwt(t, k, []byte(`{"alg":"RS256","typ":"JWT","kid":"fixture","jku":"https://other.example.invalid"}`), jsonBytes(t, claims)), now); e == nil {
		t.Fatal("JWT URL header")
	}
	raw := jsonBytes(t, claims)
	dup := append([]byte(`{"sub":"other",`), raw[1:]...)
	if _, e := o.Verify(jwt(t, k, h, dup), now); e == nil {
		t.Fatal("duplicate subject")
	}
	other, _ := rsaFixture(t)
	if _, e := o.Verify(jwt(t, other, h, raw), now); e == nil {
		t.Fatal("untrusted signing key")
	}
	for _, raw := range [][]byte{[]byte(`{"keys":[]}`), []byte(strings.Replace(string(jwks), `"e":"AQAB"`, `"e":"Aw"`, 1)), []byte(strings.Replace(string(jwks), `"use":"sig"`, `"use":"enc"`, 1))} {
		if _, e := ParseJWKS(raw); e == nil {
			t.Fatal("invalid JWKS")
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestProviderPinnedDiscoveryAndCache(t *testing.T) {
	k, jwks := rsaFixture(t)
	issuer := "https://id.example.invalid/realms/test"
	now := time.Unix(1800000000, 0)
	var mu sync.Mutex
	count := 0
	bad := false
	tr := roundTrip(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		count++
		if r.Method != "GET" {
			t.Error("method")
		}
		body := string(jwks)
		switch r.URL.String() {
		case issuer + "/.well-known/openid-configuration":
			body = `{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/protocol/openid-connect/certs"}`
			if bad {
				body = `{"issuer":"wrong","jwks_uri":"https://untrusted.example.invalid/keys"}`
			}
		case issuer + "/protocol/openid-connect/certs":
		default:
			t.Error("untrusted request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	p, e := NewProvider(context.Background(), issuer, "syn443-api", "syn443-android", tr, false)
	if e != nil {
		t.Fatal(e)
	}
	thumb, _ := PublicJWK(&ec(t).PublicKey).Thumbprint()
	claims := map[string]any{"iss": issuer, "sub": "test-user", "aud": "syn443-api", "azp": "syn443-android", "iat": now.Unix(), "exp": now.Unix() + 300, "cnf": map[string]string{"jkt": thumb}}
	token := jwt(t, k, []byte(`{"alg":"RS256","typ":"JWT","kid":"fixture"}`), jsonBytes(t, claims))
	for i := 0; i < 5; i++ {
		if _, e = p.Verify(context.Background(), token, now); e != nil {
			t.Fatal(e)
		}
	}
	if count != 2 {
		t.Fatalf("cache made %d requests", count)
	}
	for i := 0; i < 5; i++ {
		if _, e = p.Verify(context.Background(), "bad", now); e == nil {
			t.Fatal("bad token")
		}
	}
	if count != 2 {
		t.Fatal("invalid token refresh storm")
	}
	bad = true
	p.loaded = time.Now().Add(-6 * time.Minute)
	p.attempted = time.Now().Add(-time.Minute)
	for i := 0; i < 5; i++ {
		if _, e = p.Verify(context.Background(), token, now); e == nil {
			t.Fatal("expired discovery accepted")
		}
	}
	if count != 3 {
		t.Fatal("failed discovery refresh storm")
	}
	p.gate <- struct{}{}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = p.Verify(cancelled, token, now); e == nil {
		t.Fatal("cancelled wait")
	}
	<-p.gate
	if _, e = NewProvider(context.Background(), issuer, "a", "c", tr, false); e == nil {
		t.Fatal("untrusted discovery")
	}
	for _, url := range []string{"http://id.example.invalid", issuer + "/", issuer + "?x=y", "https://user@id.example.invalid", "http://127.0.0.1:1234/realms/test"} {
		if _, e = NewProvider(context.Background(), url, "a", "c", tr, false); e == nil {
			t.Fatal("unsafe issuer")
		}
	}
	if _, e = NewProvider(context.Background(), issuer, "", "c", tr, false); e == nil {
		t.Fatal("missing audience")
	}
}

func TestProviderResponseLimitsAndOperatorDocument(t *testing.T) {
	issuer := "https://id.example.invalid/realms/test"
	for _, response := range []struct {
		status int
		body   string
	}{{302, ""}, {500, ""}, {200, strings.Repeat("x", 65537)}, {200, "not JSON"}, {200, `{"issuer":"` + issuer + `","jwks_uri":"https://other.example.invalid/keys"}`}, {200, `{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/protocol/openid-connect/certs","issuer":"duplicate"}`}} {
		tr := roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: response.status, Body: io.NopCloser(strings.NewReader(response.body)), Header: http.Header{}}, nil
		})
		if _, e := NewProvider(context.Background(), issuer, "a", "c", tr, false); e == nil {
			t.Fatal("untrusted or excessive discovery")
		}
	}
	var target struct {
		Value string `json:"value"`
	}
	raw := []byte(`{"value":"` + strings.Repeat("x", 20000) + `"}`)
	if DecodeOperatorDocument(raw, &target) != nil || len(target.Value) != 20000 {
		t.Fatal("bounded operator engine document")
	}
	if Decode(raw, &target, true) == nil {
		t.Fatal("network string budget weakened")
	}
	if Decode([]byte(`{}`), nil, true) == nil || Decode([]byte(`{}`), target, true) == nil {
		t.Fatal("invalid decoder target")
	}
}

func FuzzIdentityDecode(f *testing.F) {
	for _, v := range []string{`{}`, `{"a":1,"a":2}`, `{"name":"Иван"}`, `[]`, `null`} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 70000 {
			return
		}
		var value any
		_ = Decode([]byte(raw), &value, false)
	})
}
