package overlay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func credentialFixture(t testing.TB) (Credential, CredentialBinding, *ecdsa.PrivateKey, time.Time) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	bytes := make([]byte, 16)
	if _, e = rand.Read(bytes); e != nil {
		t.Fatal(e)
	}
	value := hex.EncodeToString(bytes)
	value = value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:]
	ref := sha256.Sum256([]byte("synthetic-credential-reference"))
	thumb := sha256.Sum256([]byte("synthetic-device-key"))
	c := Credential{1, credentialAudience, fixtureAddress(), base64.RawURLEncoding.EncodeToString(thumb[:]), base64.RawURLEncoding.EncodeToString(ref[:]), 1, 0, "netbird.setup-key", now.UnixMilli(), now.UnixMilli(), now.UnixMilli() + 60000, value}
	b := CredentialBinding{Address: c.Address, KeyThumbprint: c.KeyThumbprint, Reference: c.Reference, Version: c.Version, SecurityEpoch: c.SecurityEpoch, OfflineUntilMs: now.UnixMilli() + 120000}
	return c, b, key, now
}
func rawCredential(t testing.TB, key *ecdsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}
func signedCredential(t testing.TB, key *ecdsa.PrivateKey, c Credential) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "fixture-online", "typ": credentialType})
	header, _ = policy.Canonical(header)
	payload, _ := json.Marshal(c)
	payload, _ = policy.Canonical(payload)
	return rawCredential(t, key, header, payload)
}
func TestCredentialSignerAndDeliveryVerifierBindAllAuthoritiesAndNeverLogSecret(t *testing.T) {
	c, b, key, now := credentialFixture(t)
	roots := map[string]*ecdsa.PublicKey{"fixture-online": &key.PublicKey}
	raw, e := SignCredential(c, b, "fixture-online", key, now)
	if e != nil {
		t.Fatal(e)
	}
	got, e := VerifyCredential(raw, roots, b, now)
	if e != nil || got.Value != c.Value {
		t.Fatal("addressed secret roundtrip failed", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", c, c, b, b), c.Value) || strings.Contains(fmt.Sprintf("%v %#v", b, b), b.Address.OwnerTag) {
		t.Fatal("credential diagnostics disclosed protected value")
	}
	alias := b
	alias.Address.ManagementURL = "https://API.EXAMPLE.INVALID:443/"
	if _, e = VerifyCredential(raw, roots, alias, now); e != nil {
		t.Fatal("canonical management origin alias fragmented identity")
	}
	for _, change := range []func(*CredentialBinding){func(b *CredentialBinding) { b.Address.DeviceID = "device-b" }, func(b *CredentialBinding) { b.Address.ResourceID = "resource-b" }, func(b *CredentialBinding) { b.Address.NetworkID = "network-b" }, func(b *CredentialBinding) { b.Address.IdentityEpoch++ }, func(b *CredentialBinding) {
		b.Address.OwnerTag = base64.RawURLEncoding.EncodeToString(make([]byte, 32, 32)) + "="
	}, func(b *CredentialBinding) { b.KeyThumbprint = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }, func(b *CredentialBinding) { b.Reference = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }, func(b *CredentialBinding) { b.Version++ }, func(b *CredentialBinding) { b.SecurityEpoch++ }, func(b *CredentialBinding) { b.OfflineUntilMs = now.UnixMilli() }, func(b *CredentialBinding) { b.OfflineUntilMs = c.ExpiresMs - 1 }} {
		other := b
		change(&other)
		if _, e = VerifyCredential(raw, roots, other, now); e == nil {
			t.Fatal("credential accepted for foreign authority/reference/lease")
		}
		if _, e = SignCredential(c, other, "fixture-online", key, now); e == nil {
			t.Fatal("signer ignored recipient/lease binding")
		}
	}
	if _, e = VerifyCredential(raw, roots, b, time.UnixMilli(c.ExpiresMs)); e == nil {
		t.Fatal("credential used at exact expiry")
	}
}
func TestCredentialClaimsAndPrivateKeysRejectUnsupportedOrUnboundedInput(t *testing.T) {
	c, b, key, now := credentialFixture(t)
	roots := map[string]*ecdsa.PublicKey{"fixture-online": &key.PublicKey}
	for _, change := range []func(*Credential){func(c *Credential) { c.SchemaVersion = 2 }, func(c *Credential) { c.Audience = "syn443-device" }, func(c *Credential) { c.Reference = "bad" }, func(c *Credential) { c.KeyThumbprint = strings.Repeat("_", 43) }, func(c *Credential) { c.Version = 0 }, func(c *Credential) { c.Version = 9007199254740992 }, func(c *Credential) { c.SecurityEpoch = -1 }, func(c *Credential) { c.SecurityEpoch = 9007199254740992 }, func(c *Credential) { c.Kind = "provider-management-token" }, func(c *Credential) { c.Value = "invalid" }, func(c *Credential) { c.Address.Provider = "tailscale" }, func(c *Credential) { c.IssuedAtMs = 0 }, func(c *Credential) { c.IssuedAtMs = now.UnixMilli() + 30001 }, func(c *Credential) { c.NotBeforeMs = c.IssuedAtMs - 1 }, func(c *Credential) { c.NotBeforeMs = now.UnixMilli() + 1 }, func(c *Credential) { c.ExpiresMs = now.UnixMilli() }, func(c *Credential) { c.ExpiresMs = c.NotBeforeMs }, func(c *Credential) { c.ExpiresMs = c.IssuedAtMs + 1800001 }} {
		bad := c
		change(&bad)
		if _, e := SignCredential(bad, b, "fixture-online", key, now); e == nil {
			t.Fatal("invalid addressed credential signed")
		}
		if _, e := VerifyCredential(signedCredential(t, key, bad), roots, b, now); e == nil {
			t.Fatal("signed invalid claims accepted")
		}
	}
	p384, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	other, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	zero := *key
	zero.D = new(big.Int)
	mismatch := *key
	mismatch.PublicKey = other.PublicKey
	noScalar := *key
	noScalar.D = nil
	noPoint := *key
	noPoint.X = nil
	for _, bad := range []*ecdsa.PrivateKey{nil, p384, &zero, &mismatch, &noScalar, &noPoint} {
		if _, e := SignCredential(c, b, "fixture-online", bad, now); e == nil {
			t.Fatal("invalid private key accepted")
		}
	}
	if _, e = SignCredential(c, b, "bad/key", key, now); e == nil {
		t.Fatal("invalid key identifier accepted")
	}
}
func TestCredentialJWSFramingTypeCanonicalEncodingAndTamperingFailClosed(t *testing.T) {
	c, b, key, now := credentialFixture(t)
	raw, e := SignCredential(c, b, "fixture-online", key, now)
	if e != nil {
		t.Fatal(e)
	}
	roots := map[string]*ecdsa.PublicKey{"fixture-online": &key.PublicKey}
	parts := strings.Split(raw, ".")
	for _, bad := range []string{"", strings.Repeat("x", 16385), "one.two", strings.Repeat("A", 1025) + ".AA.AA", "!.AA.AA", parts[0] + "=." + parts[1] + "." + parts[2], parts[0] + "." + parts[1] + ".!", parts[0] + "." + parts[1] + ".AA", parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)), parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("{}")) + "." + parts[2]} {
		if _, e = VerifyCredential(bad, roots, b, now); e == nil {
			t.Fatal("invalid credential JWS accepted")
		}
	}
	canonical, _ := policy.Canonical([]byte(`{"alg":"ES256","kid":"fixture-online","typ":"syn443-overlay-credential+jws"}`))
	payload, _ := json.Marshal(c)
	payload, _ = policy.Canonical(payload)
	for _, header := range [][]byte{[]byte(`{"alg":"none","kid":"fixture-online","typ":"syn443-overlay-credential+jws"}`), []byte(`{"alg":"ES256","kid":"fixture-online","typ":"syn443-policy+jws"}`), []byte(`{"alg":"ES256","kid":"fixture-online","typ":"syn443-overlay-credential+jws","extra":true}`), append([]byte(" "), canonical...), []byte(`{"alg":"ES256","kid":"missing","typ":"syn443-overlay-credential+jws"}`)} {
		clean, e := policy.Canonical(header)
		if e == nil && len(header) > 0 && header[0] != ' ' {
			header = clean
		}
		if _, e = VerifyCredential(rawCredential(t, key, header, payload), roots, b, now); e == nil {
			t.Fatal("credential header/context confusion accepted")
		}
	}
	for _, body := range [][]byte{append([]byte(" "), payload...), []byte(`{}`), []byte(`{"schemaVersion":1,"schemaVersion":1}`), []byte(`[]`), []byte(`{"unknown":true}`), []byte(strings.Repeat("x", 8193))} {
		if _, e = VerifyCredential(rawCredential(t, key, canonical, body), roots, b, now); e == nil {
			t.Fatal("noncanonical/open/oversized credential payload accepted")
		}
	}
	p384, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, public := range []*ecdsa.PublicKey{nil, &p384.PublicKey, {Curve: elliptic.P256()}, {Curve: elliptic.P256(), X: new(big.Int), Y: new(big.Int)}} {
		if _, e = VerifyCredential(raw, map[string]*ecdsa.PublicKey{"fixture-online": public}, b, now); e == nil {
			t.Fatal("untrusted/invalid public key accepted")
		}
	}
	// A syntactically invalid payload can have a valid signature and must still
	// fail after the signature gate. Request bytes are never logged.
	if _, e = VerifyCredential(rawCredential(t, key, canonical, []byte("!")), roots, b, now); e == nil {
		t.Fatal("invalid signed JSON accepted")
	}
}
func FuzzAddressedCredential(f *testing.F) {
	c, b, key, now := credentialFixture(f)
	seed, e := SignCredential(c, b, "fixture-online", key, now)
	if e != nil {
		f.Fatal(e)
	}
	roots := map[string]*ecdsa.PublicKey{"fixture-online": &key.PublicKey}
	f.Add(seed)
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16384 {
			return
		}
		_, _ = VerifyCredential(raw, roots, b, now)
	})
}

func TestCredentialPayloadMatchesClosedSharedSchema(t *testing.T) {
	c, _, _, _ := credentialFixture(t)
	raw, e := contracts.Files.ReadFile("v1/overlay-credential.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var document any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("schema JSON")
	}
	compiler := jsonschema.NewCompiler()
	const location = "https://contracts.example.invalid/overlay-credential.schema.json"
	if e = compiler.AddResource(location, document); e != nil {
		t.Fatal(e)
	}
	schema, e := compiler.Compile(location)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(c)
	var value map[string]any
	if json.Unmarshal(wire, &value) != nil || schema.Validate(value) != nil {
		t.Fatal("Go credential model differs from shared schema")
	}
	for _, field := range []string{"reference", "address", "keyThumbprint", "value"} {
		copy := map[string]any{}
		for k, v := range value {
			copy[k] = v
		}
		delete(copy, field)
		if schema.Validate(copy) == nil {
			t.Fatal("missing credential authority field accepted")
		}
	}
	value["extra"] = true
	if schema.Validate(value) == nil {
		t.Fatal("open credential schema")
	}
}
