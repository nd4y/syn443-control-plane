package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"math/big"
	"strings"
	"testing"
	"time"
)

func sample(t *testing.T) ([]byte, Payload, time.Time) {
	t.Helper()
	now := time.UnixMilli(1800000000000)
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	sum := sha256.Sum256(engine)
	p := Payload{SchemaVersion: 1, Operation: "configure", Revision: 1, TargetDevice: "device-example", Audience: "syn443-device", IssuedAtMs: now.UnixMilli() - 1000, NotBeforeMs: now.UnixMilli() - 1000, RefreshAfterMs: now.UnixMilli() + 300000, OfflineUntilMs: now.UnixMilli() + 600000, RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1"}, AlgorithmRevision: "m1-local-v1", EngineConfigB64: base64.RawURLEncoding.EncodeToString(engine), ContentHash: hex.EncodeToString(sum[:]), Activation: Gate{TimeoutSeconds: 30, Checks: []Check{{ID: "internet", Type: "https_204", Target: "https://health.example.org/generate_204", Required: true}}}}
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	return raw, p, now
}
func TestSignScopeAndRawES256(t *testing.T) {
	raw, _, now := sample(t)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := Sign(raw, "test-root", key, "device-example", 1, now)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(envelope, ".")
	signature, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || len(signature) != 64 {
		t.Fatal("signature size")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("invalid ES256")
	}
	if _, e = Verify(envelope, map[string]*ecdsa.PublicKey{"test-root": &key.PublicKey}, "device-example", now); e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(envelope, map[string]*ecdsa.PublicKey{}, "device-example", now); e == nil {
		t.Fatal("missing trusted publication root")
	}
	if _, e = Verify(envelope, map[string]*ecdsa.PublicKey{"test-root": &key.PublicKey}, "another-device", now); e == nil {
		t.Fatal("cross-device publication")
	}
	if _, e = Sign(raw, "test-root", key, "another-device", 1, now); e == nil {
		t.Fatal("scope bypass")
	}
	if _, e = Sign(raw, "test-root", key, "device-example", 2, now); e == nil {
		t.Fatal("revision bypass")
	}
	if _, e = Inspect(envelope, "device-example"); e != nil {
		t.Fatal(e)
	}
	if _, e = Inspect(envelope, "another-device"); e == nil {
		t.Fatal("recipient mismatch")
	}
	for _, bad := range []string{"", "a.b", "a.!.c", "a.e30.c", strings.Repeat("a", MaxBundle+1)} {
		if _, e = Inspect(bad, "device-example"); e == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
}

func TestVersionTwoPublicationBindsClientOwnedKey(t *testing.T) {
	_, p, now := sample(t)
	root, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := map[string]*ecdsa.PublicKey{"fixture-root": &root.PublicKey}
	own := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	other := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	legacy, _ := json.Marshal(p)
	old, e := Sign(legacy, "fixture-root", root, p.TargetDevice, p.Revision, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBound(old, keys, p.TargetDevice, own, now); e == nil {
		t.Fatal("legacy publication used as identity enrollment")
	}
	p.SchemaVersion = 2
	p.KeyThumbprint = own
	p.RequiredCapabilities = append(p.RequiredCapabilities, "policy.keybound.v2")
	raw, _ := json.Marshal(p)
	envelope, e := Sign(raw, "fixture-root", root, p.TargetDevice, p.Revision, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBound(envelope, keys, p.TargetDevice, own, now); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBound(envelope, keys, p.TargetDevice, other, now); e == nil {
		t.Fatal("delivery-chosen device ID substituted another client's policy")
	}
	for _, change := range []func(*Payload){func(v *Payload) { v.KeyThumbprint = "" }, func(v *Payload) { v.KeyThumbprint = strings.Repeat("x", 43) }, func(v *Payload) { v.RequiredCapabilities = v.RequiredCapabilities[:2] }, func(v *Payload) { v.SchemaVersion = 1 }, func(v *Payload) { v.SchemaVersion = 3 }} {
		v := p
		change(&v)
		raw, _ := json.Marshal(v)
		if _, e = Sign(raw, "fixture-root", root, v.TargetDevice, v.Revision, now); e == nil {
			t.Fatal("invalid key/version/capability combination")
		}
	}
}

func TestLockedDeviceSignatureFixture(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/policy-device-signature.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Device    string `json:"device"`
		Now       int64  `json:"nowMs"`
		Root      string `json:"spkiHex"`
		Key       string `json:"deviceSpkiHex"`
		Header    string `json:"headerHex"`
		Payload   string `json:"payloadHex"`
		Signature string `json:"signatureHex"`
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	decode := func(value string) []byte {
		t.Helper()
		v, e := hex.DecodeString(value)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	root, e := x509.ParsePKIXPublicKey(decode(f.Root))
	if e != nil {
		t.Fatal(e)
	}
	device, e := x509.ParsePKIXPublicKey(decode(f.Key))
	if e != nil {
		t.Fatal(e)
	}
	jkt, e := identity.PublicJWK(device.(*ecdsa.PublicKey)).Thumbprint()
	if e != nil {
		t.Fatal(e)
	}
	parts := []string{}
	for _, v := range []string{f.Header, f.Payload, f.Signature} {
		parts = append(parts, base64.RawURLEncoding.EncodeToString(decode(v)))
	}
	p, e := VerifyBound(strings.Join(parts, "."), map[string]*ecdsa.PublicKey{"test-root": root.(*ecdsa.PublicKey)}, f.Device, jkt, time.UnixMilli(f.Now))
	if e != nil || p.KeyThumbprint != jkt {
		t.Fatal("cross-platform device-key fixture", e)
	}
}
func TestDecodeNegativeAndBoundary(t *testing.T) {
	raw, original, now := sample(t)
	if _, e := Decode(raw, now); e != nil {
		t.Fatal(e)
	}
	tests := []func(*Payload){func(p *Payload) { p.SchemaVersion = 2 }, func(p *Payload) { p.Revision = 0 }, func(p *Payload) { p.SecurityEpoch = -1 }, func(p *Payload) { p.RevocationFloor = 2 }, func(p *Payload) { p.Audience = "another-service" }, func(p *Payload) { p.IssuedAtMs = now.UnixMilli() + 300001 }, func(p *Payload) { p.NotBeforeMs = now.UnixMilli() + 1 }, func(p *Payload) { p.OfflineUntilMs = now.UnixMilli() }, func(p *Payload) { p.OfflineUntilMs = p.IssuedAtMs + 604800001 }, func(p *Payload) { p.ContentHash = strings.Repeat("0", 64) }, func(p *Payload) { p.RequiredCapabilities = []string{"remote.code"} }, func(p *Payload) { p.Activation.TimeoutSeconds = 121 }, func(p *Payload) { p.Activation.Checks = []Check{} }, func(p *Payload) { p.AlgorithmRevision = "remote" }}
	for i, change := range tests {
		p := original
		change(&p)
		bytes, _ := json.Marshal(p)
		if _, e := Decode(bytes, now); e == nil {
			t.Errorf("invalid case %d accepted", i)
		}
	}
	for _, check := range []Check{{ID: "x", Type: "shell", Target: "example.org", Required: true}, {ID: "x", Type: "https_204", Target: "http://health.example.org", Required: true}, {ID: "x", Type: "tcp_banner", Target: "example.org", Port: 22, Expected: "SSH-", Required: true}} {
		p := original
		p.Activation.Checks = []Check{check}
		bytes, _ := json.Marshal(p)
		if _, e := Decode(bytes, now); e == nil {
			t.Fatal("invalid gate accepted")
		}
	}
	p := original
	p.Activation.Checks = append(append([]Check{}, original.Activation.Checks...), Check{ID: "home", Type: "tcp_banner", Target: "home.example.org", Port: 22, Expected: "SSH-", Required: true})
	bytes, _ := json.Marshal(p)
	if _, e := Decode(bytes, now); e != nil {
		t.Fatal(e)
	}
}
func FuzzPolicyDecode(f *testing.F) {
	raw, err := contracts.Files.ReadFile("v1/policy-vectors.json")
	if err != nil {
		f.Fatal("fixture unavailable")
	}
	var fixture map[string]json.RawMessage
	if json.Unmarshal(raw, &fixture) != nil {
		f.Fatal("fixture invalid")
	}
	var encoded string
	if json.Unmarshal(fixture["payloadHex"], &encoded) != nil {
		f.Fatal("fixture payload")
	}
	valid, err := hex.DecodeString(encoded)
	if err != nil {
		f.Fatal("fixture hex")
	}
	f.Add(valid)
	f.Add([]byte(`{"revision":1,"revision":2}`))
	f.Add([]byte(`{"revision":1e10}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Decode(raw, time.UnixMilli(1800000000000))
		if err != nil {
			return
		}
		clean, err := Canonical(raw)
		if err != nil {
			t.Fatal("accepted data failed canonicalization")
		}
		again, err := Canonical(clean)
		if err != nil || !bytes.Equal(clean, again) {
			t.Fatal("canonicalization not stable")
		}
		if p.Validate(time.UnixMilli(1800000000000)) != nil {
			t.Fatal("accepted data failed revalidation")
		}
	})
}

func TestCanonicalStrictJSON(t *testing.T) {
	for _, bad := range []string{`{"a":1,"\u0061":2}`, `{"a":1e2}`, `{"a":1.0}`, `{"a":9007199254740992}`, `{} {}`, `{"a":[1,]}`, `{"a":"\ud800"}`, strings.Repeat("[", 26) + strings.Repeat("]", 26)} {
		if _, e := Canonical([]byte(bad)); e == nil {
			t.Fatal("nonconforming JSON accepted")
		}
	}
	canonical, e := Canonical([]byte(` {"z":"<>&", "a":0} `))
	if e != nil || string(canonical) != `{"a":0,"z":"<>&"}` {
		t.Fatal("canonical mismatch")
	}
	raw, _, now := sample(t)
	raw = append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
	if _, e = Decode(raw, now); e == nil {
		t.Fatal("unknown field accepted")
	}
}
