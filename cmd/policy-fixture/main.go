// Synthetic cross-platform conformance fixture. Private key lives only in RAM.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"os"
	"strings"
	"time"
)

func main() {
	now := time.UnixMilli(1800000000000)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		panic("fixture key generation")
	}
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	sum := sha256.Sum256(engine)
	p := policy.Payload{SchemaVersion: 1, Operation: "configure", Revision: 1, TargetDevice: "device-example", Audience: "syn443-device", IssuedAtMs: now.UnixMilli() - 1000, NotBeforeMs: now.UnixMilli() - 1000, RefreshAfterMs: now.UnixMilli() + 300000, OfflineUntilMs: now.UnixMilli() + 600000, RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1"}, AlgorithmRevision: "m1-local-v1", EngineConfigB64: base64.RawURLEncoding.EncodeToString(engine), ContentHash: hex.EncodeToString(sum[:]), Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.org/generate_204", Required: true}}}}
	var deviceSPKI []byte
	if len(os.Args) > 1 {
		if len(os.Args) != 2 || os.Args[1] != "--key-bound" {
			panic("fixture option")
		}
		deviceKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			panic("fixture device key")
		}
		p.SchemaVersion = 2
		p.KeyThumbprint, e = identity.PublicJWK(&deviceKey.PublicKey).Thumbprint()
		if e != nil {
			panic("fixture thumbprint")
		}
		p.RequiredCapabilities = append(p.RequiredCapabilities, "policy.keybound.v2")
		deviceSPKI, e = x509.MarshalPKIXPublicKey(&deviceKey.PublicKey)
		if e != nil {
			panic("fixture device public encoding")
		}
	}
	raw, _ := json.Marshal(p)
	envelope, e := policy.Sign(raw, "test-root", key, p.TargetDevice, p.Revision, now)
	if e != nil {
		panic("fixture publication")
	}
	spki, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		panic("fixture public encoding")
	}
	parts := strings.Split(envelope, ".")
	decode := func(s string) string {
		b, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil {
			panic("fixture encoding")
		}
		return hex.EncodeToString(b)
	}
	// Hex segments make it explicit that this is public signature evidence, not an access token.
	result := map[string]any{"nowMs": now.UnixMilli(), "device": p.TargetDevice, "spkiHex": hex.EncodeToString(spki), "headerHex": decode(parts[0]), "payloadHex": decode(parts[1]), "signatureHex": decode(parts[2])}
	if len(deviceSPKI) > 0 {
		result["deviceSpkiHex"] = hex.EncodeToString(deviceSPKI)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(result) != nil {
		panic("fixture output")
	}
}
