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
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func previewFixture(t *testing.T) (Preview, *ecdsa.PrivateKey, time.Time) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	digest := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	p := Preview{SchemaVersion: 1, Origin: "https://control.example.invalid", Actor: identity.Hash([]byte("synthetic-admin")), RequestID: identity.Hash([]byte("preview-operation")), DraftID: "draft-a", DraftRevision: 1, DraftHash: digest("draft"), TargetKind: "device", TargetID: "device-a", Mode: "wifi", DependencyHash: digest("immutable dependencies"), EffectiveHash: digest("effective portable plan"), IssuedAtMs: now.UnixMilli(), ExpiresAtMs: now.Add(3 * time.Minute).UnixMilli(), Recipients: []PreviewRecipient{{Owner: identity.Hash([]byte("owner")), Device: "device-a", Thumbprint: identity.Hash([]byte("device-key")), GrantHash: identity.Hash([]byte("grant")), CapabilitiesHash: digest("capabilities")}}}
	return p, key, now
}

func TestPreviewIndependentlyVerifiesPurposeRecipientImpactAndExpiry(t *testing.T) {
	p, key, now := previewFixture(t)
	ctx := context.Background()
	ticket, e := SignPreview(ctx, p, "preview-root", key, now)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(ticket, ".")
	sig, e := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("independent signature verification failed")
	}
	roots := map[string]*ecdsa.PublicKey{"preview-root": &key.PublicKey}
	got, e := VerifyPreview(ctx, ticket, roots, p.Origin, p.Actor, now.Add(179*time.Second))
	if e != nil || got.DraftHash != p.DraftHash || got.Recipients[0] != p.Recipients[0] {
		t.Fatal("immutable preview lost target/hash binding", e)
	}
	for _, at := range []time.Time{now.Add(-time.Millisecond), now.Add(180 * time.Second), now.Add(181 * time.Second)} {
		if value, e := VerifyPreview(ctx, ticket, roots, p.Origin, p.Actor, at); e == nil || value.Actor != "" {
			t.Fatal("ticket accepted outside its original lease")
		}
	}
	for _, change := range []struct{ origin, actor string }{{"https://foreign.example.invalid", p.Actor}, {p.Origin, identity.Hash([]byte("foreign actor"))}} {
		if _, e := VerifyPreview(ctx, ticket, roots, change.origin, change.actor, now); e == nil {
			t.Fatal("preview borrowed another origin or actor")
		}
	}
	if fmt.Sprintf("%v %#v %v %#v", p, p, p.Recipients[0], p.Recipients[0]) != "ConfigurationPreview([redacted]) ConfigurationPreview([redacted]) ConfigurationRecipient([redacted]) ConfigurationRecipient([redacted])" {
		t.Fatal("preview diagnostic disclosure")
	}
}

func TestPreviewRejectsMalformedScopeAndNeverSignsAPIsReadyFlag(t *testing.T) {
	changes := []func(*Preview){
		func(p *Preview) { p.SchemaVersion = 2 }, func(p *Preview) { p.Origin = "http://control.example.invalid" }, func(p *Preview) { p.Origin += "/path" }, func(p *Preview) { p.Origin += "?" }, func(p *Preview) { p.Origin += "#fragment" }, func(p *Preview) { p.Origin = "https://user@control.example.invalid" }, func(p *Preview) { p.Origin = "https://CONTROL.example.invalid" }, func(p *Preview) { p.Origin = "https://" },
		func(p *Preview) { p.Actor = "operator" }, func(p *Preview) { p.RequestID = "short" }, func(p *Preview) { p.DraftID = "../escape" }, func(p *Preview) { p.DraftRevision = 0 }, func(p *Preview) { p.DraftRevision = 9007199254740992 }, func(p *Preview) { p.DraftHash = "unverified" }, func(p *Preview) { p.DependencyHash = "" }, func(p *Preview) { p.EffectiveHash = "" }, func(p *Preview) { p.TargetKind = "all" }, func(p *Preview) { p.TargetID = "" }, func(p *Preview) { p.Mode = "automatic executable" },
		func(p *Preview) { p.IssuedAtMs = 0 }, func(p *Preview) { p.IssuedAtMs++ }, func(p *Preview) { p.ExpiresAtMs = p.IssuedAtMs }, func(p *Preview) { p.ExpiresAtMs++ }, func(p *Preview) { p.Recipients = nil }, func(p *Preview) { p.Recipients = append(p.Recipients, p.Recipients[0]) },
		func(p *Preview) { p.Recipients[0].Owner = "foreign" }, func(p *Preview) { p.Recipients[0].Thumbprint = "" }, func(p *Preview) { p.Recipients[0].GrantHash = "" }, func(p *Preview) { p.Recipients[0].Device = "other-device" }, func(p *Preview) { p.Recipients[0].BaseRevision = -1 }, func(p *Preview) { p.Recipients[0].BaseHash = "nonempty-with-zero-revision" }, func(p *Preview) { p.Recipients[0].BaseRevision = 1 }, func(p *Preview) { p.Recipients[0].CapabilitiesHash = "" }, func(p *Preview) { p.TargetKind = "user"; p.TargetID = "wrong-owner" },
	}
	for i, change := range changes {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, key, now := previewFixture(t)
			change(&p)
			if ticket, e := SignPreview(context.Background(), p, "root", key, now); e == nil || ticket != "" {
				t.Fatal("invalid scope signed")
			}
		})
	}
	p, key, now := previewFixture(t)
	for _, kid := range []string{"", "../foreign", strings.Repeat("x", 65)} {
		if _, e := SignPreview(context.Background(), p, kid, key, now); e == nil {
			t.Fatal("invalid key id")
		}
	}
	for _, key := range []*ecdsa.PrivateKey{nil, {}, {PublicKey: key.PublicKey}, {PublicKey: key.PublicKey, D: big.NewInt(0)}, {PublicKey: key.PublicKey, D: key.Params().N}, {PublicKey: key.PublicKey, D: big.NewInt(1)}} {
		if _, e := SignPreview(context.Background(), p, "root", key, now); e == nil {
			t.Fatal("invalid signing key")
		}
	}
	if _, e := SignPreview(nil, p, "root", key, now); e == nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := SignPreview(ctx, p, "root", key, now); e == nil {
		t.Fatal("cancelled signature")
	}
}

func TestPreviewRejectsHeaderInjectionBodyTamperingAndSignatureMalleability(t *testing.T) {
	p, key, now := previewFixture(t)
	ticket, e := SignPreview(context.Background(), p, "root", key, now)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(ticket, ".")
	roots := map[string]*ecdsa.PublicKey{"root": &key.PublicKey}
	encode := base64.RawURLEncoding.EncodeToString
	bad := []string{"", ticket + ".extra", strings.Repeat("x", 90001), parts[0] + "=." + parts[1] + "." + parts[2], "!." + parts[1] + "." + parts[2], parts[0] + ".!." + parts[2], parts[0] + "." + parts[1] + ".!", parts[0] + "." + parts[1] + "." + encode(make([]byte, 64)), parts[0] + "." + parts[1] + "." + encode(make([]byte, 63))}
	for _, header := range []string{`{"alg":"none","typ":"syn443-configuration-preview+jws","kid":"root"}`, `{"alg":"ES256","typ":"JWT","kid":"root"}`, `{"alg":"ES256","typ":"syn443-configuration-preview+jws","kid":"foreign"}`, `{"alg":"ES256","typ":"syn443-configuration-preview+jws","kid":"root","jku":"https://foreign.example.invalid"}`, `{"alg":"ES256","alg":"ES256","typ":"syn443-configuration-preview+jws","kid":"root"}`, `null`, strings.Repeat("x", 513)} {
		bad = append(bad, encode([]byte(header))+"."+parts[1]+"."+parts[2])
	}
	for _, body := range []string{`null`, `{"ready":true}`, strings.Repeat("x", 65537)} {
		bad = append(bad, parts[0]+"."+encode([]byte(body))+"."+parts[2])
	}
	p.EffectiveHash = p.DraftHash
	raw, _ := json.Marshal(p)
	bad = append(bad, parts[0]+"."+encode(raw)+"."+parts[2])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	s := new(big.Int).SetBytes(sig[32:])
	s.Sub(key.Params().N, s)
	s.FillBytes(sig[32:])
	bad = append(bad, parts[0]+"."+parts[1]+"."+encode(sig))
	for i, ticket := range bad {
		if p, e := VerifyPreview(context.Background(), ticket, roots, p.Origin, p.Actor, now); e == nil || p.Actor != "" {
			t.Fatalf("accepted altered ticket %d", i)
		}
	}
	for _, roots := range []map[string]*ecdsa.PublicKey{nil, {"root": nil}, {"root": {Curve: elliptic.P384()}}, {"root": {Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}}} {
		if _, e := VerifyPreview(context.Background(), ticket, roots, p.Origin, p.Actor, now); e == nil {
			t.Fatal("untrusted key")
		}
	}
	if _, e := VerifyPreview(nil, ticket, roots, p.Origin, p.Actor, now); e == nil {
		t.Fatal("nil verifier context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := VerifyPreview(ctx, ticket, roots, p.Origin, p.Actor, now); e == nil {
		t.Fatal("cancelled verification")
	}
}

func TestPreviewBoundsRecipientManifestAndCapabilitySet(t *testing.T) {
	p, key, now := previewFixture(t)
	p.TargetKind = "template"
	p.TargetID = "template-a"
	recipient := p.Recipients[0]
	p.Recipients = nil
	for i := 0; i < 64; i++ {
		r := recipient
		r.Device = fmt.Sprintf("device-%02d", i)
		r.BaseRevision = 1
		r.BaseHash = p.DraftHash
		p.Recipients = append(p.Recipients, r)
	}
	if _, e := SignPreview(context.Background(), p, "root", key, now); e != nil {
		t.Fatal("64-recipient bound", e)
	}
	p.Recipients = append(p.Recipients, recipient)
	if _, e := SignPreview(context.Background(), p, "root", key, now); e == nil {
		t.Fatal("recipient quota ignored")
	}
	p.Recipients = p.Recipients[:64]
	p.Recipients[0], p.Recipients[1] = p.Recipients[1], p.Recipients[0]
	if _, e := SignPreview(context.Background(), p, "root", key, now); e == nil {
		t.Fatal("noncanonical impact order")
	}
	p.Recipients = []PreviewRecipient{recipient}
	p.TargetKind = "user"
	p.TargetID = recipient.Owner
	if _, e := SignPreview(context.Background(), p, "root", key, now); e != nil {
		t.Fatal("user scope", e)
	}
	p.TargetKind = "group"
	p.TargetID = "group-a"
	if _, e := SignPreview(context.Background(), p, "root", key, now); e != nil {
		t.Fatal("group scope", e)
	}
	input := []string{"policy.keybound.v2", "engine-config.v1"}
	a, e := PreviewCapabilitiesHash(input)
	if e != nil {
		t.Fatal(e)
	}
	b, e := PreviewCapabilitiesHash([]string{input[1], input[0]})
	if e != nil || a != b || input[0] != "policy.keybound.v2" || !previewDigest.MatchString(a) {
		t.Fatal("capability hash unstable or input mutated")
	}
	for _, input := range [][]string{nil, {}, {"duplicate", "duplicate"}, {"unknown/path"}, {strings.Repeat("x", 65)}, make([]string, 17)} {
		if _, e := PreviewCapabilitiesHash(input); e == nil {
			t.Fatal("invalid capability inventory")
		}
	}
}
