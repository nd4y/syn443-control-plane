package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func anchorFixture(t *testing.T, id string, epoch int64) (Anchor, *ecdsa.PrivateKey) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	spki, e := Public(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return Anchor{ID: id, SPKI: spki, Epoch: epoch}, key
}
func descriptorFixture(t *testing.T) (Descriptor, Anchor, *ecdsa.PrivateKey, time.Time) {
	t.Helper()
	root, key := anchorFixture(t, "offline-root-a", 1)
	online, _ := anchorFixture(t, "publication-key-a", 1)
	now := time.Unix(1800000000, 0)
	d := Descriptor{SchemaVersion: 1, Audience: "syn443-client-bootstrap", RootEpoch: 1, Revision: 1, ServiceID: "service-a", Issuer: "https://identity.example.invalid/realms/test", ClientID: "syn443-android", APIOrigin: "https://api.example.invalid", Roots: map[string]string{online.ID: online.SPKI}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	return d, root, key, now
}

func TestControlPanelOriginIsSignedCanonicalAndOptionalForLegacyDescriptors(t *testing.T) {
	d, root, key, now := descriptorFixture(t)
	legacy, e := json.Marshal(d)
	if e != nil || bytes.Contains(legacy, []byte("controlPanelOrigin")) {
		t.Fatal("legacy descriptor changed", e)
	}
	d.ControlPanelOrigin = "https://control.example.invalid"
	raw, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	verified, _, e := VerifyDescriptor(raw, root, Floor{}, now)
	if e != nil || verified.ControlPanelOrigin != d.ControlPanelOrigin {
		t.Fatal("panel origin not authenticated", e)
	}
	for _, bad := range []string{"http://control.example.invalid", "https://control.example.invalid/", "https://control.example.invalid/path", "https://user@control.example.invalid", "https://control.example.invalid?token=synthetic", "https://control.example.invalid#fragment", "https://CONTROL.example.invalid", "https://control.example.invalid:443", "https://control.example.invalid:0443", "https://control.example.invalid."} {
		d.ControlPanelOrigin = bad
		if _, e := SignDescriptor(d, root, key, now); e == nil {
			t.Fatal("unsafe panel origin signed")
		}
	}
}
func TestServiceDescriptorSignatureFloorAndRootSeparation(t *testing.T) {
	d, root, key, now := descriptorFixture(t)
	raw, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	verified, floor, e := VerifyDescriptor(raw, root, Floor{}, now)
	if e != nil || verified.APIOrigin != d.APIOrigin || floor.Revision != 1 || floor.ServiceID != d.ServiceID {
		t.Fatal("trusted descriptor", e)
	}
	if _, _, e = VerifyDescriptor(raw, root, floor, now); e != nil {
		t.Fatal("unchanged descriptor rejected", e)
	}
	d.Revision = 2
	newer, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	_, next, e := VerifyDescriptor(newer, root, floor, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyDescriptor(raw, root, next, now); !errors.Is(e, ErrRollback) {
		t.Fatal("bootstrap floor rolled back")
	}
	d.Issuer = "https://other.example.invalid/realms/test"
	changed, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyDescriptor(changed, root, next, now); !errors.Is(e, ErrRollback) {
		t.Fatal("same revision replaced trusted service identity")
	}
	if _, _, e = VerifyDescriptor(raw, root, floor, now.Add(2*time.Hour)); e == nil {
		t.Fatal("expired descriptor accepted")
	}
	other, _ := anchorFixture(t, "other-root", 1)
	if _, _, e = VerifyDescriptor(raw, other, Floor{}, now); e == nil {
		t.Fatal("caller-selected key installed")
	}
	d.Revision = 3
	d.Roots = map[string]string{root.ID: root.SPKI}
	if _, e = SignDescriptor(d, root, key, now); e == nil {
		t.Fatal("offline and online signing roots reused")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", verified, verified), "api.example.invalid") {
		t.Fatal("bootstrap metadata logged")
	}
}

func TestRootRotationRequiresOldAndNewAuthorityAndPersistsFloor(t *testing.T) {
	d, old, oldKey, now := descriptorFixture(t)
	next, newKey := anchorFixture(t, "offline-root-b", 2)
	transition := Transition{SchemaVersion: 1, Audience: "syn443-root-transition", From: old.ID, To: next.ID, SPKI: next.SPKI, Epoch: 2, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	rotation, e := SignRotation(transition, old, oldKey, newKey, now)
	if e != nil {
		t.Fatal(e)
	}
	advanced, e := AdvanceRoot(rotation, old, now)
	if e != nil || advanced.ID != next.ID || advanced.Epoch != 2 || advanced.LastTransition == "" {
		t.Fatal("dual root transition", e)
	}
	if again, e := AdvanceRoot(rotation, advanced, now.Add(2*time.Hour)); e != nil || again != advanced {
		t.Fatal("lost transition acknowledgement", e)
	}
	oldDescriptor, e := SignDescriptor(d, old, oldKey, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyDescriptor(oldDescriptor, advanced, Floor{}, now); e == nil {
		t.Fatal("retired root authorized fresh enrollment")
	}
	d.RootEpoch = 2
	d.Revision = 2
	fresh, e := SignDescriptor(d, advanced, newKey, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyDescriptor(fresh, advanced, Floor{}, now); e != nil {
		t.Fatal("new authority", e)
	}
	for _, bad := range []Rotation{{Previous: rotation.Previous, Next: rotation.Previous}, {Previous: rotation.Next, Next: rotation.Next}, {Previous: rotation.Previous, Next: "invalid"}} {
		if _, e = AdvanceRoot(bad, old, now); e == nil {
			t.Fatal("missing dual authority accepted")
		}
	}
	changed := transition
	changed.Expires--
	different, e := sign(changed, "syn443-root-transition+jws", next, newKey)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = AdvanceRoot(Rotation{rotation.Previous, different}, old, now); e == nil {
		t.Fatal("signatures cover different transitions")
	}
	if _, e = AdvanceRoot(rotation, old, now.Add(2*time.Hour)); e == nil {
		t.Fatal("expired unaccepted transition")
	}
}

func TestDescriptorAndSignedEnvelopeNegativeBoundaries(t *testing.T) {
	d, root, key, now := descriptorFixture(t)
	for _, modify := range []func(*Descriptor){func(d *Descriptor) { d.SchemaVersion = 2 }, func(d *Descriptor) { d.Audience = "other" }, func(d *Descriptor) { d.RootEpoch = 2 }, func(d *Descriptor) { d.Revision = 0 }, func(d *Descriptor) { d.ServiceID = "../bad" }, func(d *Descriptor) { d.ClientID = "" }, func(d *Descriptor) { d.APIOrigin = "http://api.example.invalid" }, func(d *Descriptor) { d.APIOrigin += "/path" }, func(d *Descriptor) { d.Issuer += "/" }, func(d *Descriptor) { d.Roots = map[string]string{} }, func(d *Descriptor) { d.Roots = map[string]string{"bad": "not-a-key"} }, func(d *Descriptor) { d.Expires = now.Unix() }, func(d *Descriptor) { d.Expires = now.Add(31 * 24 * time.Hour).Unix() }, func(d *Descriptor) { d.NotBefore = now.Unix() + 1 }} {
		bad := d
		modify(&bad)
		encoded, e := sign(bad, "syn443-bootstrap+jws", root, key)
		if e != nil {
			continue
		}
		if _, _, e = VerifyDescriptor(encoded, root, Floor{}, now); e == nil {
			t.Fatal("invalid descriptor accepted")
		}
	}
	for _, origin := range []string{"https://user@api.example.invalid", "https://api.example.invalid?x=y", "https://api.example.invalid?", "https://api.example.invalid#x", "https://API.example.invalid", "https://api.example.invalid.", "https://api.example.invalid:443", "https://api.example.invalid:", "https://api.example.invalid:0", "https://api.example.invalid:65536", "https://api.example.invalid/a/../b", "https://api.example.invalid/a//b", "https://api.example.invalid/%61"} {
		if secureURL(origin, false) {
			t.Fatal("noncanonical/untrusted origin accepted")
		}
	}
	raw, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(raw, ".")
	for _, bad := range []string{"", raw + ".", strings.Repeat("x", MaxManifest+1), "bad." + parts[1] + "." + parts[2], parts[0] + "." + parts[1] + ".AA", parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 64)), raw + "="} {
		if _, _, e = VerifyDescriptor(bad, root, Floor{}, now); e == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
	wrongType, e := sign(d, "syn443-policy+jws", root, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyDescriptor(wrongType, root, Floor{}, now); e == nil {
		t.Fatal("signature type confused")
	}
	for _, floor := range []Floor{{Revision: -1}, {Revision: 1, ServiceID: d.ServiceID, Hash: "invalid"}, {Revision: 0, Hash: identity.Hash([]byte("synthetic"))}, {ServiceID: "other-service", Revision: 1, Hash: identity.Hash([]byte("synthetic"))}} {
		if _, _, e = VerifyDescriptor(raw, root, floor, now); !errors.Is(e, ErrRollback) {
			t.Fatal("invalid persisted floor accepted")
		}
	}
	if _, e := Public(nil); e == nil {
		t.Fatal("nil publication key")
	}
	if _, e := public(base64.StdEncoding.EncodeToString([]byte("not SPKI"))); e == nil {
		t.Fatal("invalid SPKI")
	}
}

func rawEnvelope(t *testing.T, key *ecdsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}
func TestSignedButUnsupportedHeadersAndPayloadsDoNotGainTrust(t *testing.T) {
	d, root, key, now := descriptorFixture(t)
	encoded, _ := json.Marshal(d)
	payload, _ := policy.Canonical(encoded)
	for _, header := range []string{`{"alg":"none","kid":"offline-root-a","typ":"syn443-bootstrap+jws"}`, `{"alg":"ES256","kid":"offline-root-a","typ":"syn443-bootstrap+jws","jku":"https://untrusted.example.invalid"}`, `{"alg":"ES256","kid":"offline-root-a","typ":"syn443-bootstrap+jws","jwk":{}}`, `{"alg":"ES256","alg":"ES256","kid":"offline-root-a","typ":"syn443-bootstrap+jws"}`, ` {"alg":"ES256","kid":"offline-root-a","typ":"syn443-bootstrap+jws"}`} {
		raw := rawEnvelope(t, key, []byte(header), payload)
		if _, _, e := VerifyDescriptor(raw, root, Floor{}, now); e == nil {
			t.Fatal("unsupported signed header accepted")
		}
	}
	header, _ := policy.Canonical([]byte(`{"alg":"ES256","kid":"offline-root-a","typ":"syn443-bootstrap+jws"}`))
	for _, bad := range [][]byte{append([]byte(`{"schemaVersion":1,`), payload[1:]...), append(payload, []byte(` {}`)...), []byte(`{"unknown":true}`), append([]byte(" "), payload...)} {
		raw := rawEnvelope(t, key, header, bad)
		if _, _, e := VerifyDescriptor(raw, root, Floor{}, now); e == nil {
			t.Fatal("signed invalid payload accepted")
		}
	}
	badAnchor := root
	badAnchor.SPKI = "invalid"
	if _, e := SignDescriptor(d, badAnchor, key, now); e == nil {
		t.Fatal("corrupt root used for signing")
	}
	_, wrong := anchorFixture(t, "other", 1)
	if _, e := SignDescriptor(d, root, wrong, now); e == nil {
		t.Fatal("wrong private root used")
	}
}
