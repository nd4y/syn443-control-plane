package bootstrap

import (
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func releaseFixture(t *testing.T) (ReleaseManifest, Anchor, *ecdsa.PrivateKey, time.Time) {
	t.Helper()
	a, k := anchorFixture(t, "release-fixture", 1)
	now := time.Unix(1700001000, 0)
	h := strings.Repeat("a", 64)
	m := ReleaseManifest{SchemaVersion: 1, Audience: "syn443-device-release", Scope: ReleaseScope{"fixture", identity.Hash([]byte("device")), "pilot", h},
		RootEpoch: 1, SecurityEpoch: 2, Revision: 5, RevocationFloor: 3, IssuedAt: now.Unix() - 5, NotBefore: now.Unix(), Expires: now.Unix() + 60,
		APK:           ReleaseArtifact{"io.syn443.android", 20, 29, 37, map[string]string{"arm64-v8a": h}, h, 1024, strings.Repeat("1", 40), h, h},
		Compatibility: ReleaseCompatibility{11, []string{"tun.v1", "wire.v1"}, []string{"graph-v1"}, []string{"policy-v2"}}}
	return m, a, k, now
}

func TestAPKReleaseAuthenticatesRecipientTimesAndJournal(t *testing.T) {
	m, a, key, now := releaseFixture(t)
	wire, e := SignRelease(m, a, key, m.Scope, now)
	if e != nil {
		t.Fatal(e)
	}
	_, floor, e := VerifyRelease(wire, a, m.Scope, ReleaseFloor{}, now, now)
	if e != nil || floor.Revision != 5 {
		t.Fatal("first manifest", e)
	}
	_, replay, e := VerifyRelease(wire, a, m.Scope, floor, now, now)
	if e != nil || replay != floor {
		t.Fatal("exact replay", e)
	}
	again, e := SignRelease(m, a, key, m.Scope, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, same, e := VerifyRelease(again, a, m.Scope, floor, now, now); e != nil || same != floor {
		t.Fatal("same payload was not idempotent")
	}
	reject := func(w string, k Anchor, s ReleaseScope, lo, hi time.Time) {
		t.Helper()
		if _, after, err := VerifyRelease(w, k, s, floor, lo, hi); err == nil || after != floor {
			t.Fatal("invalid release advanced journal")
		}
	}
	other, _ := anchorFixture(t, a.ID, 1)
	reject(wire, other, m.Scope, now, now)
	for _, change := range []func(*ReleaseScope){
		func(s *ReleaseScope) { s.ServiceID = "other" }, func(s *ReleaseScope) { s.DeviceID = identity.Hash([]byte("other")) },
		func(s *ReleaseScope) { s.Channel = "stable" }, func(s *ReleaseScope) { s.SignerSHA256 = strings.Repeat("b", 64) },
	} {
		scope := m.Scope
		change(&scope)
		reject(wire, a, scope, now, now)
	}
	reject(wire, a, m.Scope, now.Add(-time.Second), now)
	reject(wire, a, m.Scope, now, now.Add(time.Minute))
	reject(wire, a, m.Scope, now.Add(time.Second), now)
	wrongType, e := sign(m, "syn443-policy+jws", a, key)
	if e != nil {
		t.Fatal(e)
	}
	reject(wrongType, a, m.Scope, now, now)
	for _, change := range []func(*ReleaseManifest){
		func(n *ReleaseManifest) { n.Revision-- }, func(n *ReleaseManifest) { n.APK.VersionCode++ },
		func(n *ReleaseManifest) { n.Revision++; n.SecurityEpoch-- }, func(n *ReleaseManifest) { n.Revision++; n.RevocationFloor-- },
	} {
		n := m
		change(&n)
		candidate, e := SignRelease(n, a, key, n.Scope, now)
		if e != nil {
			t.Fatal(e)
		}
		reject(candidate, a, m.Scope, now, now)
	}
	m.Revision++
	m.RevocationFloor++
	newer, e := SignRelease(m, a, key, m.Scope, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, advanced, e := VerifyRelease(newer, a, m.Scope, floor, now, now); e != nil || advanced.Revision != 6 || advanced.RevocationFloor != 4 {
		t.Fatal("expected journal advancement")
	}
}

func TestAPKReleaseClosedManifestAndCompatibility(t *testing.T) {
	m, a, k, now := releaseFixture(t)
	configured := InstalledReleaseContext{11, 41, []string{"armeabi-v7a", "arm64-v8a"}, []string{"wire.v1"}, "graph-v1", "policy-v2"}
	if !m.Supports(configured) {
		t.Fatal("supported device rejected")
	}
	for _, change := range []func(*InstalledReleaseContext){
		func(i *InstalledReleaseContext) { i.VersionCode = 10 }, func(i *InstalledReleaseContext) { i.VersionCode = 20 },
		func(i *InstalledReleaseContext) { i.SDK = 28 }, func(i *InstalledReleaseContext) { i.ABIs = []string{"x86"} },
		func(i *InstalledReleaseContext) { i.Evaluator = "old" }, func(i *InstalledReleaseContext) { i.Schema = "future" },
		func(i *InstalledReleaseContext) { i.RequiredEngineCapabilities = []string{"missing"} },
	} {
		candidate := configured
		change(&candidate)
		if m.Supports(candidate) {
			t.Fatal("unsupported installation")
		}
	}
	for _, change := range []func(*ReleaseManifest){
		func(n *ReleaseManifest) { n.APK.Package = "other.package" }, func(n *ReleaseManifest) { n.APK.SHA256 = "wrong" },
		func(n *ReleaseManifest) { n.APK.NativeLibraries = map[string]string{"mystery": n.APK.SHA256} },
		func(n *ReleaseManifest) { n.APK.Bytes = MaxReleaseAPKBytes + 1 }, func(n *ReleaseManifest) { n.Expires = n.IssuedAt + 7*24*3600 + 1 },
		func(n *ReleaseManifest) { n.Compatibility.Evaluators = []string{"z", "a"} },
		func(n *ReleaseManifest) { n.Compatibility.Schemas = []string{"a", "a"} },
	} {
		n := m
		change(&n)
		if _, e := SignRelease(n, a, k, n.Scope, now); e == nil {
			t.Fatal("invalid manifest signed")
		}
	}
	raw, _ := json.Marshal(m)
	var fields map[string]any
	if e := json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	delete(fields, "revocationFloor")
	wire, e := sign(fields, releaseType, a, k)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyRelease(wire, a, m.Scope, ReleaseFloor{}, now, now); e == nil {
		t.Fatal("accepted missing zero-valued member")
	}
}
