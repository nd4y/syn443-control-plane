package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
)

func profileKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(der)
}

func TestInstallationProfileSignsOnlyTheSpecifiedPublicService(t *testing.T) {
	key, spki := profileKey(t)
	wrongKey, online := profileKey(t)
	anchor := bootstrap.Anchor{ID: "installation-root", SPKI: spki, Epoch: 1}
	now := time.Unix(1800000000, 0)
	service := bootstrap.Descriptor{
		SchemaVersion: 1, Audience: "syn443-client-bootstrap", RootEpoch: 1, Revision: 1,
		ServiceID: "service-a", Issuer: "https://identity.example.invalid/realms/test",
		ClientID: "syn443-android", APIOrigin: "https://api.example.invalid",
		Roots: map[string]string{"publication-a": online}, IssuedAt: now.Unix(),
		NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix(),
	}
	input := func(anchor bootstrap.Anchor, service bootstrap.Descriptor) []byte {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"anchor": anchor, "service": service})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := input(anchor, service)
	encoded, err := signInstallationProfile(raw, key, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	var profile installationProfile
	if err != nil || json.Unmarshal(body, &profile) != nil || profile.SchemaVersion != 1 || profile.Anchor != anchor || profile.Upgrade != nil {
		t.Fatal("wrong installation profile", err)
	}
	signed, _, err := bootstrap.VerifyDescriptor(profile.Service, anchor, bootstrap.Floor{}, now)
	if err != nil || signed.APIOrigin != service.APIOrigin || signed.Issuer != service.Issuer || signed.Roots["publication-a"] != online {
		t.Fatal("wrong signed service", err)
	}
	if _, err = signInstallationProfile(raw, wrongKey, nil, now); err == nil {
		t.Fatal("different root signed the profile")
	}
	changed := anchor
	changed.LastTransition = "synthetic-history"
	if _, err = signInstallationProfile(input(changed, service), key, nil, now); err == nil {
		t.Fatal("unverified rotation history installed")
	}
	service.Expires = now.Unix()
	if _, err = signInstallationProfile(input(anchor, service), key, nil, now); err == nil {
		t.Fatal("expired default service signed")
	}
}

func TestInstallationProfileUpgradeRequiresBothExactRootsAndLiveTransition(t *testing.T) {
	oldKey, oldSPKI := profileKey(t)
	newKey, newSPKI := profileKey(t)
	otherKey, online := profileKey(t)
	old := bootstrap.Anchor{ID: "old-root", SPKI: oldSPKI, Epoch: 1}
	next := bootstrap.Anchor{ID: "next-root", SPKI: newSPKI, Epoch: 2}
	now := time.Unix(1800000000, 0)
	descriptor := bootstrap.Descriptor{SchemaVersion: 1, Audience: "syn443-client-bootstrap", RootEpoch: 2, Revision: 2,
		ServiceID: "service-a", Issuer: "https://identity.example.invalid/realms/test", ClientID: "syn443-android",
		APIOrigin: "https://api.example.invalid", Roots: map[string]string{"publication-a": online},
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(2 * time.Hour).Unix()}
	transition := bootstrap.Transition{SchemaVersion: 1, Audience: "syn443-root-transition", From: old.ID, To: next.ID,
		SPKI: next.SPKI, Epoch: next.Epoch, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	input := func(tn bootstrap.Transition) []byte {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"anchor": next, "service": descriptor,
			"upgrade": map[string]any{"previousAnchor": old, "transition": tn}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	encoded, err := signInstallationProfile(input(transition), newKey, oldKey, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	var profile installationProfile
	if err != nil || json.Unmarshal(raw, &profile) != nil || profile.SchemaVersion != 2 || profile.Anchor != next ||
		profile.Upgrade == nil || profile.Upgrade.PreviousAnchor != old {
		t.Fatal("wrong upgrade profile", err)
	}
	advanced, err := bootstrap.AdvanceRoot(profile.Upgrade.Rotation, old, now)
	if err != nil || advanced.LastTransition == "" || advanced.ID != next.ID || advanced.SPKI != next.SPKI || advanced.Epoch != next.Epoch {
		t.Fatal("wrong root transition", err)
	}
	if _, _, err = bootstrap.VerifyDescriptor(profile.Service, advanced, bootstrap.Floor{}, now); err != nil {
		t.Fatal(err)
	}
	for _, previousKey := range []*ecdsa.PrivateKey{nil, otherKey} {
		if _, err = signInstallationProfile(input(transition), newKey, previousKey, now); err == nil {
			t.Fatal("missing or wrong previous root accepted")
		}
	}
	if _, err = signInstallationProfile(input(transition), newKey, oldKey, now.Add(time.Hour)); err == nil {
		t.Fatal("expired transition accepted")
	}
	descriptor.Roots["retired-root"] = oldSPKI
	if _, err = signInstallationProfile(input(transition), newKey, oldKey, now); err == nil {
		t.Fatal("retired offline root reused for online publication")
	}
	delete(descriptor.Roots, "retired-root")
	transition.To = "other-root-id"
	if _, err = signInstallationProfile(input(transition), newKey, oldKey, now); err == nil {
		t.Fatal("transition to a different installation root accepted")
	}
}
