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

func TestInstallationProfileSignsOnlyTheSpecifiedPublicService(t *testing.T) {
	makeKey := func() (*ecdsa.PrivateKey, string) {
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
	key, spki := makeKey()
	wrongKey, online := makeKey()
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
	encoded, err := signInstallationProfile(raw, key, now)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	var profile installationProfile
	if err != nil || json.Unmarshal(body, &profile) != nil || profile.SchemaVersion != 1 || profile.Anchor != anchor {
		t.Fatal("wrong installation profile", err)
	}
	signed, _, err := bootstrap.VerifyDescriptor(profile.Service, anchor, bootstrap.Floor{}, now)
	if err != nil || signed.APIOrigin != service.APIOrigin || signed.Issuer != service.Issuer || signed.Roots["publication-a"] != online {
		t.Fatal("wrong signed service", err)
	}
	if _, err = signInstallationProfile(raw, wrongKey, now); err == nil {
		t.Fatal("different root signed the profile")
	}
	changed := anchor
	changed.LastTransition = "synthetic-history"
	if _, err = signInstallationProfile(input(changed, service), key, now); err == nil {
		t.Fatal("unverified rotation history installed")
	}
	service.Expires = now.Unix()
	if _, err = signInstallationProfile(input(anchor, service), key, now); err == nil {
		t.Fatal("expired default service signed")
	}
}
