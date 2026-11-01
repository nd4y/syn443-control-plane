package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeliveryAuthorizationAndRecipient(t *testing.T) {
	raw, _, now := sample(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle, e := Sign(raw, "test-root", key, "device-example", 1, now)
	if e != nil {
		t.Fatal(e)
	}
	tokenBytes := make([]byte, 32)
	if _, e = rand.Read(tokenBytes); e != nil {
		t.Fatal(e)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	handler := Delivery(Publication{Device: "device-example", Bundle: bundle, BearerHash: sha256.Sum256([]byte(token)), Roots: map[string]*ecdsa.PublicKey{"test-root": &key.PublicKey}, Clock: func() time.Time { return now }})
	for _, test := range []struct {
		method, path, auth, device string
		code                       int
	}{{"GET", "/v1/device/policy", "Bearer " + token, "device-example", 200}, {"GET", "/v1/device/policy", "Bearer " + token, "another-device", 401}, {"GET", "/v1/device/policy", "", "device-example", 401}, {"GET", "/v1/device/policy", "Bearer " + strings.Repeat("x", 257), "device-example", 401}, {"POST", "/v1/device/policy", "Bearer " + token, "device-example", 404}, {"GET", "/v1/device/policy?q=1", "Bearer " + token, "device-example", 404}, {"GET", "/v1/other", "Bearer " + token, "device-example", 404}} {
		request := httptest.NewRequest(test.method, test.path, nil)
		request.Header.Set("Authorization", test.auth)
		request.Header.Set("X-SYN443-Device", test.device)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.code {
			t.Errorf("status=%d expected=%d", response.Code, test.code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable private response")
		}
		if test.code != 200 && (strings.Contains(response.Body.String(), token) || strings.Contains(response.Body.String(), bundle)) {
			t.Fatal("private data echoed")
		}
	}
	bad := Delivery(Publication{Device: "device-example", Bundle: "invalid", BearerHash: sha256.Sum256([]byte(token))})
	request := httptest.NewRequest("GET", "/v1/device/policy", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-SYN443-Device", "device-example")
	response := httptest.NewRecorder()
	bad.ServeHTTP(response, request)
	if response.Code != 503 {
		t.Fatal("invalid publication served")
	}
}
