package overlay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
)

func fixtureAddress() Address {
	return Address{"service-a", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "device-a", "personal-overlay", "netbird", "cloud-resource", "provider-network", 1, "https://api.example.invalid"}
}
func TestSharedNamespaceVectorsAndEveryAuthorityBoundary(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/overlay-namespace-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var values struct {
		SchemaVersion int `json:"schemaVersion"`
		Cases         []struct {
			Name     string  `json:"name"`
			Address  Address `json:"address"`
			Expected string  `json:"expected"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &values) != nil || values.SchemaVersion != 1 || len(values.Cases) != 7 {
		t.Fatal("namespace wire fixture")
	}
	for _, item := range values.Cases {
		got, e := Namespace(item.Address)
		if e != nil || got != item.Expected {
			t.Fatal("cross-platform namespace differs", item.Name, e)
		}
	}
	a := fixtureAddress()
	initial, e := Namespace(a)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(initial, "managed-netbird/") || strings.HasPrefix(initial, "netbird/") {
		t.Fatal("managed SDK state aliases operator root")
	}
	for _, change := range []func(*Address){func(a *Address) { a.ServiceID = "service-b" }, func(a *Address) {
		a.OwnerTag = base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	}, func(a *Address) { a.DeviceID = "device-b" }, func(a *Address) { a.OverlayID = "overlay-b" }, func(a *Address) { a.ResourceID = "resource-b" }, func(a *Address) { a.NetworkID = "network-b" }, func(a *Address) { a.IdentityEpoch = 2 }, func(a *Address) { a.ManagementURL = "https://other.example.invalid" }} {
		b := a
		change(&b)
		got, e := Namespace(b)
		if e != nil || got == initial {
			t.Fatal("authority context reused SDK identity", e)
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", a, a), a.OwnerTag) {
		t.Fatal("identity diagnostics leak account binding")
	}
}
func TestMalformedIdentityAddressAndManagementURLsFailClosed(t *testing.T) {
	a := fixtureAddress()
	for _, change := range []func(*Address){func(a *Address) { a.ServiceID = "../outside" }, func(a *Address) { a.OverlayID = "" }, func(a *Address) { a.ResourceID = strings.Repeat("x", 65) }, func(a *Address) { a.NetworkID = "provider/network" }, func(a *Address) { a.DeviceID = "short" }, func(a *Address) { a.OwnerTag = "bad" }, func(a *Address) { a.OwnerTag = strings.Repeat("_", 43) }, func(a *Address) { a.Provider = "tailscale" }, func(a *Address) { a.Provider = "zerotier" }, func(a *Address) { a.IdentityEpoch = 0 }, func(a *Address) { a.IdentityEpoch = 9007199254740992 }, func(a *Address) { a.ManagementURL = "http://api.example.invalid" }} {
		b := a
		change(&b)
		if _, e := Namespace(b); e == nil {
			t.Fatal("invalid identity admitted")
		}
	}
	for _, raw := range []string{"", "http://api.example.invalid", "https://api.example.invalid/path", "https://api.example.invalid/?q=1", "https://api.example.invalid?", "https://api.example.invalid/#fragment", "https://api.example.invalid#", "https://api.example.invalid:0", "https://api.example.invalid:65536", "https://api.example.invalid:", "https://api.example.invalid//", "https://api.example.invalid/%2F", "https://api.example.invalid/../", "https://api.example.invalid\n", "https://[fe80::1%25wlan0]/", "https://api.example.invalid/" + strings.Repeat("x", 2048), "https://api.example.invalid/%zz"} {
		if _, e := ManagementOrigin(raw); e == nil {
			t.Fatal("ambiguous management origin admitted")
		}
	}
	credential := (&url.URL{Scheme: "https", Host: "api.example.invalid", User: url.UserPassword("fixture-user", "fixture-password")}).String()
	if _, e := ManagementOrigin(credential); e == nil {
		t.Fatal("credential URI accepted")
	}
	for raw, want := range map[string]string{"https://API.EXAMPLE.INVALID:443/": "https://api.example.invalid", "https://api.example.invalid:8443/": "https://api.example.invalid:8443", "https://[::1]:443/": "https://[::1]", "https://[::1]:8443": "https://[::1]:8443"} {
		if got, e := ManagementOrigin(raw); e != nil || got != want {
			t.Fatal("origin canonicalization", e)
		}
	}
}
