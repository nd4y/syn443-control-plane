package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runtimeConfiguration(t *testing.T) ConfigurationRuntimeConfig {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return ConfigurationRuntimeConfig{ControlOrigin: "https://control.example.invalid", Issuer: "https://id.example.invalid/realms/test", Audience: "syn443-control-api", ClientIDs: []string{"syn443-control-web", "syn443-control-mobile"}, AssuranceACR: "urn:syn443:loa:2", LayerEncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{91}, 32)), SourceEncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{81}, 32)), Roots: map[string]string{"fixture-root": base64.StdEncoding.EncodeToString(raw)}}
}
func TestConfigurationRuntimeRejectsAuthorityAndSecretCompartmentMixing(t *testing.T) {
	c := runtimeConfiguration(t)
	raw, _ := json.Marshal(c)
	if _, e := ParseConfigurationRuntime(raw); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c, c), c.LayerEncryptionKey) {
		t.Fatal("runtime secret diagnostic")
	}
	for _, change := range []func(*ConfigurationRuntimeConfig){func(c *ConfigurationRuntimeConfig) { c.ControlOrigin = "http://control.example.invalid" }, func(c *ConfigurationRuntimeConfig) { c.ControlOrigin += "/path" }, func(c *ConfigurationRuntimeConfig) { c.ControlOrigin = "https://user@control.example.invalid" }, func(c *ConfigurationRuntimeConfig) { c.Audience = "syn443-device-api" }, func(c *ConfigurationRuntimeConfig) { c.ClientIDs = []string{"syn443-android"} }, func(c *ConfigurationRuntimeConfig) {
		c.ClientIDs = []string{"syn443-control-web", "syn443-control-web"}
	}, func(c *ConfigurationRuntimeConfig) { c.Issuer = "" }, func(c *ConfigurationRuntimeConfig) { c.AssuranceACR = "" }, func(c *ConfigurationRuntimeConfig) { c.LayerEncryptionKey = "bad" }, func(c *ConfigurationRuntimeConfig) { c.SourceEncryptionKey = c.LayerEncryptionKey }, func(c *ConfigurationRuntimeConfig) { c.SourceEncryptionKey += "\n" }, func(c *ConfigurationRuntimeConfig) { c.Roots = map[string]string{} }, func(c *ConfigurationRuntimeConfig) { c.Roots = map[string]string{"fixture-root": "malformed"} }} {
		bad := runtimeConfiguration(t)
		change(&bad)
		raw, _ := json.Marshal(bad)
		if _, e := ParseConfigurationRuntime(raw); e == nil {
			t.Fatal("invalid authority admitted")
		}
	}
	if _, e := ParseConfigurationRuntime(append(raw[:len(raw)-1], []byte(`,"providerToken":"forbidden"}`)...)); e == nil {
		t.Fatal("provider credential field admitted")
	}
	if _, e := ParseConfigurationRuntime(bytes.Repeat([]byte{' '}, 65537)); e == nil {
		t.Fatal("oversized runtime file admitted")
	}
	if _, e := c.LayerStore(context.Background(), nil, true); e == nil {
		t.Fatal("nil database")
	}
	if _, e := c.SourceStore(nil, nil); e == nil {
		t.Fatal("nil source scope")
	}
}
func TestConfigurationRuntimeFileRequiresOwnerOnlyRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX owner permissions tested in Actions")
	}
	c := runtimeConfiguration(t)
	raw, _ := json.Marshal(c)
	p := filepath.Join(t.TempDir(), "runtime.json")
	if e := os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadConfigurationRuntime(p); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadConfigurationRuntime(p); e == nil {
		t.Fatal("world-readable key file admitted")
	}
	if _, e := ReadConfigurationRuntime(p + ".missing"); e == nil {
		t.Fatal("missing file admitted")
	}
}
