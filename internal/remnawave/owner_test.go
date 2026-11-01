package remnawave

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnerConfigurationTrustAndFileBoundaries(t *testing.T) {
	_, server, _ := fixture(t, nil)
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	cert := filepath.Join(dir, "ca.pem")
	config := filepath.Join(dir, "resource.json")
	write := func(path string, raw []byte, mode os.FileMode) {
		t.Helper()
		if e := os.WriteFile(path, raw, mode); e != nil {
			t.Fatal("fixture write failed")
		}
	}
	write(secret, []byte(fixtureToken+"\n"), 0600)
	write(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0644)
	base := ownerConfig{FixtureLoopback: true, ResourceID: "panel-a", ProviderType: "panel.remnawave", APIVersion: "3.4", Endpoint: server.URL, Enabled: true, CredentialFile: secret, CertificateAuthorityFile: cert, AllowedNetworks: []string{"127.0.0.1/32"}}
	put := func(o ownerConfig) {
		t.Helper()
		raw, e := json.Marshal(o)
		if e != nil {
			t.Fatal("fixture encode failed")
		}
		write(config, raw, 0600)
	}
	put(base)
	c, e := NewFromOwnerFile(config)
	if e != nil {
		t.Fatal("valid owner config rejected")
	}
	c.now = func() time.Time { return fixedTime }
	if _, e = c.ReadAssignment(context.Background(), c.Binding("42")); e != nil {
		t.Fatal("verified owner transport failed")
	}
	c.Close()
	for _, tc := range []struct {
		name   string
		change func(*ownerConfig)
	}{
		{"relative-secret", func(o *ownerConfig) { o.CredentialFile = "relative" }},
		{"missing-secret", func(o *ownerConfig) { o.CredentialFile = filepath.Join(dir, "missing") }},
		{"relative-ca", func(o *ownerConfig) { o.CertificateAuthorityFile = "relative" }},
		{"invalid-ca", func(o *ownerConfig) { o.CertificateAuthorityFile = secret }},
		{"broad-network", func(o *ownerConfig) { o.AllowedNetworks = []string{"10.0.0.0/8"} }},
		{"broad-ipv6", func(o *ownerConfig) { o.AllowedNetworks = []string{"fc00::/7"} }},
		{"bad-network", func(o *ownerConfig) { o.AllowedNetworks = []string{"invalid"} }},
		{"too-many-networks", func(o *ownerConfig) { o.AllowedNetworks = make([]string, 17) }},
		{"unsupported-version", func(o *ownerConfig) { o.APIVersion = "2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.change(&o)
			put(o)
			x, err := NewFromOwnerFile(config)
			if err == nil {
				x.Close()
				t.Fatal("invalid owner config accepted")
			}
			if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), fixtureToken) {
				t.Fatal("owner failure leaked private input")
			}
		})
	}
	for _, raw := range []string{`{"resourceId":"a","resourceId":"b"}`, `{"unknown":"value"}`, `{`, strings.Repeat("x", 16385)} {
		write(config, []byte(raw), 0600)
		if x, e := NewFromOwnerFile(config); e == nil {
			x.Close()
			t.Fatal("malformed owner file accepted")
		}
	}
	put(base)
	if e := os.Chmod(secret, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := NewFromOwnerFile(config); e == nil {
		t.Fatal("readable secret accepted")
	}
	if e := os.Chmod(secret, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, 0777); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(dir, 0700)
	if _, e := NewFromOwnerFile(config); e == nil {
		t.Fatal("writable secret parent accepted")
	}
}

func TestPrivateFileRejectsSpecialAndChangedInputs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "data")
	if e := os.WriteFile(file, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(file, link); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		path string
		max  int64
	}{{"relative", 4}, {dir, 4}, {link, 4}, {file, 3}, {filepath.Join(dir, "missing"), 4}} {
		if _, e := privateFile(tc.path, tc.max, true); e == nil {
			t.Fatal("unsafe private file accepted")
		}
	}
	if e := os.WriteFile(file, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := privateFile(file, 4, true); e == nil {
		t.Fatal("empty private file accepted")
	}
}
