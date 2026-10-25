package enrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerOnlyBoundedConfigAndKeys(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "operator.json")
	write := func(raw []byte) {
		t.Helper()
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write([]byte(`{"listen":"127.0.0.1:17847","origin":"https://api.example.invalid"}`))
	if _, e := ReadConfig(path); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{[]byte(`{"Listen":"case"}`), []byte(`{"listen":"a","listen":"b"}`), bytes.Repeat([]byte("x"), 65537), {}} {
		write(raw)
		if _, e := ReadConfig(path); e == nil {
			t.Fatal("invalid config")
		}
	}
	write([]byte("{}"))
	os.Chmod(path, 0644)
	if _, e := PrivateFile(path, 32); e == nil {
		t.Fatal("world-readable config")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(root, "symlink")
	if e := os.Symlink(path, link); e == nil {
		if _, e = PrivateFile(link, 32); e == nil {
			t.Fatal("symlink config")
		}
	}
	for _, name := range []string{root, filepath.Join(root, "missing")} {
		if _, e := PrivateFile(name, 32); e == nil {
			t.Fatal("nonfile config")
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	loaded, e := PrivateKey(path)
	if e != nil || loaded.D.Cmp(key.D) != 0 {
		t.Fatal("valid signing key")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(other)
	for _, raw := range [][]byte{[]byte("invalid"), append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), []byte("trailing")...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})} {
		write(raw)
		if _, e = PrivateKey(path); e == nil {
			t.Fatal("invalid signing key")
		}
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	c := Config{Roots: map[string]string{"fixture-root": base64.StdEncoding.EncodeToString(pub)}}
	if _, e = PublicRoots(c); e != nil {
		t.Fatal(e)
	}
	for _, roots := range []map[string]string{nil, {"root": "invalid"}, {"root": base64.StdEncoding.EncodeToString(rsaDER)}} {
		if _, e = PublicRoots(Config{Roots: roots}); e == nil {
			t.Fatal("invalid trust roots")
		}
	}
}
func TestDatabaseTransportAndAEAD(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	c := Config{EncryptionKey: base64.StdEncoding.EncodeToString(key), Database: "postgres://fixture@127.0.0.1:17846/fixture?sslmode=disable"}
	store, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	defer store.DB.Close()
	raw := store.Seal([]byte("synthetic payload"), "purpose-a")
	opened, e := store.Open(raw, "purpose-a")
	if e != nil || string(opened) != "synthetic payload" {
		t.Fatal("AEAD roundtrip")
	}
	if _, e = store.Open(raw, "purpose-b"); e == nil {
		t.Fatal("AEAD purpose swap")
	}
	raw[len(raw)-1] ^= 1
	if _, e = store.Open(raw, "purpose-a"); e == nil {
		t.Fatal("AEAD modification")
	}
	if _, e = store.Open([]byte("short"), "purpose-a"); e == nil {
		t.Fatal("truncated AEAD")
	}
	for _, dsn := range []string{"invalid", "postgres://fixture@database.example.invalid/fixture?sslmode=disable", "postgres://fixture@database.example.invalid/fixture?sslmode=prefer", "postgres://fixture@database.example.invalid/fixture?sslmode=require"} {
		v := c
		v.Database = dsn
		if s, e := OpenStore(v); e == nil {
			s.DB.Close()
			t.Fatal("unverified remote database TLS")
		}
	}
	bad := c
	bad.EncryptionKey = "invalid"
	if _, e = OpenStore(bad); e == nil {
		t.Fatal("invalid encryption key")
	}
	if _, e = NewStore(nil, make([]byte, 16)); e == nil {
		t.Fatal("weak encryption key")
	}
}
