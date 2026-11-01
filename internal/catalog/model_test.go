package catalog

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func sourceExample(now time.Time) Source {
	return Source{ID: "source-a", Owner: "user-a", Name: "Synthetic source", Mode: "manual", Format: "uri", Enabled: true, ValidUntil: now.Add(24 * time.Hour).Unix(), RefreshSeconds: 3600, MaxStaleSeconds: 86400, NetworkModes: []string{"wifi"}}
}
func TestSourceModelAndSecretOperations(t *testing.T) {
	now := time.Now()
	base := sourceExample(now)
	if base.Validate(now) != nil {
		t.Fatal("valid source")
	}
	for _, change := range []func(*Source){func(s *Source) { s.ID = "bad/id" }, func(s *Source) { s.Owner = "" }, func(s *Source) { s.Mode = "unknown" }, func(s *Source) { s.Format = "unknown" }, func(s *Source) { s.RefreshSeconds = 59 }, func(s *Source) { s.MaxStaleSeconds = 604801 }, func(s *Source) { s.ValidUntil = now.Unix() }, func(s *Source) { s.NetworkModes = []string{"wifi", "wifi"} }, func(s *Source) { s.NetworkModes = []string{"unrecognized"} }, func(s *Source) { s.ResourceID = "forbidden" }} {
		s := base
		change(&s)
		if s.Validate(now) == nil {
			t.Fatal("invalid source accepted")
		}
	}
	r := base
	r.Mode = "resource"
	r.ResourceID = "panel-a"
	r.ExternalUserID = "42"
	if r.Validate(now) != nil {
		t.Fatal("resource binding")
	}
	old := []byte(`"synthetic-protected-value"`)
	kept, e := (SecretPatch{Operation: "keep"}).Apply(old)
	if e != nil || !bytes.Equal(kept, old) {
		t.Fatal("keep")
	}
	kept[0] = 'x'
	if old[0] == 'x' {
		t.Fatal("keep aliased mutable input")
	}
	if v, e := (SecretPatch{Operation: "delete"}).Apply(old); e != nil || v != nil {
		t.Fatal("delete")
	}
	if v, e := (SecretPatch{Operation: "replace", Value: json.RawMessage(`"new-synthetic-value"`)}).Apply(old); e != nil || !bytes.Contains(v, []byte("new-synthetic-value")) {
		t.Fatal("replace")
	}
	for _, patch := range []SecretPatch{{Operation: "unknown"}, {Operation: "keep", Value: old}, {Operation: "delete", Value: old}, {Operation: "replace", Value: json.RawMessage(`null`)}, {Operation: "replace", Value: json.RawMessage(`{"authorization":"***"}`)}, {Operation: "replace", Value: json.RawMessage(`["[redacted]"]`)}, {Operation: "replace", Value: json.RawMessage(`{"v":1,"v":2}`)}} {
		if _, e := patch.Apply(old); e == nil {
			t.Fatal("ambiguous mask/mutation")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", SecretPatch{Operation: "replace", Value: old}, base), "synthetic-protected-value") {
		t.Fatal("sensitive formatter")
	}
}
func TestProtectedProfilesMustMatchNativeIdentity(t *testing.T) {
	profiles, e := subscriptions.Import("source-a", bytes.Repeat([]byte{3}, 32), "uri", []byte("http://proxy.example.invalid:443"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = protectedProfiles(profiles); e != nil {
		t.Fatal(e)
	}
	profiles[0].ID = "forged-id"
	if _, e = protectedProfiles(profiles); e == nil {
		t.Fatal("profile/native identity mismatch")
	}
	if _, e = protectedProfiles(nil); e == nil {
		t.Fatal("empty working snapshot")
	}
}
func TestFetchCredentialsAreClosedAndDoNotPermitMasksOrKeyFiles(t *testing.T) {
	raw := []byte(`{"url":"https://proxy.example.invalid/subscription","headers":{"Authorization":"Bearer synthetic-only"}}`)
	c, e := ReadFetchCredential(raw)
	if e != nil || c.URL == "" {
		t.Fatal("valid fetch credential")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c, c), "synthetic-only") {
		t.Fatal("credential formatter")
	}
	for _, raw := range []string{`{}`, `{"url":"http://proxy.example.invalid"}`, `{"url":"https://proxy.example.invalid","fixture":true}`, `{"url":"https://proxy.example.invalid","headers":{"Host":"wrong.example.invalid"}}`, `{"url":"https://proxy.example.invalid","rootCa":"not-a-certificate"}`, `{"url":"https://proxy.example.invalid","allowedNetworks":["not-a-network"]}`} {
		if _, e := ReadFetchCredential([]byte(raw)); e == nil {
			t.Fatal("unsafe credential accepted")
		}
	}
}

func TestProtectedRecordDomainsAndHashSeparation(t *testing.T) {
	s, e := NewStore(&sql.DB{}, bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte("synthetic-sensitive-record")
	encrypted, e := s.seal(raw, "source-a/1")
	if e != nil || bytes.Contains(encrypted, raw) {
		t.Fatal("protected storage")
	}
	plain, e := s.open(encrypted, "source-a/1")
	if e != nil || !bytes.Equal(plain, raw) {
		t.Fatal("protected readback")
	}
	if _, e = s.open(encrypted, "source-b/1"); e == nil {
		t.Fatal("AAD crossed source domain")
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, e = s.open(encrypted, "source-a/1"); e == nil {
		t.Fatal("damaged ciphertext")
	}
	if _, e = s.open(nil, "source-a/1"); e == nil {
		t.Fatal("missing ciphertext became empty state")
	}
	other, e := NewStore(&sql.DB{}, bytes.Repeat([]byte{8}, 32))
	if e != nil || s.hash(raw) == other.hash(raw) {
		t.Fatal("ordinary hashes became credential guessing oracle")
	}
	if _, e = NewStore(nil, bytes.Repeat([]byte{7}, 32)); e == nil {
		t.Fatal("missing database")
	}
	if _, e = NewStore(&sql.DB{}, nil); e == nil {
		t.Fatal("missing storage key")
	}
}
