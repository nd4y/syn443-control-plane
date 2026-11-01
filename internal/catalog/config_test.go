package catalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRuntimeConfigPrivateDatabaseAndAdministrativeAudience(t *testing.T) {
	c := RuntimeConfig{Database: "postgres://syn443_control_api@127.0.0.1:17847/postgres?sslmode=disable", EncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{37}, 32)), Audience: "syn443-control-api", ClientIDs: []string{"syn443-control-web", "syn443-control-mobile"}, Issuer: "https://identity.example.invalid/realms/test", AssuranceACR: "urn:syn443:loa:2"}
	raw, _ := json.Marshal(c)
	parsed, e := ParseRuntimeConfig(raw)
	if e != nil || parsed.ValidateAdmin() != nil {
		t.Fatal("runtime document", e)
	}
	store, e := OpenStore(parsed)
	if e != nil {
		t.Fatal(e)
	}
	store.DB.Close()
	for _, database := range []string{"postgres://syn443_control_api@database.example.invalid/postgres?sslmode=disable", "postgres://syn443_control_api@database.example.invalid/postgres?sslmode=prefer", "not a valid DSN"} {
		bad := c
		bad.Database = database
		if s, e := OpenStore(bad); e == nil {
			s.DB.Close()
			t.Fatal("unverified remote SQL transport accepted")
		}
	}
	remote := c
	remote.Database = "postgres://syn443_control_api@database.example.invalid/postgres?sslmode=verify-full"
	store, e = OpenStore(remote)
	if e != nil {
		t.Fatal("verified SQL transport", e)
	}
	store.DB.Close()
	for _, key := range []string{"not-base64", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		bad := c
		bad.EncryptionKey = key
		if s, e := OpenStore(bad); e == nil {
			s.DB.Close()
			t.Fatal("invalid encryption key")
		}
	}
	for _, change := range []func(*RuntimeConfig){func(c *RuntimeConfig) { c.Audience = "syn443-api" }, func(c *RuntimeConfig) { c.ClientIDs = []string{"syn443-android"} }, func(c *RuntimeConfig) { c.ClientIDs = []string{"syn443-control-web", "syn443-control-web"} }, func(c *RuntimeConfig) { c.ClientIDs = nil }, func(c *RuntimeConfig) { c.Issuer = "" }, func(c *RuntimeConfig) { c.AssuranceACR = "" }} {
		bad := c
		change(&bad)
		if bad.ValidateAdmin() == nil {
			t.Fatal("mixed user/admin identity configuration")
		}
	}
	for _, raw := range []string{`{"database":"a","database":"b"}`, `{"database":"a","signingKey":"unauthorized"}`, strings.Repeat(" ", 65537)} {
		if _, e := ParseRuntimeConfig([]byte(raw)); e == nil {
			t.Fatal("invalid runtime shape")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c, c), c.EncryptionKey) {
		t.Fatal("runtime secret formatter")
	}
	if _, e := (VerifierGroup{rejectVerifier{}, rejectVerifier{}}).Verify(context.Background(), "invalid", time.Now()); e == nil {
		t.Fatal("unverified admin token")
	}
}
