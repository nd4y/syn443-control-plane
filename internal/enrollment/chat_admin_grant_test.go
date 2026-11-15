package enrollment

import (
	"strings"
	"testing"
	"time"
)

func TestChatWebAdminGrantRejectsMissingForeignAndUnboundedAuthority(t *testing.T) {
	now := time.Unix(1800000000, 0)
	on := true
	c := chatIssuerConfig()
	c.ChatWebIssuer = "https://id.example.invalid/realms/operators"
	g := ChatWebAdminGrant{Issuer: c.ChatWebIssuer, Subject: "synthetic-admin", Enabled: &on, Until: now.Add(time.Hour).Unix()}
	if g.Validate(c, now) != nil || g.Hash() == "" {
		t.Fatal("valid scoped grant rejected")
	}
	missing := g
	missing.Enabled = nil
	if missing.Hash() != "" {
		t.Fatal("missing enable intent produced an authority hash")
	}
	for i := 0; i < 10; i++ {
		v := g
		cfg := c
		switch i {
		case 0:
			v.Enabled = nil
		case 1:
			v.Subject = ""
		case 2:
			v.Subject = "bad\nsubject"
		case 3:
			v.Subject = strings.Repeat("x", 257)
		case 4:
			v.Issuer = c.Issuer
		case 5:
			v.Until = now.Unix()
		case 6:
			v.Until = now.Add(31 * 24 * time.Hour).Unix()
		case 7:
			v.ExpectedGrantHash = "invalid"
		case 8:
			cfg.ChatWebOrigin = ""
		case 9:
			cfg.ChatEnabled = false
		}
		if v.Validate(cfg, now) == nil {
			t.Fatalf("invalid grant accepted: case%d", i)
		}
	}
	for _, issuer := range []string{"http://id.example.invalid/realms/operators", "https://user@id.example.invalid/realms/operators", "https://id.example.invalid/realms/operators?x=1", "https://id.example.invalid/realms/operators#x", "https://id.example.invalid/realms/operators/"} {
		v := g
		cfg := c
		v.Issuer = issuer
		cfg.ChatWebIssuer = issuer
		if v.Validate(cfg, now) == nil {
			t.Fatal("unsafe pinned issuer accepted")
		}
	}
	v := g
	cfg := c
	cfg.ChatWebIssuer = ""
	v.Issuer = cfg.Issuer
	if v.Validate(cfg, now) != nil {
		t.Fatal("default issuer compatibility lost")
	}
	if g.Validate(c, time.Unix(-1, 0)) == nil {
		t.Fatal("invalid operator clock accepted")
	}
}
