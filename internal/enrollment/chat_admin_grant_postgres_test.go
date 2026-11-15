//go:build postgres

package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func webAdminGrantFixture(f *fixture) (Config, ChatWebAdminGrant) {
	c := chatIssuerConfig()
	c.Issuer = f.grant.Issuer
	c.ChatWebIssuer = "https://id.example.invalid/realms/operators"
	on := true
	return c, ChatWebAdminGrant{Issuer: c.ChatWebIssuer, Subject: "synthetic-web-admin", Enabled: &on, Until: f.now.Add(time.Hour).Unix()}
}

func TestWebOnlyChatAdminCreateReplayWithdrawAndDeviceDenial(t *testing.T) {
	f, user := chatSetup(t)
	id := chatSelf(t, f, user)
	c, g := webAdminGrantFixture(f)
	ctx := context.Background()
	hash, e := AuthorizeChatWebAdmin(ctx, fixtureOwner, c, g, f.now)
	if e != nil || hash != g.Hash() {
		t.Fatal("web-only grant", e)
	}
	admin := chatClient{key: key(t), owner: Owner(g.Issuer, g.Subject)}
	thumb, _ := identity.PublicJWK(&admin.key.PublicKey).Thumbprint()
	principal := identity.Principal{Issuer: g.Issuer, Subject: g.Subject, Thumbprint: thumb}
	token := random()
	f.api.ChatVerifier = &verifier{principals: map[string]identity.Principal{token: principal}}
	r := f.call(t, admin.key, "POST", "/v1/admin/chat/inbox", token, "", []byte(`{}`))
	expect(t, r, 401)
	nonce := r.Header().Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("missing challenge")
	}
	expect(t, f.call(t, admin.key, "POST", "/v1/admin/chat/inbox", token, nonce, []byte(`{}`)), 200)
	raw, _ := json.Marshal(map[string]any{"conversation": id})
	expect(t, f.call(t, admin.key, "POST", "/v1/admin/chat/messages", token, nonce, raw), 200)
	// Even an otherwise accepted OIDC identity cannot create a VPN device.
	enrollToken := random()
	f.v.mu.Lock()
	f.v.principals[enrollToken] = principal
	f.v.mu.Unlock()
	body, _ := json.Marshal(Request{random(), identity.PublicJWK(&admin.key.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}})
	r = f.call(t, admin.key, "POST", "/v1/devices/enroll", enrollToken, "", body)
	if r.Code == 401 {
		challenge := r.Header().Get("DPoP-Nonce")
		if challenge == "" {
			t.Fatal("invalid denial challenge")
		}
		r = f.call(t, admin.key, "POST", "/v1/devices/enroll", enrollToken, challenge, body)
	}
	expect(t, r, 403)
	var limit, devices int
	if e = fixtureOwner.QueryRow(`SELECT device_limit,(SELECT count(*) FROM identity_devices WHERE owner=$1) FROM identity_accounts WHERE owner=$1`, admin.owner).Scan(&limit, &devices); e != nil || limit != 0 || devices != 0 {
		t.Fatal("web account acquired device authority", e)
	}
	if _, e = AuthorizeChatWebAdmin(ctx, fixtureOwner, c, g, f.now); e != nil {
		t.Fatal("lost-reply replay", e)
	}
	next := g
	next.Until += 3600
	next.ExpectedGrantHash = hash
	hash, e = AuthorizeChatWebAdmin(ctx, fixtureOwner, c, next, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = AuthorizeChatWebAdmin(ctx, fixtureOwner, c, next, f.now); e != nil {
		t.Fatal("updated lost-reply replay", e)
	}
	off := false
	withdraw := next
	withdraw.Enabled = &off
	withdraw.ExpectedGrantHash = hash
	if _, e = AuthorizeChatWebAdmin(ctx, fixtureOwner, c, withdraw, f.now); e != nil {
		t.Fatal(e)
	}
	expect(t, f.call(t, admin.key, "POST", "/v1/admin/chat/inbox", token, nonce, []byte(`{}`)), 403)
	for _, old := range []ChatWebAdminGrant{g, next} {
		if _, e = AuthorizeChatWebAdmin(ctx, fixtureOwner, c, old, f.now); !errors.Is(e, ErrConflict) {
			t.Fatal("stale grant restored withdrawn authority", e)
		}
	}
	var audits int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_chat_admin_audit WHERE owner=$1`, admin.owner).Scan(&audits); e != nil || audits != 3 {
		t.Fatal("grant audit or replay count", e)
	}
	chatCall(t, f, user, "messages", map[string]any{"conversation": id}, 200)
}

func TestWebOnlyAdminMigrationConflictsAndAuditFailureAreAtomic(t *testing.T) {
	f := newFixture(t, 2)
	c, g := webAdminGrantFixture(f)
	ctx := context.Background()
	// Exercise the actual old constraint migration, not only a new database.
	if _, e := fixtureOwner.Exec(`ALTER TABLE identity_accounts DROP CONSTRAINT identity_accounts_device_limit_check, ADD CONSTRAINT identity_accounts_device_limit_check CHECK(device_limit BETWEEN 1 AND 16)`); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(Schema); e != nil {
		t.Fatal("original schema migration", e)
	}
	old := g
	old.Issuer = f.grant.Issuer
	old.Subject = f.grant.Subject
	cfg := c
	cfg.ChatWebIssuer = ""
	if _, e := AuthorizeChatWebAdmin(ctx, fixtureOwner, cfg, old, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("existing VPN account replaced", e)
	}
	for _, db := range []*Store{f.store, f.worker} {
		if _, e := AuthorizeChatWebAdmin(ctx, db.DB, c, g, f.now); e == nil {
			t.Fatal("runtime role granted admin")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := AuthorizeChatWebAdmin(cancelled, fixtureOwner, c, g, f.now); e == nil {
		t.Fatal("cancelled grant")
	}
	if _, e := fixtureOwner.Exec(`CREATE FUNCTION fixture_reject_chat_admin_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END; $$; CREATE TRIGGER fixture_reject_chat_admin_audit BEFORE INSERT ON identity_chat_admin_audit FOR EACH ROW EXECUTE FUNCTION fixture_reject_chat_admin_audit()`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := fixtureOwner.Exec(`DROP TRIGGER IF EXISTS fixture_reject_chat_admin_audit ON identity_chat_admin_audit; DROP FUNCTION IF EXISTS fixture_reject_chat_admin_audit()`); e != nil {
			t.Error(e)
		}
	})
	if _, e := AuthorizeChatWebAdmin(ctx, fixtureOwner, c, g, f.now); e == nil {
		t.Fatal("grant committed without audit")
	}
	var accounts, roles int
	owner := Owner(g.Issuer, g.Subject)
	if e := fixtureOwner.QueryRow(`SELECT (SELECT count(*) FROM identity_accounts WHERE owner=$1),(SELECT count(*) FROM chat_admins WHERE owner=$1)`, owner).Scan(&accounts, &roles); e != nil || accounts != 0 || roles != 0 {
		t.Fatal("partial grant survived audit failure", e)
	}
	var limit int
	var hash string
	if e := fixtureOwner.QueryRow(`SELECT device_limit,grant_hash FROM identity_accounts WHERE owner=$1`, Owner(f.grant.Issuer, f.grant.Subject)).Scan(&limit, &hash); e != nil || limit != 2 || hash != f.grant.Hash() {
		t.Fatal("normal account changed", e)
	}
	bad := f.grant
	bad.DeviceLimit = 0
	if bad.Validate(f.now) == nil {
		t.Fatal("normal device grant accepted zero")
	}
}

func TestWebOnlyAdminConcurrentChangesHaveOneCASWinner(t *testing.T) {
	f := newFixture(t, 1)
	c, g := webAdminGrantFixture(f)
	ctx := context.Background()
	hash, e := AuthorizeChatWebAdmin(ctx, fixtureOwner, c, g, f.now)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 1; i <= 2; i++ {
		next := g
		next.ExpectedGrantHash = hash
		next.Until += int64(i) * 3600
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := AuthorizeChatWebAdmin(ctx, fixtureOwner, c, next, f.now)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent authority updates both committed")
	}
	var audits int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_chat_admin_audit WHERE owner=$1`, Owner(g.Issuer, g.Subject)).Scan(&audits); e != nil || audits != 2 {
		t.Fatal("duplicate authority audit", e)
	}
}
