//go:build postgres

package invitation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestSQLIssueLostReplyAndConflictingOperations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, _ := random()
	payload, _ := json.Marshal(IssueRequest{f.owner, f.grant, f.now.Unix() + 600, "service-a", 1})
	raw, _ := json.Marshal(Envelope{1, "invite.issue", id, payload})
	call := func(raw []byte) (any, error) {
		return f.admin.Dispatch(ctx, token, signed(t, f.key, f.admin.ControlOrigin+"/v1/control/action", token, "", raw, f.now), raw, f.now)
	}
	first, e := call(raw)
	if e != nil {
		t.Fatal(e)
	}
	again, e := call(raw)
	if e != nil || first.(Issued) != again.(Issued) {
		t.Fatal("lost issue reply created another code", e)
	}
	changed, _ := json.Marshal(IssueRequest{f.owner, f.grant, f.now.Unix() + 599, "service-a", 1})
	conflict, _ := json.Marshal(Envelope{1, "invite.issue", id, changed})
	if _, e = call(conflict); !errors.Is(e, ErrConflict) {
		t.Fatal("idempotency key changed issued scope", e)
	}
	f.claim(t, first.(Issued))
	if _, e = call(raw); !errors.Is(e, ErrConflict) {
		t.Fatal("consumed code re-exported", e)
	}
	if _, e = f.adminCall(t, "invite.issue", IssueRequest{f.owner, identity.Hash([]byte("wrong-grant")), f.now.Unix() + 600, "service-a", 1}); !errors.Is(e, ErrDenied) {
		t.Fatal("wrong grant issued")
	}
	if _, e = f.adminCall(t, "invite.issue", IssueRequest{f.owner, f.grant, f.now.Unix() + 601, "service-a", 1}); !errors.Is(e, ErrDenied) {
		t.Fatal("overlong invite lifetime")
	}
	if _, e = f.adminCall(t, "invite.issue", IssueRequest{f.owner, f.grant, f.now.Unix() + 600, "other-service", 1}); !errors.Is(e, ErrDenied) {
		t.Fatal("foreign service issued")
	}
	if _, e = f.adminCall(t, "invite.approve", Approval{ID: first.(Issued).ID, Version: 1, Thumbprint: identity.Hash([]byte("other")), PairCode: "123456"}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale key approval")
	}
}

func TestSQLClaimSeatQuotaKeySubstitutionAndStatusBoundaries(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		f.claim(t, f.issue(t))
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		f.phone = key
	}
	third := f.issue(t)
	invite, e := bootstrap.AuthenticateLink(third.Link, f.root, bootstrap.Floor{}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := random()
	raw, _ := json.Marshal(Claim{id, invite.Code, identity.PublicJWK(&f.phone.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}})
	proof := signed(t, f.phone, "https://api.example.invalid/v1/invitations/claim", "", "", raw, f.now)
	if _, e = f.device.Claim(ctx, "service-a", "https://api.example.invalid", raw, proof, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("pending reservations bypassed account device limit", e)
	}
	if _, e = f.device.Claim(ctx, "other-service", "https://api.example.invalid", raw, proof, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("cross-service code accepted")
	}
	var firstID, nonce string
	if e = fixtureOwner.QueryRow(`SELECT id,claim_nonce FROM managed_invitations WHERE claim_jkt IS NOT NULL ORDER BY created_at,id LIMIT 1`).Scan(&firstID, &nonce); e != nil {
		t.Fatal(e)
	}
	status, _ := json.Marshal(DeviceRequest{firstID, id})
	proof = signed(t, f.phone, "https://api.example.invalid/v1/invitations/status", "", nonce, status, f.now)
	if _, e = f.device.Status(ctx, "https://api.example.invalid", status, proof, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("other key read claim status")
	}
	if _, e = f.device.Claim(ctx, "service-a", "https://api.example.invalid", []byte(`{"unknown":true}`), "invalid", f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("unknown claim fields")
	}
}

func TestSQLInvitationDatabaseOutageNeverAcknowledgesDurableWork(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	closed, e := sql.Open("pgx", os.Getenv("SYN443_TEST_DATABASE"))
	if e != nil {
		t.Fatal(e)
	}
	closed.Close()
	dead, e := NewStore(closed, bytes.Repeat([]byte{37}, 32))
	if e != nil {
		t.Fatal(e)
	}
	issued := f.issue(t)
	invitation, e := bootstrap.AuthenticateLink(issued.Link, f.root, bootstrap.Floor{}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := random()
	claim, _ := json.Marshal(Claim{id, invitation.Code, identity.PublicJWK(&f.phone.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}})
	status, _ := json.Marshal(DeviceRequest{issued.ID, id})
	for _, call := range []func() error{
		func() error {
			_, e := dead.Claim(ctx, "service-a", "https://api.example.invalid", claim, signed(t, f.phone, "https://api.example.invalid/v1/invitations/claim", "", "", claim, f.now), f.now)
			return e
		},
		func() error {
			_, e := dead.Status(ctx, "https://api.example.invalid", status, "invalid", f.now)
			return e
		},
		func() error { _, e := dead.Ready(ctx, issued.ID, f.verification(), f.now); return e },
	} {
		if e := call(); !errors.Is(e, ErrUnavailable) {
			t.Fatal("unavailable database acknowledged invitation operation", e)
		}
	}
	f.admin.Store = dead
	for _, test := range []struct {
		action  string
		payload any
	}{{"invite.issue", IssueRequest{f.owner, f.grant, f.now.Unix() + 600, "service-a", 1}}, {"invite.approve", Approval{issued.ID, 1, identity.Hash([]byte("phone")), "123456"}}, {"invite.get", Mutation{ID: issued.ID}}} {
		if _, e := f.adminCall(t, test.action, test.payload); !errors.Is(e, ErrUnavailable) {
			t.Fatal("unavailable admin write acknowledged", e)
		}
	}
	if e := dead.RuntimeRole(ctx, "syn443_control_api"); !errors.Is(e, ErrDenied) {
		t.Fatal("unverified database role")
	}
}

func TestSQLInvitationRuntimeConfigClosedTrustAndOrigins(t *testing.T) {
	f := newFixture(t)
	c := Config{EncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{37}, 32)), ControlOrigin: f.admin.ControlOrigin, IdentityOrigin: "https://api.example.invalid", Issuer: f.v.p.Issuer, Audience: "syn443-control-api", ClientIDs: []string{"syn443-control-mobile"}, AssuranceACR: f.admin.AssuranceACR, Anchor: f.root, Descriptor: f.admin.Descriptor}
	raw, _ := json.Marshal(c)
	parsed, e := ParseConfig(raw, f.now)
	if e != nil || len(parsed.Key()) != 32 {
		t.Fatal("runtime config", e)
	}
	path := filepath.Join(t.TempDir(), "invitation.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadConfig(path, f.now); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadConfig(path+"-absent", f.now); e == nil {
		t.Fatal("missing owner file")
	}
	for _, change := range []func(*Config){func(c *Config) { c.ControlOrigin = "https://control.example.invalid/path" }, func(c *Config) { c.IdentityOrigin = "https://other.example.invalid" }, func(c *Config) { c.ClientIDs = []string{"syn443-android"} }, func(c *Config) { c.ClientIDs = []string{"syn443-control-web", "syn443-control-web"} }, func(c *Config) { c.Audience = "syn443-device" }, func(c *Config) { c.EncryptionKey = "invalid" }, func(c *Config) { c.Anchor.Epoch = 2 }, func(c *Config) { c.AssuranceACR = "" }} {
		changed := c
		change(&changed)
		value, _ := json.Marshal(changed)
		if _, e = ParseConfig(value, f.now); !errors.Is(e, ErrDenied) {
			t.Fatal("unsafe runtime config accepted", e)
		}
	}
	if _, e = ParseConfig(append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), f.now); e == nil {
		t.Fatal("unknown config field")
	}
	group := verifierGroup{f.v}
	if _, e = group.Verify(context.Background(), token, f.now); e != nil {
		t.Fatal(e)
	}
	if _, e = (verifierGroup{}).Verify(context.Background(), token, f.now); e == nil {
		t.Fatal("empty verifier group")
	}
	if _, e = (Config{Issuer: "not-an-issuer", ClientIDs: []string{"syn443-control-mobile"}}).Verification(context.Background()); e == nil {
		t.Fatal("untrusted issuer configured")
	}
	if _, e = ParseConfig(raw, f.now.Add(4000*time.Second)); e == nil {
		t.Fatal("expired descriptor at startup")
	}
}
