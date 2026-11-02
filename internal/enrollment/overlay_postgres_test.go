//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

type overlayFixture struct {
	*fixture
	client   *ecdsa.PrivateKey
	session  Session
	request  OverlayRequest
	binding  overlay.CredentialBinding
	envelope string
}

func newOverlayFixture(t *testing.T) *overlayFixture {
	t.Helper()
	f := newFixture(t, 2)
	f.api.OverlayServiceID = "fixture-service"
	m := ManagedOverlayReference{"home", "provider-resource", "tenant", 1, random(), 1}
	engine, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"type": "netbird", "tag": "home", "management_url": "https://overlay.example.invalid", "managed": m}}, "route": map[string]any{"final": "home"}})
	sum := sha256.Sum256(engine)
	f.grant.Template.EngineConfigB64 = b64.EncodeToString(engine)
	f.grant.Template.ContentHash = hex.EncodeToString(sum[:])
	f.grant.Template.RequiredCapabilities = append(f.grant.Template.RequiredCapabilities, "overlay.credentials.v1")
	if e := Authorize(context.Background(), fixtureOwner, f.grant, f.now); e != nil {
		t.Fatal(e)
	}
	client := key(t)
	token := f.token(client)
	raw, _ := json.Marshal(Request{random(), identity.PublicJWK(&client.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "overlay.credentials.v1"}})
	result := f.call(t, client, "POST", "/v1/devices/enroll", token, "", raw)
	expect(t, result, 401)
	result = f.call(t, client, "POST", "/v1/devices/enroll", token, result.Header().Get("DPoP-Nonce"), raw)
	expect(t, result, 200)
	var session Session
	if identity.Decode(result.Body.Bytes(), &session, true) != nil {
		t.Fatal("session shape")
	}
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	thumb, _ := identity.PublicJWK(&client.PublicKey).Thumbprint()
	binding := overlay.CredentialBinding{Address: overlay.Address{ServiceID: f.api.OverlayServiceID, OwnerTag: overlayOwner(f.api.OverlayServiceID, f.grant.Issuer, f.grant.Subject), DeviceID: session.DeviceID, OverlayID: m.OverlayID, Provider: "netbird", ResourceID: m.ResourceID, NetworkID: m.NetworkID, IdentityEpoch: m.IdentityEpoch, ManagementURL: "https://overlay.example.invalid"}, KeyThumbprint: thumb, Reference: m.SetupReference, Version: 1, SecurityEpoch: 0, OfflineUntilMs: f.now.Add(time.Hour).UnixMilli()}
	var entropy [16]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		t.Fatal(e)
	}
	secret := hex.EncodeToString(entropy[:])
	secret = secret[:8] + "-" + secret[8:12] + "-" + secret[12:16] + "-" + secret[16:20] + "-" + secret[20:]
	c := overlay.Credential{SchemaVersion: 1, Audience: "syn443-overlay-credential", Address: binding.Address, KeyThumbprint: thumb, Reference: binding.Reference, Version: 1, SecurityEpoch: 0, Kind: "netbird.setup-key", IssuedAtMs: f.now.UnixMilli(), NotBeforeMs: f.now.UnixMilli(), ExpiresMs: f.now.Add(5 * time.Minute).UnixMilli(), Value: secret}
	envelope, e := overlay.SignCredential(c, binding, "fixture-root", f.key, f.now)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := fixturePublisher.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = f.worker.InstallOverlayGrant(context.Background(), tx, Owner(f.grant.Issuer, f.grant.Subject), binding, envelope, f.api.Roots, f.now); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	namespace, _ := overlay.Namespace(binding.Address)
	return &overlayFixture{f, client, session, OverlayRequest{random(), namespace, binding.Reference, 1}, binding, envelope}
}
func (o *overlayFixture) raw() []byte { raw, _ := json.Marshal(o.request); return raw }
func (o *overlayFixture) call(t *testing.T, consume bool) *httptest.ResponseRecorder {
	t.Helper()
	path := "/v1/device/overlay/fetch"
	if consume {
		path = "/v1/device/overlay/consume"
	}
	return o.fixture.call(t, o.client, "POST", path, o.session.AccessToken, o.session.Nonce, o.raw())
}
func (o *overlayFixture) publication(t *testing.T, change func(*policy.Payload)) {
	t.Helper()
	var protected []byte
	var revision int64
	if e := fixtureOwner.QueryRow(`SELECT publication,revision FROM identity_devices WHERE id=$1`, o.session.DeviceID).Scan(&protected, &revision); e != nil {
		t.Fatal(e)
	}
	raw, e := o.store.Open(protected, "publication/v1/"+o.session.DeviceID+"/"+formatInt(revision))
	if e != nil {
		t.Fatal(e)
	}
	p, e := policy.VerifyBound(string(raw), o.api.Roots, o.session.DeviceID, o.binding.KeyThumbprint, o.now)
	if e != nil {
		t.Fatal(e)
	}
	change(&p)
	p.Revision++
	raw, _ = json.Marshal(p)
	envelope, e := policy.Sign(raw, "fixture-root", o.key, o.session.DeviceID, p.Revision, o.now)
	if e != nil {
		t.Fatal(e)
	}
	protected = o.worker.Seal([]byte(envelope), "publication/v1/"+o.session.DeviceID+"/"+formatInt(p.Revision))
	if _, e = fixturePublisher.Exec(`UPDATE identity_devices SET publication=$2,revision=$3 WHERE id=$1`, o.session.DeviceID, protected, p.Revision); e != nil {
		t.Fatal(e)
	}
}
func TestOverlayDeliveryRetryConsumptionAndSeparateRuntimeRoles(t *testing.T) {
	o := newOverlayFixture(t)
	for i := 0; i < 2; i++ {
		r := o.call(t, false)
		expect(t, r, 200)
		var reply OverlayReply
		if json.Unmarshal(r.Body.Bytes(), &reply) != nil || reply.Envelope != o.envelope || reply.Consumed {
			t.Fatal("lost response retry changed envelope")
		}
		if r.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable credential")
		}
		replacement, e := NewStore(fixtureAPI, o.encryption)
		if e != nil {
			t.Fatal(e)
		}
		o.api.Store = replacement
	}
	initial := o.request.OperationID
	o.request.OperationID = random()
	expect(t, o.call(t, false), 409)
	o.request.OperationID = initial
	raw := o.raw()
	expect(t, o.fixture.call(t, o.client, "POST", "/v1/device/overlay/fetch", o.session.AccessToken, o.session.Nonce, append(raw, ' ')), 409)
	o.publication(t, func(p *policy.Payload) { p.RefreshAfterMs++ })
	expect(t, o.call(t, false), 200) // A harmless signed config revision preserves identity/operation.
	for i := 0; i < 2; i++ {
		r := o.call(t, true)
		expect(t, r, 200)
		var reply OverlayReply
		if json.Unmarshal(r.Body.Bytes(), &reply) != nil || !reply.Consumed || reply.Envelope != "" {
			t.Fatal("ack disclosed credential")
		}
	}
	expect(t, o.call(t, false), 403)
	var erased bool
	if e := fixtureOwner.QueryRow(`SELECT envelope IS NULL FROM identity_overlay_grants WHERE device=$1`, o.session.DeviceID).Scan(&erased); e != nil || !erased {
		t.Fatal("consumed server envelope retained", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", o.request, o.request, OverlayReply{Envelope: o.envelope}, OverlayReply{Envelope: o.envelope}), o.envelope) {
		t.Fatal("formatted envelope disclosure")
	}
	for _, query := range []string{
		`INSERT INTO identity_overlay_grants SELECT * FROM identity_overlay_grants`,
		`UPDATE identity_overlay_grants SET owner='other'`,
		`UPDATE identity_overlay_grants SET envelope_hash='other'`,
		`UPDATE identity_overlay_grants SET revoked=true`,
		`DELETE FROM identity_overlay_grants`,
		`DELETE FROM identity_overlay_deliveries`,
	} {
		if _, e := fixtureAPI.Exec(query); e == nil {
			t.Fatal("API exceeded credential authority")
		}
	}
	if _, e := fixturePublisher.Exec(`SELECT * FROM identity_overlay_deliveries`); e == nil {
		t.Fatal("publisher read device operations")
	}
	for _, query := range []string{
		`UPDATE identity_overlay_grants SET reference='other'`,
		`UPDATE identity_overlay_grants SET envelope=decode('01','hex')`,
		`UPDATE identity_overlay_deliveries SET consumed_ms=NULL`,
	} {
		if _, e := fixtureOwner.Exec(query); e == nil {
			t.Fatal("immutable or erased material resurrected")
		}
	}
}
func TestOverlayCurrentPermissionScopesAndFixedDenials(t *testing.T) {
	cases := []struct {
		name   string
		status int
		change func(*testing.T, *overlayFixture)
	}{
		{"account-revoked", 403, func(t *testing.T, o *overlayFixture) {
			_, e := fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false`)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"device-revoked", 403, func(t *testing.T, o *overlayFixture) {
			_, e := fixtureAPI.Exec(`UPDATE identity_devices SET active=false`)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"session-revoked", 403, func(t *testing.T, o *overlayFixture) {
			_, e := fixtureAPI.Exec(`UPDATE identity_sessions SET active=false`)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"grant-revoked", 403, func(t *testing.T, o *overlayFixture) {
			_, e := fixturePublisher.Exec(`UPDATE identity_overlay_grants SET revoked=true`)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"grant-authority-changed", 403, func(t *testing.T, o *overlayFixture) {
			_, e := fixtureOwner.Exec(`UPDATE identity_accounts SET grant_hash='changed'`)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"service-substituted", 403, func(t *testing.T, o *overlayFixture) { o.api.OverlayServiceID = "other-service" }},
		{"reference-substituted", 403, func(t *testing.T, o *overlayFixture) { o.request.Reference = random() }},
		{"version-substituted", 403, func(t *testing.T, o *overlayFixture) { o.request.Version++ }},
		{"namespace-substituted", 403, func(t *testing.T, o *overlayFixture) { o.request.Namespace = "managed-netbird/" + random() }},
		{"expired-credential", 403, func(t *testing.T, o *overlayFixture) {
			o.now = o.now.Add(5 * time.Minute)
			o.api.Clock = func() time.Time { return o.now }
		}},
		{"unknown-signing-root", 503, func(t *testing.T, o *overlayFixture) {
			o.api.Roots = map[string]*ecdsa.PublicKey{"other-root": &o.key.PublicKey}
		}},
		{"signed-epoch-advanced", 403, func(t *testing.T, o *overlayFixture) { o.publication(t, func(p *policy.Payload) { p.SecurityEpoch++ }) }},
		{"capability-withdrawn", 403, func(t *testing.T, o *overlayFixture) {
			o.publication(t, func(p *policy.Payload) {
				p.RequiredCapabilities = p.RequiredCapabilities[:len(p.RequiredCapabilities)-1]
			})
		}},
		{"release", 403, func(t *testing.T, o *overlayFixture) {
			o.publication(t, func(p *policy.Payload) { p.Operation = "release" })
		}},
		{"unapproved", 403, func(t *testing.T, o *overlayFixture) {
			_, e := fixturePublisher.Exec(`UPDATE identity_devices SET publication=NULL`)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"unknown-operation-ack", 409, func(t *testing.T, o *overlayFixture) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := newOverlayFixture(t)
			c.change(t, o)
			r := o.call(t, c.name == "unknown-operation-ack")
			expect(t, r, c.status)
			if strings.Contains(r.Body.String(), o.envelope) || strings.Contains(r.Body.String(), o.session.AccessToken) {
				t.Fatal("denial disclosed secret")
			}
		})
	}
}
func TestOverlayTransportProofAndIdempotencyBoundaries(t *testing.T) {
	o := newOverlayFixture(t)
	path := "/v1/device/overlay/fetch"
	raw := o.raw()
	proof := signed(t, o.client, "POST", o.origin+path, o.session.AccessToken, o.session.Nonce, raw, o.now)
	expect(t, o.rawCall("POST", path, o.session.AccessToken, proof, raw), 200)
	expect(t, o.rawCall("POST", path, o.session.AccessToken, proof, raw), 401)
	expect(t, o.fixture.call(t, o.client, "POST", path, o.session.AccessToken, "wrong-nonce", raw), 401)
	expect(t, o.fixture.call(t, key(t), "POST", path, o.session.AccessToken, o.session.Nonce, raw), 403)
	expect(t, o.fixture.call(t, o.client, "GET", path, o.session.AccessToken, o.session.Nonce, nil), 404)
	expect(t, o.fixture.call(t, o.client, "POST", path+"?token=x", o.session.AccessToken, o.session.Nonce, raw), 404)
	for _, body := range [][]byte{[]byte(`{}`), []byte(`null`), append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), bytes.Repeat([]byte("x"), 8193)} {
		expect(t, o.fixture.call(t, o.client, "POST", path, o.session.AccessToken, o.session.Nonce, body), 401)
	}
	req := httptest.NewRequest("POST", o.origin+path, bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "DPoP "+o.session.AccessToken)
	req.Header.Set("DPoP", signed(t, o.client, "POST", o.origin+path, o.session.AccessToken, o.session.Nonce, raw, o.now))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://browser.example.invalid")
	response := httptest.NewRecorder()
	o.api.ServeHTTP(response, req)
	expect(t, response, 401)
	o.api.OverlayServiceID = ""
	expect(t, o.call(t, false), 404)
}
func TestDeviceOperationLocksTokenTupleDeadlineRollbackAndCancellation(t *testing.T) {
	f := newFixture(t, 2)
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := context.Background()
	b, e := f.store.Lookup(ctx, session.AccessToken, false)
	if e != nil {
		t.Fatal(e)
	}
	next := func() identity.Proof {
		return identity.Proof{Thumbprint: b.Jkt, Claims: identity.ProofClaims{Jti: random(), Nonce: session.Nonce}}
	}
	operation := func(ctx context.Context, tx *sql.Tx, a DeviceAuthority) (DeviceResult, error) {
		return DeviceResult{Value: true, UntilMs: f.now.Add(time.Minute).UnixMilli()}, nil
	}
	if value, e := f.store.WithDeviceSession(ctx, b, session.AccessToken, next(), f.now, operation); e != nil || value != true {
		t.Fatal("valid bounded device operation", e)
	}
	for _, modify := range []func(*Binding){func(b *Binding) { b.Device = random() }, func(b *Binding) { b.Jkt = random() }, func(b *Binding) { b.Owner = random() }} {
		bad := b
		modify(&bad)
		if _, e := f.store.WithDeviceSession(ctx, bad, session.AccessToken, next(), f.now, operation); e == nil {
			t.Fatal("substituted tuple accepted")
		}
	}
	other, _, _ := f.register(t, key(t))
	otherBinding, e := f.store.Lookup(ctx, other.AccessToken, false)
	if e != nil {
		t.Fatal(e)
	}
	bad := b
	bad.Session = otherBinding.Session
	if _, e = f.store.WithDeviceSession(ctx, bad, session.AccessToken, next(), f.now, operation); e == nil {
		t.Fatal("cross-device session accepted")
	}
	if _, e = f.store.WithDeviceSession(ctx, b, random(), next(), f.now, operation); e == nil {
		t.Fatal("stale access token accepted")
	}
	p := next()
	if _, e = f.store.WithDeviceSession(ctx, b, session.AccessToken, p, f.now, func(ctx context.Context, tx *sql.Tx, a DeviceAuthority) (DeviceResult, error) {
		_, e := tx.ExecContext(ctx, `UPDATE identity_sessions SET active=false WHERE id=$1`, b.Session)
		if e != nil {
			t.Fatal(e)
		}
		return DeviceResult{}, ErrUnavailable
	}); !errors.Is(e, ErrUnavailable) {
		t.Fatal("failed callback returned value")
	}
	// Failed work rolls back both its SQL and the proof replay record.
	if _, e = f.store.WithDeviceSession(ctx, b, session.AccessToken, p, f.now, operation); e != nil {
		t.Fatal("failed operation consumed proof or changed session", e)
	}
	if _, e = f.store.WithDeviceSession(ctx, b, session.AccessToken, next(), f.now, func(context.Context, *sql.Tx, DeviceAuthority) (DeviceResult, error) {
		time.Sleep(3 * time.Millisecond)
		return DeviceResult{Value: true, UntilMs: f.now.UnixMilli() + 1}, nil
	}); e == nil {
		t.Fatal("expired final operation permit accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = f.store.WithDeviceSession(canceled, b, session.AccessToken, next(), f.now, operation); e == nil {
		t.Fatal("canceled SQL operation accepted")
	}
	if _, e = f.store.WithDeviceSession(ctx, b, session.AccessToken, next(), f.now, nil); !errors.Is(e, identity.ErrInvalid) {
		t.Fatal("nil callback accepted")
	}
	if _, e = f.store.WithDeviceSession(ctx, b, "short", next(), f.now, operation); !errors.Is(e, identity.ErrInvalid) {
		t.Fatal("short token accepted")
	}
	value, e := f.store.WithDeviceSession(ctx, b, session.AccessToken, next(), f.now, func(ctx context.Context, tx *sql.Tx, a DeviceAuthority) (DeviceResult, error) {
		if e := tx.Rollback(); e != nil {
			t.Fatal(e)
		}
		return DeviceResult{Value: "must-not-escape", UntilMs: f.now.Add(time.Minute).UnixMilli()}, nil
	})
	if e == nil || value != nil {
		t.Fatal("uncommitted callback result escaped")
	}
	// An actual row-lock wait must not extend the original proof/session authority.
	locker, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer locker.Rollback()
	if _, e = locker.Exec(`SELECT id FROM identity_devices WHERE id=$1 FOR UPDATE`, b.Device); e != nil {
		t.Fatal(e)
	}
	blocked, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, e = f.store.WithDeviceSession(blocked, b, session.AccessToken, next(), f.now, operation); e == nil {
		t.Fatal("locked cancellation succeeded")
	}
}

func TestOverlayRejectsMalformedSignedReferences(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any, map[string]any)
	}{
		{"unknown-managed-field", func(top, out map[string]any) { out["managed"].(map[string]any)["unknown"] = true }},
		{"null-managed", func(top, out map[string]any) { out["managed"] = nil }},
		{"wrong-outbound-type", func(top, out map[string]any) { out["type"] = "direct" }},
		{"invalid-management", func(top, out map[string]any) { out["management_url"] = "http://overlay.example.invalid" }},
		{"invalid-reference", func(top, out map[string]any) { out["managed"].(map[string]any)["setupReference"] = "not-a-digest" }},
		{"zero-version", func(top, out map[string]any) { out["managed"].(map[string]any)["setupVersion"] = 0 }},
		{"zero-identity-epoch", func(top, out map[string]any) { out["managed"].(map[string]any)["identityEpoch"] = 0 }},
		{"inline-key", func(top, out map[string]any) { out["setup_key"] = "forbidden" }},
		{"caller-state-path", func(top, out map[string]any) { out["state_directory"] = "/forbidden" }},
		{"duplicate-identity", func(top, out map[string]any) { top["outbounds"] = []any{out, out} }},
		{"wrong-outbounds-shape", func(top, out map[string]any) { top["outbounds"] = true }},
		{"too-many-outbounds", func(top, out map[string]any) {
			items := make([]any, 65)
			for i := range items {
				items[i] = out
			}
			top["outbounds"] = items
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := newOverlayFixture(t)
			o.publication(t, func(p *policy.Payload) {
				engine, _ := b64.DecodeString(p.EngineConfigB64)
				var top map[string]any
				if json.Unmarshal(engine, &top) != nil {
					t.Fatal("engine fixture")
				}
				out := top["outbounds"].([]any)[0].(map[string]any)
				c.change(top, out)
				engine, _ = json.Marshal(top)
				sum := sha256.Sum256(engine)
				p.EngineConfigB64 = b64.EncodeToString(engine)
				p.ContentHash = hex.EncodeToString(sum[:])
			})
			expect(t, o.call(t, false), 503)
		})
	}
}
func TestOverlayGrantIssuerRejectsInvalidSignatureScopeAndImmutableReference(t *testing.T) {
	o := newOverlayFixture(t)
	ctx := context.Background()
	tx, e := fixturePublisher.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	bad := o.binding
	bad.KeyThumbprint = random()
	if e = o.worker.InstallOverlayGrant(ctx, tx, Owner(o.grant.Issuer, o.grant.Subject), bad, o.envelope, o.api.Roots, o.now); e == nil {
		t.Fatal("wrong addressed scope issued")
	}
	if e = o.worker.InstallOverlayGrant(ctx, tx, "", o.binding, o.envelope, o.api.Roots, o.now); e == nil {
		t.Fatal("missing owner issued")
	}
	if e = o.worker.InstallOverlayGrant(ctx, tx, Owner(o.grant.Issuer, o.grant.Subject), o.binding, o.envelope, o.api.Roots, o.now); e == nil {
		t.Fatal("existing immutable reference replaced")
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	// A consumed/erased record cannot be fetched even before an enrollment ack.
	if _, e = fixtureAPI.Exec(`UPDATE identity_overlay_grants SET envelope=NULL`); e != nil {
		t.Fatal(e)
	}
	expect(t, o.call(t, false), 403)
}
