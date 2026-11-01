//go:build postgres

package invitation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

var fixtureOwner, fixtureControl, fixtureDevice, fixtureSigner *sql.DB

func TestMain(m *testing.M) {
	u, e := url.Parse(os.Getenv("SYN443_TEST_DATABASE"))
	if e != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" {
		panic("owned SQL fixture required")
	}
	fixtureOwner, e = sql.Open("pgx", u.String())
	if e != nil {
		panic("fixture connection")
	}
	if _, e = fixtureOwner.Exec(enrollment.Schema + "\n" + catalog.Schema + "\n" + Schema); e != nil {
		panic(e)
	}
	var worker *sql.DB
	for _, item := range []struct {
		name   string
		target **sql.DB
	}{{"syn443_identity_api", &fixtureDevice}, {"syn443_identity_publisher", &fixtureSigner}, {"syn443_control_api", &fixtureControl}, {"syn443_source_worker", &worker}} {
		password, _ := random()
		var statement string
		if e = fixtureOwner.QueryRow(`SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOBYPASSRLS PASSWORD %L',$1::text,$2::text)`, item.name, password).Scan(&statement); e != nil {
			panic(e)
		}
		if _, e = fixtureOwner.Exec(statement); e != nil {
			panic(e)
		}
		copy := *u
		copy.User = url.UserPassword(item.name, password)
		*item.target, e = sql.Open("pgx", copy.String())
		if e != nil {
			panic("role connection")
		}
		(*item.target).SetMaxOpenConns(4)
	}
	if _, e = fixtureOwner.Exec(enrollment.Roles + "\n" + catalog.Roles + "\n" + Roles); e != nil {
		panic(e)
	}
	code := m.Run()
	worker.Close()
	fixtureSigner.Close()
	fixtureDevice.Close()
	fixtureControl.Close()
	fixtureOwner.Close()
	os.Exit(code)
}

type verifier struct{ p identity.Principal }

func (v *verifier) Verify(context.Context, string, time.Time) (identity.Principal, error) {
	return v.p, nil
}

type fixture struct {
	admin          *AdminService
	device, signer *Store
	key, phone     *ecdsa.PrivateKey
	v              *verifier
	owner, grant   string
	now            time.Time
	root           bootstrap.Anchor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if _, e := fixtureOwner.Exec(`TRUNCATE managed_invitation_replays,managed_invitations,identity_requests,identity_refresh_history,identity_replays,identity_revocations,identity_owner_revocations,identity_challenges,identity_sessions,identity_devices,identity_accounts,catalog_acl RESTART IDENTITY CASCADE`); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	phone, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	thumb, _ := identity.PublicJWK(&key.PublicKey).Thumbprint()
	v := &verifier{identity.Principal{Issuer: "https://identity.example.invalid/realms/test", Subject: "synthetic-admin", Thumbprint: thumb, Expires: now.Unix() + 300, AuthTime: now.Unix(), ACR: "urn:syn443:loa:2", Methods: []string{"otp"}, Scope: "syn443.control"}}
	owner := identity.Hash([]byte(v.p.Issuer + "\x00synthetic-user"))
	grant := identity.Hash([]byte("synthetic-grant"))
	actor := identity.Hash([]byte(v.p.Issuer + "\x00" + v.p.Subject))
	if _, e = fixtureOwner.Exec(`INSERT INTO identity_accounts(owner,issuer,subject,enabled,device_limit,valid_until,grant_hash) VALUES($1,'https://identity.example.invalid/realms/test','synthetic-user',true,2,$2,$3)`, owner, now.Unix()+86400, grant); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'*','*','*',$2)`, actor, now.Unix()+86400); e != nil {
		t.Fatal(e)
	}
	boxKey := bytes.Repeat([]byte{37}, 32)
	control, e := NewStore(fixtureControl, boxKey)
	if e != nil {
		t.Fatal(e)
	}
	device, e := NewStore(fixtureDevice, boxKey)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := NewStore(fixtureSigner, boxKey)
	if e != nil {
		t.Fatal(e)
	}
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rootSPKI, _ := bootstrap.Public(&rootKey.PublicKey)
	onlineKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	online, _ := bootstrap.Public(&onlineKey.PublicKey)
	root := bootstrap.Anchor{ID: "offline-root-a", SPKI: rootSPKI, Epoch: 1}
	d := bootstrap.Descriptor{SchemaVersion: 1, Audience: "syn443-client-bootstrap", RootEpoch: 1, Revision: 1, ServiceID: "service-a", Issuer: v.p.Issuer, ClientID: "syn443-android", APIOrigin: "https://api.example.invalid", Roots: map[string]string{"online-a": online}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Unix() + 3600}
	manifest, e := bootstrap.SignDescriptor(d, root, rootKey, now)
	if e != nil {
		t.Fatal(e)
	}
	return &fixture{&AdminService{Store: control, Verifier: v, ControlOrigin: "https://control.example.invalid", AssuranceACR: "urn:syn443:loa:2", Descriptor: manifest, Anchor: root}, device, signer, key, phone, v, owner, grant, now, root}
}

const token = "synthetic-administrative-access-token"

func signed(t *testing.T, key *ecdsa.PrivateKey, uri, token, nonce string, raw []byte, now time.Time) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": identity.PublicJWK(&key.PublicKey)})
	jti, _ := random()
	claims := identity.ProofClaims{Jti: jti, Htm: "POST", Htu: uri, Iat: now.Unix(), Nonce: nonce, RequestHash: identity.Hash(raw)}
	if token != "" {
		claims.Ath = identity.Hash([]byte(token))
	}
	body, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(body)
	hash := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, hash[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + enc.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}
func (f *fixture) adminCall(t *testing.T, action string, payload any) (any, error) {
	t.Helper()
	id, _ := random()
	body, _ := json.Marshal(payload)
	raw, _ := json.Marshal(Envelope{1, action, id, body})
	proof := signed(t, f.key, f.admin.ControlOrigin+"/v1/control/action", token, "", raw, f.now)
	return f.admin.Dispatch(context.Background(), token, proof, raw, f.now)
}
func (f *fixture) issue(t *testing.T) Issued {
	t.Helper()
	value, e := f.adminCall(t, "invite.issue", IssueRequest{f.owner, f.grant, f.now.Unix() + 600, "service-a", 1})
	if e != nil {
		t.Fatal(e)
	}
	return value.(Issued)
}
func (f *fixture) claim(t *testing.T, issued Issued) (ClaimState, []byte) {
	t.Helper()
	invitation, e := bootstrap.AuthenticateLink(issued.Link, f.root, bootstrap.Floor{}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := random()
	raw, _ := json.Marshal(Claim{id, invitation.Code, identity.PublicJWK(&f.phone.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}})
	proof := signed(t, f.phone, invitation.Descriptor.APIOrigin+"/v1/invitations/claim", "", "", raw, f.now)
	state, e := f.device.Claim(context.Background(), "service-a", invitation.Descriptor.APIOrigin, raw, proof, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return state, raw
}

func TestSQLInvitationReservesOneKeyAndNeedsSeparateApprovalBeforeSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for role, store := range map[string]*Store{"syn443_control_api": f.admin.Store, "syn443_identity_api": f.device, "syn443_identity_publisher": f.signer} {
		if e := store.RuntimeRole(ctx, role); e != nil {
			t.Fatal(e)
		}
	}
	issued := f.issue(t)
	state, raw := f.claim(t, issued)
	if state.State != "pending_approval" || state.Version != 2 || len(state.Nonce) != 43 || len(state.PairCode) != 6 {
		t.Fatal("claim state")
	}
	proof := signed(t, f.phone, "https://api.example.invalid/v1/invitations/claim", "", "", raw, f.now)
	again, e := f.device.Claim(ctx, "service-a", "https://api.example.invalid", raw, proof, f.now)
	if e != nil || again != state {
		t.Fatal("lost claim reply", e)
	}
	var sessions, devices int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_sessions`).Scan(&sessions); e != nil {
		t.Fatal(e)
	}
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_devices`).Scan(&devices); e != nil || sessions != 0 || devices != 0 {
		t.Fatal("claim leaked a session/device grant")
	}
	if _, e = fixtureDevice.Exec(`UPDATE managed_invitations SET approved_at=1 WHERE id=$1`, state.ID); e == nil {
		t.Fatal("device role approved itself")
	}
	if _, e = fixtureControl.Exec(`UPDATE managed_invitations SET claim_jkt='forged' WHERE id=$1`, state.ID); e == nil {
		t.Fatal("admin role replaced a device key")
	}
	thumb, _ := identity.PublicJWK(&f.phone.PublicKey).Thumbprint()
	value, e := f.adminCall(t, "invite.approve", Approval{state.ID, state.Version, thumb, state.PairCode})
	if e != nil || value.(View).State != "provisioning" {
		t.Fatal("explicit approval", e)
	}
	id, _ := random()
	statusBody, _ := json.Marshal(DeviceRequest{state.ID, id})
	proof = signed(t, f.phone, "https://api.example.invalid/v1/invitations/status", "", state.Nonce, statusBody, f.now)
	status, e := f.device.Status(ctx, "https://api.example.invalid", statusBody, proof, f.now)
	if e != nil || status.State != "provisioning" {
		t.Fatal("approved but unsigned state", e)
	}
	if _, e = f.device.Status(ctx, "https://api.example.invalid", statusBody, proof, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("status proof replay")
	}
	var encrypted []byte
	if e = fixtureOwner.QueryRow(`SELECT claim_payload FROM managed_invitations WHERE id=$1`, state.ID).Scan(&encrypted); e != nil || bytes.Contains(encrypted, []byte("capabilities")) {
		t.Fatal("claim stored in plaintext")
	}
	if _, e = fixtureOwner.Exec(`UPDATE managed_invitations SET owner=$2 WHERE id=$1`, state.ID, identity.Hash([]byte("other"))); e == nil {
		t.Fatal("invitation owner changed")
	}
	if _, e = fixtureOwner.Exec(`UPDATE managed_invitations SET claim_nonce='forged' WHERE id=$1`, state.ID); e == nil {
		t.Fatal("claimed key binding changed")
	}
}

func TestSQLInvitationWrongKeyExpiryMFAAndRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.v.p.Methods = []string{"pwd"}
	if _, e := f.adminCall(t, "invite.issue", IssueRequest{f.owner, f.grant, f.now.Unix() + 600, "service-a", 1}); !errors.Is(e, ErrDenied) {
		t.Fatal("manual onboarding without fresh MFA")
	}
	f.v.p.Methods = []string{"otp"}
	issued := f.issue(t)
	state, raw := f.claim(t, issued)
	wrong, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	proof := signed(t, wrong, "https://api.example.invalid/v1/invitations/claim", "", "", raw, f.now)
	if _, e = f.device.Claim(ctx, "service-a", "https://api.example.invalid", raw, proof, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("stolen code replaced claim key")
	}
	proof = signed(t, f.phone, "https://api.example.invalid/v1/invitations/claim", "", "", raw, f.now.Add(601*time.Second))
	if _, e = f.device.Claim(ctx, "service-a", "https://api.example.invalid", raw, proof, f.now.Add(601*time.Second)); !errors.Is(e, ErrExpired) {
		t.Fatal("expired invite reused", e)
	}
	thumb, _ := identity.PublicJWK(&f.phone.PublicKey).Thumbprint()
	if _, e = f.adminCall(t, "invite.approve", Approval{state.ID, state.Version, thumb, "00000x"}); !errors.Is(e, ErrConflict) {
		t.Fatal("pair code not checked")
	}
	if _, e = f.adminCall(t, "invite.revoke", Mutation{state.ID, state.Version}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.adminCall(t, "invite.approve", Approval{state.ID, state.Version, thumb, state.PairCode}); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked invite approved")
	}
	if _, e = fixtureOwner.Exec(`UPDATE managed_invitations SET revoked=false WHERE id=$1`, state.ID); e == nil {
		t.Fatal("revocation reversed")
	}
	f.v.p.Methods = []string{"pwd"}
	if value, e := f.adminCall(t, "invite.get", Mutation{ID: state.ID}); e != nil || value.(View).State != "revoked" {
		t.Fatal("scoped inventory unnecessarily required MFA", e)
	}
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl`); e != nil {
		t.Fatal(e)
	}
	if _, e = f.adminCall(t, "invite.get", Mutation{ID: state.ID}); !errors.Is(e, ErrDenied) {
		t.Fatal("withdrawn role remained active")
	}
	var claim Claim
	if e = json.Unmarshal(raw, &claim); e != nil {
		t.Fatal(e)
	}
	request, e := claim.EnrollmentRequest()
	if e != nil || strings.Contains(string(request), `"code":`) {
		t.Fatal("invitation code copied into portable enrollment")
	}
}
