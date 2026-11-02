//go:build postgres

package deviceprovisioning

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
	"net/url"
	"os"
	"testing"
	"time"

	"encoding/hex"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

var fixtureOwner, fixtureControl, fixtureDevice, fixtureSigner, fixtureSourceWorker *sql.DB

func TestMain(m *testing.M) {
	u, e := url.Parse(os.Getenv("SYN443_TEST_DATABASE"))
	if e != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" {
		panic("owned SQL fixture required")
	}
	fixtureOwner, e = sql.Open("pgx", u.String())
	if e != nil {
		panic("fixture connection")
	}
	if _, e = fixtureOwner.Exec(enrollment.Schema + "\n" + catalog.Schema + "\n" + invitation.Schema + "\n" + ConfigurationSchema); e != nil {
		panic(e)
	}
	for _, item := range []struct {
		name   string
		target **sql.DB
	}{{"syn443_identity_api", &fixtureDevice}, {"syn443_identity_publisher", &fixtureSigner}, {"syn443_control_api", &fixtureControl}, {"syn443_source_worker", &fixtureSourceWorker}} {
		password, _ := random()
		var statement string
		var exists bool
		if e = fixtureOwner.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, item.name).Scan(&exists); e != nil {
			panic(e)
		}
		verb := "CREATE"
		if exists {
			verb = "ALTER"
		}
		if e = fixtureOwner.QueryRow(`SELECT format('%s ROLE %I LOGIN NOINHERIT NOBYPASSRLS PASSWORD %L',$1::text,$2::text,$3::text)`, verb, item.name, password).Scan(&statement); e != nil {
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
	if _, e = fixtureOwner.Exec(enrollment.Roles + "\n" + catalog.Roles + "\n" + invitation.Roles + "\n" + ConfigurationRoles); e != nil {
		panic(e)
	}
	code := m.Run()
	fixtureSourceWorker.Close()
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
	admin          *invitation.AdminService
	device, signer *invitation.Store
	key, phone     *ecdsa.PrivateKey
	v              *verifier
	owner, grant   string
	now            time.Time
	root           bootstrap.Anchor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if _, e := fixtureOwner.Exec(`TRUNCATE managed_configuration_heads,managed_configuration_versions,managed_configuration_previews,managed_invitation_replays,managed_invitations,identity_requests,identity_refresh_history,identity_replays,identity_revocations,identity_owner_revocations,identity_challenges,identity_sessions,identity_devices,identity_accounts,catalog_network_drafts,catalog_proofs,catalog_outbox,catalog_audit,catalog_operations,catalog_jobs,catalog_dependencies,catalog_snapshots,catalog_share_heads,catalog_source_grants,catalog_sources,catalog_resources,catalog_acl RESTART IDENTITY CASCADE;UPDATE identity_clock SET second=0 WHERE id=true;UPDATE catalog_clock SET second=0 WHERE id=true`); e != nil {
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
	control, e := invitation.NewStore(fixtureControl, boxKey)
	if e != nil {
		t.Fatal(e)
	}
	device, e := invitation.NewStore(fixtureDevice, boxKey)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := invitation.NewStore(fixtureSigner, boxKey)
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
	return &fixture{&invitation.AdminService{Store: control, Verifier: v, ControlOrigin: "https://control.example.invalid", AssuranceACR: "urn:syn443:loa:2", Descriptor: manifest, Anchor: root}, device, signer, key, phone, v, owner, grant, now, root}
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
	raw, _ := json.Marshal(invitation.Envelope{1, action, id, body})
	proof := signed(t, f.key, f.admin.ControlOrigin+"/v1/control/action", token, "", raw, f.now)
	return f.admin.Dispatch(context.Background(), token, proof, raw, f.now)
}
func (f *fixture) issue(t *testing.T) invitation.Issued {
	t.Helper()
	value, e := f.adminCall(t, "invite.issue", invitation.IssueRequest{f.owner, f.grant, f.now.Unix() + 600, "service-a", 1})
	if e != nil {
		t.Fatal(e)
	}
	return value.(invitation.Issued)
}
func (f *fixture) claim(t *testing.T, issued invitation.Issued) (invitation.ClaimState, []byte) {
	t.Helper()
	link, e := bootstrap.AuthenticateLink(issued.Link, f.root, bootstrap.Floor{}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := random()
	raw, _ := json.Marshal(invitation.Claim{id, link.Code, identity.PublicJWK(&f.phone.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}})
	proof := signed(t, f.phone, link.Descriptor.APIOrigin+"/v1/invitations/claim", "", "", raw, f.now)
	state, e := f.device.Claim(context.Background(), "service-a", link.Descriptor.APIOrigin, raw, proof, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return state, raw
}

func random() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func (f *fixture) verification() invitation.Verification {
	return invitation.Verification{AdminVerifier: f.v, ControlOrigin: f.admin.ControlOrigin, IdentityOrigin: "https://api.example.invalid", AssuranceACR: f.admin.AssuranceACR, Anchor: f.root}
}
func (f *fixture) grantConfig(t *testing.T) enrollment.Grant {
	t.Helper()
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	sum := sha256.Sum256(engine)
	g := enrollment.Grant{Issuer: f.v.p.Issuer, Subject: "synthetic-user", DeviceLimit: 2, Until: f.now.Unix() + 7200, Template: policy.Payload{SchemaVersion: 1, Operation: "configure", Revision: 1, Audience: "syn443-device", RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}, AlgorithmRevision: "m1-local-v1", EngineConfigB64: base64.RawURLEncoding.EncodeToString(engine), ContentHash: hex.EncodeToString(sum[:]), Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.org/generate_204", Required: true}}}}}
	if e := enrollment.Authorize(context.Background(), fixtureOwner, g, f.now); e != nil {
		t.Fatal(e)
	}
	f.grant = g.Hash()
	return g
}
