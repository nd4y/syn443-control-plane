//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

type configurationWorkerSQLFixture struct {
	n        networkFixture
	control  *ConfigurationControl
	proposal LayerProposal
	worker   *ConfigurationWorker
	idp      *configurationAdminOIDCFixture
	runtime  ConfigurationRuntimeConfig
	current  func() time.Time
}

// Reuse actual invitation/source-import/ACL fixtures. The first ordinary
// publication deliberately has no NetworkAuthority or managed assignment.
func newConfigurationWorkerSQLFixture(t *testing.T) configurationWorkerSQLFixture {
	t.Helper()
	n, control, proposal := configurationControlFixture(t)
	n.publisher.Configurations = nil
	if e := n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal("ordinary unassigned device approval failed", e)
	}
	idp := newConfigurationAdminOIDCFixture(t)
	c := runtimeConfiguration(t)
	c.Issuer, c.ControlOrigin = idp.adminIssuer, control.Origin
	public, e := x509.MarshalPKIXPublicKey(&n.f.key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	c.Roots = map[string]string{"fixture-root": base64.StdEncoding.EncodeToString(public)}
	// Existing owner-fixture pattern: authorize the administrative actor in its
	// independent realm without changing device/source owner, key or grants.
	actor := enrollment.Owner(c.Issuer, n.f.v.p.Subject)
	if actor == n.actor.ID {
		t.Fatal("independent administrative issuer aliased the device realm")
	}
	if _, e := fixtureOwner.Exec(`UPDATE catalog_acl SET actor=$1 WHERE actor=$2`, actor, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	n.actor.ID = actor
	for _, db := range []*sql.DB{fixtureControl, fixtureSourceWorker} {
		if worker, e := configurationWorkerFromDB(context.Background(), c, db, "fixture-root", n.f.key, idp.server.Client().Transport); e == nil || worker != nil {
			t.Fatal("real API/source SQL role acquired configuration publication")
		}
	}
	if idp.adminMetadata.Load() != 0 || idp.deviceMetadata.Load() != 0 {
		t.Fatal("wrong SQL role reached administrative discovery")
	}
	worker, e := configurationWorkerFromDB(context.Background(), c, fixtureSigner, "fixture-root", n.f.key, idp.server.Client().Transport)
	if e != nil {
		t.Fatal("real publisher-role constructor failed", e)
	}
	// TestMain owns the shared fixtureSigner pool. Do not call worker.Close on
	// this borrowed constructor seam or close a pool owned by other test cases.
	control.Verifier = worker.publisher.Verifier
	started := time.Now()
	return configurationWorkerSQLFixture{n, control, proposal, worker, idp, c,
		func() time.Time { return n.f.now.Add(time.Since(started)) }}
}

func (f configurationWorkerSQLFixture) token(t *testing.T) string {
	t.Helper()
	thumb, e := identity.PublicJWK(&f.n.f.key.PublicKey).Thumbprint()
	if e != nil {
		t.Fatal(e)
	}
	return f.idp.token(t, f.runtime.Issuer, f.runtime.ClientIDs[0], f.n.f.v.p.Subject, thumb, f.current())
}

func (f configurationWorkerSQLFixture) call(t *testing.T, token, action, operation string, payload any) (any, error) {
	t.Helper()
	body, e := json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(invitation.Envelope{Version: 1, Action: action, RequestID: identity.Hash([]byte(operation)), Payload: body})
	if e != nil {
		t.Fatal(e)
	}
	at := f.current()
	proof := signed(t, f.n.f.key, f.control.Origin+"/v1/control/action", token, "", raw, at)
	return f.control.Dispatch(context.Background(), token, proof, raw, at)
}

func (f configurationWorkerSQLFixture) dispatch(t *testing.T, action, operation string, payload any) ConfigurationRequestView {
	t.Helper()
	value, e := f.call(t, f.token(t), action, operation, payload)
	if e != nil {
		t.Fatal("actual OIDC/DPoP administrative queue action denied", e)
	}
	request, ok := value.(ConfigurationRequestView)
	if !ok {
		t.Fatal("unexpected administrative queue result")
	}
	return request
}

func (f configurationWorkerSQLFixture) tick(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now, e := f.worker.Now(ctx, f.current())
	if e != nil {
		t.Fatal("real database clock failed", e)
	}
	return f.worker.RunOnce(ctx, now)
}

func configurationWorkerDevicePublication(t *testing.T, device string) (int64, []byte, string, string, []byte) {
	t.Helper()
	var revision int64
	var ciphertext, request []byte
	var owner, key string
	var active, approved bool
	if e := fixtureOwner.QueryRow(`SELECT revision,publication,owner,jkt,request_body,active,approved FROM identity_devices WHERE id=$1`, device).
		Scan(&revision, &ciphertext, &owner, &key, &request, &active, &approved); e != nil || !active || !approved {
		t.Fatal("actual approved device missing", e)
	}
	return revision, ciphertext, owner, key, request
}

func TestConfigurationWorkerPostgresActualQueueAndUnassignedRenewalRemainIndependent(t *testing.T) {
	f := newConfigurationWorkerSQLFixture(t)
	ctx := context.Background()
	device := f.n.target.Device
	firstRevision, firstCipher, owner, ownKey, request := configurationWorkerDevicePublication(t, device)
	var heads int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_heads`).Scan(&heads); e != nil || heads != 0 || firstRevision != 1 {
		t.Fatal("unassigned fixture already had a managed publication", e)
	}
	if f.n.publisher.Configurations != nil {
		t.Fatal("fixture installed NetworkAuthority in ordinary lease renewal")
	}
	renewedAt := f.n.f.now.Add(301 * time.Second)
	if e := f.n.publisher.RunOnce(ctx, renewedAt); e != nil {
		t.Fatal("approved unassigned device lost ordinary lease renewal", e)
	}
	revision, ciphertext, renewedOwner, renewedKey, renewedRequest := configurationWorkerDevicePublication(t, device)
	if revision != 2 || bytes.Equal(ciphertext, firstCipher) || renewedOwner != owner || renewedKey != ownKey || !bytes.Equal(renewedRequest, request) {
		t.Fatal("ordinary renewal changed enrollment identity or did not issue its next lease")
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_heads`).Scan(&heads); e != nil || heads != 0 {
		t.Fatal("ordinary unassigned renewal created a managed head", e)
	}
	plain, e := f.n.publisher.Store.Open(ciphertext, "publication/v1/"+device+"/"+fmt.Sprint(revision))
	if e != nil {
		t.Fatal(e)
	}
	verified, e := policy.VerifyBound(string(plain), f.worker.publisher.Roots, device, ownKey, renewedAt)
	if e != nil || verified.Revision != 2 {
		t.Fatal("ordinary unassigned renewal was not independently signed/key-bound", e)
	}
	engine, e := base64.RawURLEncoding.DecodeString(verified.EngineConfigB64)
	if e != nil || strings.Contains(string(engine), "proxy.example.invalid") || !strings.Contains(string(engine), `"type":"direct"`) {
		t.Fatal("ordinary publisher borrowed unapproved managed source configuration")
	}
	if _, e := f.worker.publisher.Store.Open(ciphertext, "publication/v1/"+device+"/"+fmt.Sprint(revision)); e == nil {
		t.Fatal("configuration worker received the identity publication encryption key")
	}
	// Keep all signed receipt/time checks on one advancing logical fixture
	// clock after the five-minute renewal, without waiting on real wall time.
	started := time.Now()
	f.current = func() time.Time { return renewedAt.Add(time.Second).Add(time.Since(started)) }
	queued := f.dispatch(t, "configuration.preview.request", "independent worker preview", configurationPreviewInput{f.proposal})
	if e := f.tick(t); e != nil {
		t.Fatal("independent worker failed actual queued preview", e)
	}
	var state string
	var raw []byte
	if e := fixtureOwner.QueryRow(`SELECT state,result FROM managed_configuration_requests WHERE id=$1`, queued.ID).Scan(&state, &raw); e != nil || state != "ready" {
		t.Fatal("actual preview receipt missing", e)
	}
	var preview ConfigurationPreviewResult
	if identity.DecodeConfiguration(raw, &preview) != nil || preview.Preview.Actor != f.n.actor.ID || len(preview.Preview.Recipients) != 1 || preview.Preview.Recipients[0].Owner != owner || preview.Preview.Recipients[0].Thumbprint != ownKey {
		t.Fatal("preview substituted administrative identity for the enrolled device")
	}
	if _, e := configuration.VerifyPreview(ctx, preview.Ticket, f.worker.publisher.Roots, f.control.Origin, f.n.actor.ID, f.current()); e != nil {
		t.Fatal("actual worker preview signature rejected", e)
	}
	// An immediate second actual DB clock observation must preserve the
	// preview's issuance milliseconds. Do not hide this with a tick/sleep or
	// relax VerifyPreview's exact future-time check.
	checkedNow, e := f.worker.Now(ctx, f.current())
	if e != nil || checkedNow.UnixMilli() < preview.Preview.IssuedAtMs {
		t.Fatal("next worker clock rewound a freshly signed preview", e)
	}
	if _, e := configuration.VerifyPreview(ctx, preview.Ticket, f.worker.publisher.Roots, f.control.Origin, f.n.actor.ID, checkedNow); e != nil {
		t.Fatal("immediate next worker time rejected its own fresh preview", e)
	}
	if _, e := configuration.VerifyPreview(ctx, preview.Ticket, f.worker.publisher.Roots, f.control.Origin, f.n.actor.ID, time.UnixMilli(preview.Preview.IssuedAtMs-1)); !errors.Is(e, configuration.ErrInvalid) {
		t.Fatal("exact future-preview guard was weakened", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_heads`).Scan(&heads); e != nil || heads != 0 {
		t.Fatal("preview created a configuration head", e)
	}
	queued = f.dispatch(t, "configuration.publish", "independent worker publish", configurationPublishInput{preview.PreviewID, preview.Ticket})
	if e := f.tick(t); e != nil {
		t.Fatal("independent worker failed actual queued publication", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT state,result FROM managed_configuration_requests WHERE id=$1`, queued.ID).Scan(&state, &raw); e != nil || state != "published" {
		t.Fatal("actual publication receipt missing", e)
	}
	var headRevision int64
	var headHash string
	if e := fixtureOwner.QueryRow(`SELECT revision,body_hash FROM managed_configuration_heads WHERE device=$1`, device).Scan(&headRevision, &headHash); e != nil || headRevision != 1 || headHash != preview.Preview.DraftHash {
		t.Fatal("reviewed desired head was not atomically published", e)
	}
	// Independently read the real signed head and source snapshot. This local
	// test reader is never attached to the ordinary enrollment publisher.
	reader := &NetworkAuthority{Sources: f.worker.publisher.Sources,
		Layers: &SQLNetworkLayers{Store: f.worker.publisher.Store, ControlOrigin: f.control.Origin, Roots: f.worker.publisher.Roots}}
	target := f.n.target
	target.CurrentRevision = revision
	prepared, e := reader.Prepare(ctx, target, f.current())
	if e != nil || prepared == nil || !bytes.Contains(prepared.EngineConfig, []byte("proxy.example.invalid")) {
		t.Fatal("signed head did not compose the original authorized source snapshot", e)
	}
	afterRevision, afterCipher, afterOwner, afterKey, afterRequest := configurationWorkerDevicePublication(t, device)
	if f.n.publisher.Configurations != nil || afterRevision != revision || !bytes.Equal(afterCipher, ciphertext) || afterOwner != owner || afterKey != ownKey || !bytes.Equal(afterRequest, request) {
		t.Fatal("configuration worker issued a device lease, changed its binding or rewired ordinary renewal")
	}
	if f.idp.deviceMetadata.Load() != 0 {
		t.Fatal("configuration worker consulted the device realm")
	}
}

func staleConfigurationWorkerMFA(t *testing.T, f configurationWorkerSQLFixture) string {
	t.Helper()
	parts := strings.Split(f.token(t), ".")
	raw, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		t.Fatal("invalid owned IdP fixture token")
	}
	// The signed token itself is newly issued and unexpired. Only the strong
	// authentication time is old, so denial must not be an access-token expiry.
	claims["auth_time"] = f.current().Add(-601 * time.Second).Unix()
	raw, e = json.Marshal(claims)
	if e != nil {
		t.Fatal(e)
	}
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(input))
	signature, e := rsa.SignPKCS1v15(rand.Reader, f.idp.key, crypto.SHA256, hash[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestConfigurationWorkerPostgresOriginalReceiptsRequireLiveSourceACLAndMFA(t *testing.T) {
	for _, kind := range []string{"mfa", "source", "acl"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfigurationWorkerSQLFixture(t)
			if kind == "mfa" {
				token := staleConfigurationWorkerMFA(t, f)
				principal, e := f.worker.publisher.Verifier.Verify(context.Background(), token, f.current())
				if e != nil || principal.Expires <= f.current().Unix() || principal.MFAUntil(f.runtime.AssuranceACR, f.current()) != 0 {
					t.Fatal("fixture did not isolate valid identity from expired MFA", e)
				}
				if _, e := f.call(t, token, "configuration.preview.request", "expired strong authentication", configurationPreviewInput{f.proposal}); !errors.Is(e, catalog.ErrReauthentication) {
					t.Fatal("actual signed stale MFA reached configuration admission", e)
				}
				var queued int
				if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_requests`).Scan(&queued); e != nil || queued != 0 {
					t.Fatal("MFA denial created a queue receipt", e)
				}
				return
			}
			queued := f.dispatch(t, "configuration.preview.request", "revoked "+kind+" after queue", configurationPreviewInput{f.proposal})
			if kind == "acl" {
				if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, f.n.actor.ID); e != nil {
					t.Fatal(e)
				}
			} else {
				changed := f.n.source
				changed.Enabled = false
				changed.State, changed.AccessState, changed.ActiveSnapshot, changed.CandidateSnapshot = "", "", "", ""
				changed.LastSync, changed.NextSync, changed.LastResourceRevision = 0, 0, 0
				if _, e := f.n.api.PutSource(context.Background(), f.n.actor, changed, catalog.SecretPatch{Operation: "keep"}, "disable-source-after-original-receipt", f.current()); e != nil {
					t.Fatal("normal source API did not revoke the queued dependency", e)
				}
			}
			if e := f.tick(t); e == nil {
				t.Fatal("independent publisher trusted API-time authority after revocation")
			}
			var state string
			if e := fixtureOwner.QueryRow(`SELECT state FROM managed_configuration_requests WHERE id=$1`, queued.ID).Scan(&state); e != nil || state != "rejected" {
				t.Fatal("revoked original receipt did not terminate without approval", e)
			}
			for _, table := range []string{"managed_configuration_previews", "managed_configuration_heads", "managed_configuration_layer_versions"} {
				var count int
				if e := fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
					t.Fatal("revocation created a partial approval artifact", e)
				}
			}
		})
	}
}
