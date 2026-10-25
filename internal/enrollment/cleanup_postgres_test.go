//go:build postgres

package enrollment

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestFreshIdentityCanRevokeLostOutcomeWithoutOldPrivateKey(t *testing.T) {
	f := newFixture(t, 1)
	old := key(t)
	session, _, _ := f.register(t, old)
	oldThumb, _ := identity.PublicJWK(&old.PublicKey).Thumbprint()
	fresh := key(t)
	token := f.token(fresh)
	body, _ := json.Marshal(Cleanup{random(), []string{oldThumb}})
	path := "/v1/identity/devices/revoke"
	r := f.call(t, fresh, "POST", path, token, "", body)
	expect(t, r, 401)
	nonce := r.Header().Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("fresh identity nonce")
	}
	proof := signed(t, fresh, "POST", f.origin+path, token, nonce, body, f.now)
	expect(t, f.rawCall("POST", path, token, proof, body), 204)
	expect(t, f.call(t, fresh, "POST", path, token, nonce, body), 204)
	expect(t, f.rawCall("POST", path, token, proof, body), 401)
	expect(t, f.call(t, old, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil), 403)
	var request Cleanup
	json.Unmarshal(body, &request)
	request.Thumbprints = []string{random()}
	changed, _ := json.Marshal(request)
	expect(t, f.call(t, fresh, "POST", path, token, nonce, changed), 409)
	newSession, _, _ := f.register(t, fresh)
	if newSession.DeviceID == session.DeviceID {
		t.Fatal("revoked registration revived")
	}
}
func TestOwnerCleanupCannotRevokeAnotherUserAndWorksAfterAssignmentDenial(t *testing.T) {
	f := newFixture(t, 2)
	ownKey := key(t)
	own, _, _ := f.register(t, ownKey)
	ownThumb, _ := identity.PublicJWK(&ownKey.PublicKey).Thumbprint()
	previous := f.grant
	f.grant.Subject = "other-synthetic-user"
	if e := Authorize(context.Background(), fixtureOwner, f.grant, f.now); e != nil {
		t.Fatal(e)
	}
	foreignKey := key(t)
	foreign, _, _ := f.register(t, foreignKey)
	foreignThumb, _ := identity.PublicJWK(&foreignKey.PublicKey).Thumbprint()
	f.grant = previous
	if _, e := fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false WHERE owner=$1`, Owner(f.grant.Issuer, f.grant.Subject)); e != nil {
		t.Fatal(e)
	}
	fresh := key(t)
	token := f.token(fresh)
	body, _ := json.Marshal(Cleanup{random(), []string{ownThumb, foreignThumb, random()}})
	path := "/v1/identity/devices/revoke"
	r := f.call(t, fresh, "POST", path, token, "", body)
	expect(t, r, 401)
	nonce := r.Header().Get("DPoP-Nonce")
	expect(t, f.call(t, fresh, "POST", path, token, nonce, body), 204)
	expect(t, f.call(t, foreignKey, "GET", "/v1/device/policy", foreign.AccessToken, foreign.Nonce, nil), 202)
	expect(t, f.call(t, ownKey, "GET", "/v1/device/policy", own.AccessToken, own.Nonce, nil), 403)
	expect(t, f.call(t, foreignKey, "POST", path, token, nonce, body), 403)
	expect(t, f.call(t, fresh, "POST", path, own.AccessToken, nonce, body), 401)
	// It is a cleanup-only credential: a disabled account still cannot enroll or receive config.
	enroll, _ := json.Marshal(Request{random(), identity.PublicJWK(&fresh.PublicKey), []string{"engine-config.v1", "tun.lease.v1"}})
	expect(t, f.call(t, fresh, "POST", "/v1/devices/enroll", token, nonce, enroll), 403)
}
func TestCleanupShapeAndChallengeAdmission(t *testing.T) {
	f := newFixture(t, 1)
	fresh := key(t)
	token := f.token(fresh)
	path := "/v1/identity/devices/revoke"
	for _, request := range []Cleanup{{"short", []string{random()}}, {random(), nil}, {random(), []string{"short"}}} {
		body, _ := json.Marshal(request)
		expect(t, f.call(t, fresh, "POST", path, token, "", body), 401)
	}
	duplicate := random()
	body, _ := json.Marshal(Cleanup{random(), []string{duplicate, duplicate}})
	expect(t, f.call(t, fresh, "POST", path, token, "", body), 401)
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = random()
	}
	body, _ = json.Marshal(Cleanup{random(), tooMany})
	expect(t, f.call(t, fresh, "POST", path, token, "", body), 401)
	for i := 0; i < 32; i++ {
		k := key(t)
		bearer := f.token(k)
		body, _ = json.Marshal(Cleanup{random(), []string{random()}})
		expect(t, f.call(t, k, "POST", path, bearer, "", body), 401)
	}
	body, _ = json.Marshal(Cleanup{random(), []string{random()}})
	expect(t, f.call(t, fresh, "POST", path, token, "", body), 503)
	f.now = f.now.Add(181 * time.Second)
	f.api.Clock = func() time.Time { return f.now }
	expect(t, f.call(t, fresh, "POST", path, token, "", body), 401)
	var count int
	fixtureOwner.QueryRow(`SELECT count(*) FROM identity_challenges`).Scan(&count)
	if count != 1 {
		t.Fatal("expired challenges retained or admission unbounded")
	}
}
