//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

var fixtureOwner *sql.DB
var fixtureAPI, fixturePublisher *sql.DB
var fixtureAPIDSN, fixturePublisherDSN string
var b64 = base64.RawURLEncoding

func TestMain(m *testing.M) {
	dsn := os.Getenv("SYN443_TEST_DATABASE")
	if dsn == "" {
		panic("temporary PostgreSQL fixture required")
	}
	u, e := url.Parse(dsn)
	if e != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" {
		panic("loopback fixture required")
	}
	fixtureOwner, e = sql.Open("pgx", dsn)
	if e != nil {
		panic("fixture database")
	}
	if _, e = fixtureOwner.Exec(Schema); e != nil {
		panic(e)
	}
	for _, item := range []struct {
		name   string
		target **sql.DB
	}{{"syn443_identity_api", &fixtureAPI}, {"syn443_identity_publisher", &fixturePublisher}} {
		password := random()
		var statement string
		if e = fixtureOwner.QueryRow(`SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOBYPASSRLS PASSWORD %L',$1::text,$2::text)`, item.name, password).Scan(&statement); e != nil {
			panic(e)
		}
		if _, e = fixtureOwner.Exec(statement); e != nil {
			panic("fixture role")
		}
		copy := *u
		copy.User = url.UserPassword(item.name, password)
		if item.name == "syn443_identity_api" {
			fixtureAPIDSN = copy.String()
		} else {
			fixturePublisherDSN = copy.String()
		}
		*item.target, e = sql.Open("pgx", copy.String())
		if e != nil {
			panic("runtime role connection")
		}
		(*item.target).SetMaxOpenConns(4)
	}
	if _, e = fixtureOwner.Exec(Roles); e != nil {
		panic(e)
	}
	code := m.Run()
	fixtureAPI.Close()
	fixturePublisher.Close()
	fixtureOwner.Close()
	os.Exit(code)
}

type verifier struct {
	mu         sync.Mutex
	principals map[string]identity.Principal
}

func (v *verifier) Verify(_ context.Context, token string, _ time.Time) (identity.Principal, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	p, ok := v.principals[token]
	if !ok {
		return p, identity.ErrInvalid
	}
	return p, nil
}

type fixture struct {
	store, worker *Store
	api           *API
	v             *verifier
	grant         Grant
	now           time.Time
	key           *ecdsa.PrivateKey
	origin        string
	encryption    []byte
}

func newFixture(t *testing.T, limit int) *fixture {
	t.Helper()
	ctx := context.Background()
	_, e := fixtureOwner.Exec(`TRUNCATE identity_accounts,identity_devices,identity_challenges,identity_sessions,identity_requests,identity_refresh_history,identity_replays,identity_revocations,identity_owner_revocations CASCADE;UPDATE identity_clock SET second=0`)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc := make([]byte, 32)
	rand.Read(enc)
	store, _ := NewStore(fixtureAPI, enc)
	worker, _ := NewStore(fixturePublisher, enc)
	now := time.Unix(1800000000, 0)
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	sum := sha256.Sum256(engine)
	grant := Grant{Issuer: "https://id.example.invalid/realms/test", Subject: "synthetic-user", DeviceLimit: limit, Until: now.Unix() + 7200, Template: policy.Payload{SchemaVersion: 1, Operation: "configure", Revision: 1, Audience: "syn443-device", RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1"}, AlgorithmRevision: "m1-local-v1", EngineConfigB64: b64.EncodeToString(engine), ContentHash: hex.EncodeToString(sum[:]), Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.org/generate_204", Required: true}}}}}
	if e = Authorize(ctx, fixtureOwner, grant, now); e != nil {
		t.Fatal(e)
	}
	v := &verifier{principals: map[string]identity.Principal{}}
	origin := "https://api.example.invalid"
	api, e := NewAPI(store, v, origin, map[string]*ecdsa.PublicKey{"fixture-root": &key.PublicKey}, false)
	if e != nil {
		t.Fatal(e)
	}
	api.Clock = func() time.Time { return now }
	return &fixture{store, worker, api, v, grant, now, key, origin, enc}
}
func (f *fixture) token(key *ecdsa.PrivateKey) string {
	token := random()
	thumb, _ := identity.PublicJWK(&key.PublicKey).Thumbprint()
	f.v.mu.Lock()
	f.v.principals[token] = identity.Principal{Issuer: f.grant.Issuer, Subject: f.grant.Subject, Thumbprint: thumb}
	f.v.mu.Unlock()
	return token
}
func signed(t *testing.T, key *ecdsa.PrivateKey, method, uri, token, nonce string, body []byte, now time.Time) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": identity.PublicJWK(&key.PublicKey)})
	hash := ""
	if method == "POST" {
		hash = identity.Hash(body)
	}
	c, _ := json.Marshal(identity.ProofClaims{Jti: random(), Htm: method, Htu: uri, Iat: now.Unix(), Ath: identity.Hash([]byte(token)), Nonce: nonce, RequestHash: hash})
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sum := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + b64.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}
func (f *fixture) call(t *testing.T, key *ecdsa.PrivateKey, method, path, token, nonce string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	proof := signed(t, key, method, f.origin+path, token, nonce, body, f.now)
	return f.rawCall(method, path, token, proof, body)
}
func (f *fixture) rawCall(method, path, token, proof string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, f.origin+path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", proof)
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	return w
}
func expect(t *testing.T, r *httptest.ResponseRecorder, status int) {
	t.Helper()
	if r.Code != status {
		t.Fatalf("status %d expected %d, fixed error: %s", r.Code, status, r.Body.String())
	}
}
func (f *fixture) register(t *testing.T, key *ecdsa.PrivateKey) (Session, []byte, string) {
	t.Helper()
	token := f.token(key)
	raw, _ := json.Marshal(Request{random(), identity.PublicJWK(&key.PublicKey), []string{"engine-config.v1", "tun.lease.v1"}})
	r := f.call(t, key, "POST", "/v1/devices/enroll", token, "", raw)
	expect(t, r, 401)
	nonce := r.Header().Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("nonce challenge")
	}
	r = f.call(t, key, "POST", "/v1/devices/enroll", token, nonce, raw)
	expect(t, r, 200)
	var session Session
	if identity.Decode(r.Body.Bytes(), &session, true) != nil {
		t.Fatal("session shape")
	}
	return session, raw, token
}
func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func (f *fixture) publisher() *Publisher {
	return &Publisher{Store: f.worker, Verifier: f.v, Grants: map[string]Grant{Owner(f.grant.Issuer, f.grant.Subject): f.grant}, KeyID: "fixture-root", Key: f.key, Origin: f.origin}
}

func TestEnrollmentSessionAndPublication(t *testing.T) {
	f := newFixture(t, 2)
	k := key(t)
	session, raw, token := f.register(t, k)
	if session.DeviceID == "" || session.AccessToken == session.RefreshToken || session.AccessUntilMs != f.now.Add(10*time.Minute).UnixMilli() {
		t.Fatal("session limits")
	}
	var challenge string
	if e := fixtureOwner.QueryRow(`SELECT nonce FROM identity_challenges`).Scan(&challenge); e != nil {
		t.Fatal(e)
	}
	duplicate := f.call(t, k, "POST", "/v1/devices/enroll", token, challenge, raw)
	expect(t, duplicate, 200)
	var again Session
	json.Unmarshal(duplicate.Body.Bytes(), &again)
	if again != session {
		t.Fatal("non-idempotent enrollment")
	}
	changed := bytes.Replace(raw, []byte("tun.lease.v1"), []byte("policy.es256.v1"), 1)
	expect(t, f.call(t, k, "POST", "/v1/devices/enroll", token, challenge, changed), 401)
	proof := signed(t, k, "GET", f.origin+"/v1/device/policy", session.AccessToken, session.Nonce, nil, f.now)
	expect(t, f.rawCall("GET", "/v1/device/policy", session.AccessToken, proof, nil), 202)
	expect(t, f.rawCall("GET", "/v1/device/policy", session.AccessToken, proof, nil), 401)
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	r := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, r, 200)
	p, e := policy.Verify(r.Body.String(), f.api.Roots, session.DeviceID, f.now)
	if e != nil || p.Revision != 1 || p.EngineConfigB64 != f.grant.Template.EngineConfigB64 {
		t.Fatal("wrong assigned publication", e)
	}
	if _, e = policy.Verify(r.Body.String(), f.api.Roots, "other-device", f.now); e == nil {
		t.Fatal("cross-device publication")
	}
	// New process objects retain nonce, replay, publication and opaque credentials in PostgreSQL.
	newStore, _ := NewStore(fixtureAPI, f.encryption)
	f.api.Store = newStore
	expect(t, f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil), 200)
	expect(t, f.rawCall("GET", "/v1/device/policy", session.AccessToken, proof, nil), 401)
	wrong := key(t)
	expect(t, f.call(t, wrong, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil), 403)
	expect(t, f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, "wrong", nil), 401)
	// Tokens and publications must not occur as plaintext in retained receipt/cache rows.
	var receipt, reply, pub []byte
	if e = fixtureOwner.QueryRow(`SELECT d.receipt,r.response,d.publication FROM identity_devices d JOIN identity_requests r ON r.owner=d.owner LIMIT 1`).Scan(&receipt, &reply, &pub); e != nil {
		t.Fatal(e)
	}
	for _, blob := range [][]byte{receipt, reply, pub} {
		for _, secret := range []string{token, session.AccessToken, session.RefreshToken, f.grant.Template.EngineConfigB64} {
			if bytes.Contains(blob, []byte(secret)) {
				t.Fatal("plaintext persisted")
			}
		}
	}
	if _, e = f.store.Open(receipt, "wrong-purpose"); e == nil {
		t.Fatal("AEAD purpose swap")
	}
}
func TestRefreshRotationReuseAndRevoke(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	s, _, _ := f.register(t, k)
	body, _ := json.Marshal(map[string]string{"requestId": random()})
	path := "/v1/device/session/refresh"
	r := f.call(t, k, "POST", path, s.RefreshToken, s.Nonce, body)
	expect(t, r, 200)
	var next Session
	json.Unmarshal(r.Body.Bytes(), &next)
	if next.Generation != 1 || next.RefreshToken == s.RefreshToken || next.RefreshUntilMs != s.RefreshUntilMs {
		t.Fatal("refresh family")
	}
	// Lost response: old proof nonce gets an authenticated challenge, then the same request returns the same result.
	r = f.call(t, k, "POST", path, s.RefreshToken, s.Nonce, body)
	expect(t, r, 401)
	if r.Header().Get("DPoP-Nonce") != next.Nonce {
		t.Fatal("rotation nonce")
	}
	r = f.call(t, k, "POST", path, s.RefreshToken, next.Nonce, body)
	expect(t, r, 200)
	var duplicate Session
	json.Unmarshal(r.Body.Bytes(), &duplicate)
	if duplicate != next {
		t.Fatal("lost response retry")
	}
	expect(t, f.call(t, k, "GET", "/v1/device/policy", s.AccessToken, next.Nonce, nil), 403)
	other, _ := json.Marshal(map[string]string{"requestId": random()})
	r = f.call(t, k, "POST", path, s.RefreshToken, next.Nonce, other)
	expect(t, r, 401)
	if !strings.Contains(r.Body.String(), "session_reuse") {
		t.Fatal("reuse not classified")
	}
	expect(t, f.call(t, k, "POST", path, next.RefreshToken, next.Nonce, other), 403)
	// Reauthentication creates a new family for the same device; explicit revoke is durably idempotent.
	s2, _, _ := f.register(t, k)
	if s2.DeviceID != s.DeviceID {
		t.Fatal("device identity changed")
	}
	body, _ = json.Marshal(map[string]string{"requestId": random()})
	expect(t, f.call(t, k, "POST", "/v1/device/revoke", s2.AccessToken, s2.Nonce, body), 204)
	expect(t, f.call(t, k, "POST", "/v1/device/revoke", s2.AccessToken, s2.Nonce, body), 204)
	expect(t, f.call(t, k, "GET", "/v1/device/policy", s2.AccessToken, s2.Nonce, nil), 403)
	expect(t, f.call(t, k, "POST", path, s2.RefreshToken, s2.Nonce, other), 403)
	// The API role cannot revive the key, even through direct SQL.
	if _, e := fixtureAPI.Exec(`UPDATE identity_devices SET active=true WHERE id=$1`, s2.DeviceID); e == nil {
		t.Fatal("revived device")
	}
}
func TestConcurrentDeviceLimitAndReplay(t *testing.T) {
	f := newFixture(t, 1)
	keys := []*ecdsa.PrivateKey{key(t), key(t)}
	raws := make([][]byte, 2)
	tokens := make([]string, 2)
	nonces := make([]string, 2)
	for i, k := range keys {
		tokens[i] = f.token(k)
		raws[i], _ = json.Marshal(Request{random(), identity.PublicJWK(&k.PublicKey), []string{"engine-config.v1", "tun.lease.v1"}})
		r := f.call(t, k, "POST", "/v1/devices/enroll", tokens[i], "", raws[i])
		expect(t, r, 401)
		nonces[i] = r.Header().Get("DPoP-Nonce")
	}
	status := make(chan int, 2)
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status <- f.call(t, keys[i], "POST", "/v1/devices/enroll", tokens[i], nonces[i], raws[i]).Code
		}(i)
	}
	wg.Wait()
	close(status)
	counts := map[int]int{}
	for s := range status {
		counts[s]++
	}
	if counts[200] != 1 || counts[403] != 1 {
		t.Fatal("non-atomic device limit", counts)
	}
	var count int
	fixtureOwner.QueryRow(`SELECT count(*) FROM identity_devices`).Scan(&count)
	if count != 1 {
		t.Fatal("extra device")
	}
}
func TestPublisherScopeAndDatabaseRoles(t *testing.T) {
	f := newFixture(t, 2)
	ctx := context.Background()
	if f.store.RuntimeRole(ctx, false) != nil || f.worker.RuntimeRole(ctx, true) != nil {
		t.Fatal("valid restricted role rejected")
	}
	ownerStore, _ := NewStore(fixtureOwner, f.encryption)
	if f.store.RuntimeRole(ctx, true) == nil || f.worker.RuntimeRole(ctx, false) == nil || ownerStore.RuntimeRole(ctx, false) == nil {
		t.Fatal("unsafe or wrong runtime role accepted")
	}
	k := key(t)
	s, _, _ := f.register(t, k)
	for _, statement := range []string{`UPDATE identity_accounts SET enabled=false`, `UPDATE identity_accounts SET grant_hash='changed'`, `UPDATE identity_devices SET approved=true`, `UPDATE identity_devices SET publication='x'`, `UPDATE identity_devices SET owner='changed'`, `DELETE FROM identity_devices`, `CREATE TABLE unauthorized(x int)`} {
		if _, e := fixtureAPI.Exec(statement); e == nil {
			t.Fatal("API exceeded authority", statement)
		}
	}
	for _, statement := range []string{`SELECT * FROM identity_sessions`, `UPDATE identity_accounts SET enabled=false`, `UPDATE identity_devices SET active=false`, `INSERT INTO identity_devices(id,owner,jkt,request_body,receipt) VALUES('x','x','x','x','x')`} {
		if _, e := fixturePublisher.Exec(statement); e == nil {
			t.Fatal("publisher exceeded authority", statement)
		}
	}
	// A compromised API can create a pending row, but cannot forge the independent key-bound receipt.
	bad := key(t)
	thumb, _ := identity.PublicJWK(&bad.PublicKey).Thumbprint()
	body, _ := json.Marshal(Request{random(), identity.PublicJWK(&bad.PublicKey), []string{"engine-config.v1", "tun.lease.v1"}})
	receipt, _ := json.Marshal(Receipt{Token: f.token(k), Proof: signed(t, bad, "POST", f.origin+"/v1/devices/enroll", "other", random(), body, f.now), URI: f.origin + "/v1/devices/enroll", AcceptedAt: f.now.Unix()})
	fake := random()
	if _, e := fixtureAPI.Exec(`INSERT INTO identity_devices(id,owner,jkt,request_body,receipt) VALUES($1,$2,$3,$4,$5)`, fake, Owner(f.grant.Issuer, f.grant.Subject), thumb, body, f.store.Seal(receipt, "receipt/v1/"+fake)); e != nil {
		t.Fatal(e)
	}
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	var approved bool
	fixtureOwner.QueryRow(`SELECT approved FROM identity_devices WHERE id=$1`, fake).Scan(&approved)
	if approved {
		t.Fatal("forged device signed")
	}
	expect(t, f.call(t, k, "GET", "/v1/device/policy", s.AccessToken, s.Nonce, nil), 200)
	// Changed grant hashes, disabled accounts and removed worker assignments cannot produce a new policy.
	if _, e := fixtureOwner.Exec(`UPDATE identity_accounts SET grant_hash='changed'; UPDATE identity_devices SET refresh_after=0`); e != nil {
		t.Fatal(e)
	}
	if e := f.publisher().RunOnce(context.Background(), f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var revision int64
	fixtureOwner.QueryRow(`SELECT revision FROM identity_devices WHERE id=$1`, s.DeviceID).Scan(&revision)
	if revision != 1 {
		t.Fatal("unapproved assignment published")
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false`); e != nil {
		t.Fatal(e)
	}
	expect(t, f.call(t, k, "GET", "/v1/device/policy", s.AccessToken, s.Nonce, nil), 403)
}
func TestClockExpiryAndAdmission(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	s, _, _ := f.register(t, k)
	fenced, e := f.store.Now(context.Background(), f.now.Add(601*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	back, e := f.store.Now(context.Background(), f.now)
	if e != nil || !back.Equal(fenced) {
		t.Fatal("clock rollback")
	}
	f.now = fenced
	f.api.Clock = func() time.Time { return f.now }
	expect(t, f.call(t, k, "GET", "/v1/device/policy", s.AccessToken, s.Nonce, nil), 403)
	f.now = f.now.Add(86400 * time.Second)
	body, _ := json.Marshal(map[string]string{"requestId": random()})
	expect(t, f.call(t, k, "POST", "/v1/device/session/refresh", s.RefreshToken, s.Nonce, body), 403)
	for i := 0; i < 120; i++ {
		f.api.admit("test-ip", f.now)
	}
	if f.api.admit("test-ip", f.now) {
		t.Fatal("rate limit")
	}
	for i := 0; i < 16; i++ {
		f.api.slots <- struct{}{}
	}
	expect(t, f.rawCall("GET", "/v1/device/policy", s.AccessToken, "invalid", nil), 503)
	for i := 0; i < 16; i++ {
		<-f.api.slots
	}
	if _, e = NewAPI(f.store, f.v, "http://api.example.invalid", f.api.Roots, false); e == nil {
		t.Fatal("insecure origin")
	}
}

func TestHTTPBoundariesAndIdempotencyConflict(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	s, raw, token := f.register(t, k)
	var nonce string
	fixtureOwner.QueryRow(`SELECT nonce FROM identity_challenges`).Scan(&nonce)
	var req Request
	json.Unmarshal(raw, &req)
	req.Capabilities = append(req.Capabilities, "policy.es256.v1")
	changed, _ := json.Marshal(req)
	expect(t, f.call(t, k, "POST", "/v1/devices/enroll", token, nonce, changed), 409)
	unknown := random()
	expect(t, f.call(t, k, "POST", "/v1/devices/enroll", unknown, "", raw), 401)
	wrong := key(t)
	expect(t, f.call(t, wrong, "POST", "/v1/devices/enroll", token, "", raw), 403)
	for _, body := range [][]byte{[]byte(`{"requestId":"first","requestId":"second"}`), []byte(`{"RequestID":"case"}`), []byte(`{"requestId":"short"}`)} {
		expect(t, f.call(t, k, "POST", "/v1/device/revoke", s.AccessToken, s.Nonce, body), 401)
	}
	for _, path := range []string{"/unknown", "/v1/device/policy?x=1", "/v1/device/%70olicy", "/v1/device/policy?"} {
		expect(t, f.rawCall("GET", path, s.AccessToken, "invalid", nil), 404)
	}
	for _, kind := range []string{"auth", "proof", "content", "oversized", "get-body", "remote", "no-dpop"} {
		r := httptest.NewRequest("POST", f.origin+"/v1/device/revoke", strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "DPoP "+s.AccessToken)
		r.Header.Set("DPoP", "invalid")
		r.Header.Set("Content-Type", "application/json")
		switch kind {
		case "auth":
			r.Header.Add("Authorization", "DPoP duplicate")
		case "proof":
			r.Header.Add("DPoP", "duplicate")
		case "content":
			r.Header.Set("Content-Type", "text/plain")
		case "oversized":
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 8193)))
		case "get-body":
			r.Method = "GET"
			r.URL.Path = "/v1/device/policy"
		case "remote":
			r.RemoteAddr = "invalid"
		case "no-dpop":
			r.Header.Set("Authorization", "Bearer "+s.AccessToken)
		}
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		expect(t, w, 401)
		if strings.Contains(w.Body.String(), s.AccessToken) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("sensitive response")
		}
	}
	for i := 0; i < 120; i++ {
		f.api.admit("127.0.0.1", f.now)
	}
	expect(t, f.rawCall("GET", "/v1/device/policy", s.AccessToken, "invalid", nil), 429)
}
func TestRenewalAndFailedPublicationKeepLastAuthorizedSnapshot(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	s, _, _ := f.register(t, k)
	pub := f.publisher()
	ctx := context.Background()
	if e := pub.RunOnce(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(1801 * time.Second)
	if e := pub.RunOnce(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	var revision int64
	var ciphertext []byte
	fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, s.DeviceID).Scan(&revision, &ciphertext)
	if revision != 2 {
		t.Fatal("scheduled renewal")
	}
	delete(pub.Grants, Owner(f.grant.Issuer, f.grant.Subject))
	fixtureOwner.Exec(`UPDATE identity_devices SET refresh_after=0`)
	if e := pub.RunOnce(ctx, f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var retained []byte
	var problem string
	fixtureOwner.QueryRow(`SELECT revision,publication,publication_error FROM identity_devices WHERE id=$1`, s.DeviceID).Scan(&revision, &retained, &problem)
	if revision != 2 || !bytes.Equal(ciphertext, retained) || problem != "temporarily_unavailable" {
		t.Fatal("failed renewal replaced authorized publication")
	}
	// A corrupted receipt cannot turn a pending enrollment into an approved device.
	f = newFixture(t, 1)
	s, _, _ = f.register(t, key(t))
	fixtureAPI.Exec(`UPDATE identity_devices SET receipt=$1`, []byte("invalid"))
	if e := f.publisher().RunOnce(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	var approved bool
	fixtureOwner.QueryRow(`SELECT approved FROM identity_devices WHERE id=$1`, s.DeviceID).Scan(&approved)
	if approved {
		t.Fatal("corrupted receipt accepted")
	}
}
