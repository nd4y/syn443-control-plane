//go:build postgres

package catalog

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type adminVerifier struct{ Principal identity.Principal }

func (v *adminVerifier) Verify(context.Context, string, time.Time) (identity.Principal, error) {
	return v.Principal, nil
}

type adminFixture struct {
	API      *API
	Worker   *Store
	Actor    Actor
	Now      time.Time
	Key      *ecdsa.PrivateKey
	Verifier *adminVerifier
}

func adminHTTPFixture(t *testing.T) *adminFixture {
	t.Helper()
	store, worker, actor, now := databaseFixture(t)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	thumb, _ := identity.PublicJWK(&key.PublicKey).Thumbprint()
	v := &adminVerifier{identity.Principal{Issuer: "https://identity.example.invalid/realms/test", Subject: "synthetic-admin", Thumbprint: thumb, Expires: now.Add(5 * time.Minute).Unix(), AuthTime: now.Unix(), ACR: "urn:syn443:loa:2", Methods: []string{"otp"}, Scope: "openid syn443.control"}}
	actor.ID = identity.Hash([]byte(v.Principal.Issuer + "\x00" + v.Principal.Subject))
	if _, e = fixtureOwner.Exec(`UPDATE catalog_acl SET actor=$1`, actor.ID); e != nil {
		t.Fatal(e)
	}
	api, e := NewAPI(store, v, "https://control.example.invalid", "urn:syn443:loa:2", false)
	if e != nil {
		t.Fatal(e)
	}
	api.Clock = func() time.Time { return now }
	return &adminFixture{api, worker, actor, now, key, v}
}

const adminToken = "synthetic-control-access-token-not-a-credential"

func (f *adminFixture) proof(t *testing.T, raw []byte) string {
	t.Helper()
	b64 := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": identity.PublicJWK(&f.Key.PublicKey)})
	id, _ := random()
	claims, _ := json.Marshal(identity.ProofClaims{Jti: id, Htm: "POST", Htu: f.API.Origin + "/v1/control/action", Iat: f.Now.Unix(), Ath: identity.Hash([]byte(adminToken)), RequestHash: identity.Hash(raw)})
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	r, s, e := ecdsa.Sign(rand.Reader, f.Key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + b64.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}
func (f *adminFixture) request(raw []byte, proof string) *http.Request {
	r := httptest.NewRequest("POST", f.API.Origin+"/v1/control/action", bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Authorization", "DPoP "+adminToken)
	r.Header.Set("DPoP", proof)
	r.Header.Set("Content-Type", "application/json")
	return r
}
func (f *adminFixture) call(t *testing.T, action string, payload any, status int) []byte {
	t.Helper()
	id, _ := random()
	body, _ := json.Marshal(payload)
	raw, _ := json.Marshal(Action{Version: 1, Action: action, RequestID: id, Payload: body})
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, f.request(raw, f.proof(t, raw)))
	if w.Code != status {
		t.Fatalf("%s status%d expected%d; fixed reply:%s", action, w.Code, status, w.Body.String())
	}
	return w.Body.Bytes()
}
func TestSQLAdminHTTPProofScopeMFAReplayAndClosedDTO(t *testing.T) {
	f := adminHTTPFixture(t)
	source := sourceExample(f.Now)
	f.call(t, "source.put", map[string]any{"source": source, "secret": SecretPatch{Operation: "keep"}}, 200)
	f.call(t, "source.get", map[string]any{"id": source.ID}, 200)
	raw := []byte(`{"version":1,"action":"source.get","requestId":"fixed-request-id","payload":{"id":"source-a"}}`)
	proof := f.proof(t, raw)
	r := f.request(raw, proof)
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	f.API.ServeHTTP(w, f.request(raw, proof))
	if w.Code != 403 {
		t.Fatal("DPoP replay accepted")
	}
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Origin", "https://untrusted.example.invalid") }, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+adminToken) }, func(r *http.Request) { r.Header.Del("DPoP") }, func(r *http.Request) { r.Header.Add("DPoP", "duplicate") }, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }} {
		r = f.request(raw, f.proof(t, raw))
		mutate(r)
		w = httptest.NewRecorder()
		f.API.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("request boundary", w.Code)
		}
	}
	f.Verifier.Principal.Scope = "openid"
	f.call(t, "source.get", map[string]any{"id": source.ID}, 403)
	f.Verifier.Principal.Scope = "syn443.control"
	f.Verifier.Principal.Methods = []string{"pwd"}
	f.call(t, "source.shares.put", map[string]any{"id": source.ID, "revision": 1, "shares": Shares{Recipients: []Recipient{}}}, 403)
	f.Verifier.Principal.Methods = []string{"otp"}
	for _, action := range []string{"source.list", "source.snapshot", "job.get", "job.list", "source.get", "source.shares.get", "source.put", "source.sync", "source.import", "source.shares.put", "source.review", "resource.get", "resource.put", "job.cancel", "unsupported"} {
		f.call(t, action, map[string]any{"unknown": true}, 400)
	}
	for _, bad := range []string{`{"version":1,"version":1,"action":"source.get","payload":{}}`, `{"version":2,"action":"source.get","requestId":"x","payload":{}}`, `{"Version":1,"action":"source.get","requestId":"x","payload":{}}`} {
		w = httptest.NewRecorder()
		f.API.ServeHTTP(w, f.request([]byte(bad), f.proof(t, []byte(bad))))
		if w.Code != 400 {
			t.Fatal("closed envelope", w.Code)
		}
	}
	r = f.request(raw, f.proof(t, []byte("different body")))
	w = httptest.NewRecorder()
	f.API.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("proof did not bind body")
	}
	f.Verifier.Principal.Thumbprint = identity.Hash([]byte("other-key"))
	f.call(t, "source.get", map[string]any{"id": source.ID}, 403)
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl`); e != nil {
		t.Fatal(e)
	}
	f.Verifier.Principal.Thumbprint, _ = identity.PublicJWK(&f.Key.PublicKey).Thumbprint()
	f.call(t, "source.get", map[string]any{"id": source.ID}, 403)
}

func TestSQLAdminJobHistoryIsBoundedAndScopedToSelectedSource(t *testing.T) {
	f := adminHTTPFixture(t)
	ctx := context.Background()
	store := f.API.Store
	source := mustSource(t, store, f.Actor, sourceExample(f.Now), "history-source", f.Now)
	raw := []byte("http://proxy.example.invalid:443")
	for index := 0; index < 21; index++ {
		request := fmt.Sprintf("history-%02d", index)
		job, e := store.Queue(ctx, f.Actor, source.ID, source.Revision, request, raw, f.Now)
		if e != nil {
			t.Fatal(e)
		}
		if e = store.Cancel(ctx, f.Actor, job.ID, request+"-cancel", f.Now); e != nil {
			t.Fatal(e)
		}
	}
	f.Now = f.Now.Add(time.Second)
	f.API.Clock = func() time.Time { return f.Now }
	current, e := store.Queue(ctx, f.Actor, source.ID, source.Revision, "history-current", raw, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	other := sourceExample(f.Now)
	other.ID = "foreign-source"
	other = mustSource(t, store, f.Actor, other, "other-history-source", f.Now)
	foreign, e := store.Queue(ctx, f.Actor, other.ID, other.Revision, "other-history-current", raw, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	read := func(after string) JobHistoryPage {
		t.Helper()
		wire := f.call(t, "job.list", map[string]string{"sourceId": source.ID, "after": after}, 200)
		if bytes.Contains(wire, raw) || bytes.Contains(wire, []byte(foreign.ID)) || bytes.Contains(wire, []byte("history-current")) {
			t.Fatal("another source, request identifier or raw job input was exposed")
		}
		var page JobHistoryPage
		if e := json.Unmarshal(wire, &page); e != nil || page.SourceID != source.ID || page.ObservedAt != f.Now.Unix() {
			t.Fatal("bad scoped history page", e)
		}
		return page
	}
	first := read("")
	if len(first.Jobs) != 20 || first.Next != first.Jobs[19].Job.ID || first.Jobs[0].Job.ID != current.ID ||
		first.Jobs[0].Job.Phase != "queued" || first.Jobs[0].NextAttemptAt != f.Now.Unix() {
		t.Fatal("first page, backlog state or ordering is wrong")
	}
	second := read(first.Next)
	if len(second.Jobs) != 2 || second.Next != "" || second.Jobs[0].Job.ID >= first.Next ||
		second.Jobs[0].Job.Phase != "cancelled" || second.Jobs[0].NextAttemptAt != 0 {
		t.Fatal("stable cursor did not resume at the exact prior boundary")
	}
	f.call(t, "job.list", map[string]string{"sourceId": source.ID, "after": foreign.ID}, 403)
	f.call(t, "job.list", map[string]string{"sourceId": source.ID, "after": "invalid/path"}, 400)
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, f.Actor.ID); e != nil {
		t.Fatal(e)
	}
	f.call(t, "job.list", map[string]string{"sourceId": source.ID}, 403)
}

func TestControlHTTPNetworkDraftIsPrivateScopedAndNeverAnActivePublication(t *testing.T) {
	f := adminHTTPFixture(t)
	draft := draftExample()
	f.call(t, "configuration.draft.get", map[string]any{"id": draft.ID}, 403)
	response := f.call(t, "configuration.draft.put", map[string]any{"draft": draft}, 200)
	var saved NetworkDraft
	if json.Unmarshal(response, &saved) != nil || saved.Revision != 1 || saved.SavedAt != f.Now.Unix() {
		t.Fatal("draft HTTP receipt")
	}
	read := f.call(t, "configuration.draft.get", map[string]any{"id": draft.ID}, 200)
	if string(read) != string(response) {
		t.Fatal("private readback changed draft")
	}
	f.call(t, "configuration.draft.put", map[string]any{"draft": draft}, 409)
	f.call(t, "configuration.draft.put", map[string]any{"draft": saved}, 400) // Server-owned timestamp must not be asserted by a caller.
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, f.Actor.ID); e != nil {
		t.Fatal(e)
	}
	f.call(t, "configuration.draft.get", map[string]any{"id": draft.ID}, 403)
	var count int
	if e := fixtureOwner.QueryRow(`SELECT (SELECT count(*) FROM catalog_sources)+(SELECT count(*) FROM catalog_resources)+(SELECT count(*) FROM catalog_outbox)`).Scan(&count); e != nil || count != 0 {
		t.Fatal("draft mutated source or publication work", e)
	}
}

func TestControlHTTPNetworkDraftRetriesUseFreshProofAndExactOperation(t *testing.T) {
	f := adminHTTPFixture(t)
	body, _ := json.Marshal(map[string]any{"draft": draftExample()})
	raw, _ := json.Marshal(Action{Version: 1, Action: "configuration.draft.put", RequestID: "stable-draft-operation", Payload: body})
	var original []byte
	for range 2 {
		response := httptest.NewRecorder()
		f.API.ServeHTTP(response, f.request(raw, f.proof(t, raw)))
		if response.Code != 200 {
			t.Fatal("fresh proof retry", response.Code)
		}
		if original != nil && string(original) != response.Body.String() {
			t.Fatal("lost reply changed durable receipt")
		}
		original = append([]byte(nil), response.Body.Bytes()...)
	}
	proof := f.proof(t, raw)
	first := httptest.NewRecorder()
	f.API.ServeHTTP(first, f.request(raw, proof))
	second := httptest.NewRecorder()
	f.API.ServeHTTP(second, f.request(raw, proof))
	if first.Code != 200 || second.Code != 403 {
		t.Fatal("proof replay accepted")
	}
	var revision int64
	if e := fixtureOwner.QueryRow(`SELECT revision FROM catalog_network_drafts WHERE actor=$1`, f.Actor.ID).Scan(&revision); e != nil || revision != 1 {
		t.Fatal("retry mutated draft", e)
	}
}

func TestSQLAdminHTTPCatalogActionsAndManualWorker(t *testing.T) {
	f := adminHTTPFixture(t)
	source := sourceExample(f.Now)
	var created Source
	json.Unmarshal(f.call(t, "source.put", map[string]any{"source": source, "secret": SecretPatch{Operation: "keep"}}, 200), &created)
	f.call(t, "source.shares.put", map[string]any{"id": source.ID, "revision": created.Revision, "shares": Shares{Recipients: []Recipient{{Kind: "user", ID: "user-b"}}}}, 200)
	f.call(t, "source.shares.get", map[string]any{"id": source.ID}, 200)
	worker := Worker{Store: f.Worker, Clock: func() time.Time { return f.Now }}
	lines := "http://one.example.invalid:443\nhttp://two.example.invalid:443\nhttp://three.example.invalid:443"
	f.call(t, "source.import", map[string]any{"id": source.ID, "revision": created.Revision, "data": []byte(lines)}, 200)
	if j, e := worker.ProcessOne(context.Background()); e != nil || j.Phase != "succeeded" {
		t.Fatal("manual worker", e)
	}
	first, e := f.API.Store.GetSource(context.Background(), f.Actor, source.ID, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	f.call(t, "source.list", map[string]any{"owner": source.Owner, "after": ""}, 200)
	view := f.call(t, "source.snapshot", map[string]any{"id": source.ID, "snapshot": ""}, 200)
	if bytes.Contains(view, []byte("outbound")) || bytes.Contains(view, []byte("one.example.invalid")) {
		t.Fatal("inventory revealed source credentials")
	}
	f.call(t, "source.import", map[string]any{"id": source.ID, "revision": created.Revision, "data": []byte(strings.Split(lines, "\n")[0])}, 200)
	if j, e := worker.ProcessOne(context.Background()); e != nil || j.Phase != "succeeded" {
		t.Fatal("manual quarantine worker", e)
	}
	current, e := f.API.Store.GetSource(context.Background(), f.Actor, source.ID, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	var hash string
	if e = fixtureOwner.QueryRow(`SELECT content_hash FROM catalog_snapshots WHERE id=$1`, current.CandidateSnapshot).Scan(&hash); e != nil {
		t.Fatal(e)
	}
	f.call(t, "source.review", Review{SourceID: source.ID, SourceRevision: created.Revision, Candidate: current.CandidateSnapshot, Hash: hash, Active: first.ActiveSnapshot, Approve: true}, 200)
	f.call(t, "resource.put", map[string]any{"resource": resourceExample(), "secret": resourceSecret("https://panel.example.invalid"), "impactHash": ""}, 200)
	f.call(t, "resource.get", map[string]any{"id": "panel-a"}, 200)
	server := sourceExample(f.Now)
	server.ID = "server-source"
	server.Mode = "server"
	var external Source
	json.Unmarshal(f.call(t, "source.put", map[string]any{"source": server, "secret": SecretPatch{Operation: "replace", Value: []byte(`{"url":"https://subscription.example.invalid"}`)}}, 200), &external)
	var job Job
	json.Unmarshal(f.call(t, "source.sync", map[string]any{"id": server.ID, "revision": external.Revision}, 200), &job)
	f.call(t, "job.get", map[string]any{"id": job.ID}, 200)
	f.call(t, "job.cancel", map[string]any{"id": job.ID}, 200)
	f.call(t, "source.sync", map[string]any{"id": source.ID, "revision": 1}, 400)
	if j, e := worker.ProcessOne(context.Background()); e != nil || j.ID != "" {
		t.Fatal("idle worker", e)
	}
}
