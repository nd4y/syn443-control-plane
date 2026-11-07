//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
)

func TestDeviceSourceFetchUsesBoundSessionAndRestrictedCatalogViews(t *testing.T) {
	f := newFixture(t, 2)
	ctx := context.Background()
	if _, err := fixtureOwner.Exec(catalog.Schema + `
 GRANT SELECT ON catalog_device_fetch_sources,catalog_device_fetch_jobs TO syn443_identity_api;
 GRANT UPDATE(selection_guard) ON catalog_device_fetch_sources TO syn443_identity_api;
 GRANT UPDATE(lease,lease_until,device_attempts,payload,device_result_hash,updated_at) ON catalog_device_fetch_jobs TO syn443_identity_api;`); err != nil {
		t.Fatal(err)
	}
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	defer clear(dataKey)
	catalogStore, err := catalog.NewStore(fixtureOwner, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	deviceStore, err := catalog.NewStore(fixtureAPI, dataKey)
	if err != nil || deviceStore.DeviceFetchRole(ctx) != nil || catalogStore.DeviceFetchRole(ctx) == nil {
		t.Fatal("catalog role privilege boundary", err)
	}
	ownerKey := key(t)
	session, _, _ := f.register(t, ownerKey)
	otherKey := key(t)
	other, _, _ := f.register(t, otherKey)
	expect(t, f.call(t, ownerKey, "GET", deviceFetchClaimPath, session.AccessToken, session.Nonce, nil), http.StatusNotFound)
	f.api.DeviceFetch = deviceStore
	expect(t, f.call(t, ownerKey, "GET", deviceFetchClaimPath, session.AccessToken, session.Nonce, nil), http.StatusNoContent)
	actor := catalog.Actor{ID: "synthetic-source-admin", SessionUntil: f.now.Add(time.Hour).Unix(), MFAUntil: f.now.Add(time.Hour).Unix()}
	if _, err = fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'*','*','*',$2)`, actor.ID, actor.SessionUntil); err != nil {
		t.Fatal(err)
	}
	source, err := catalogStore.PutSource(ctx, actor, catalog.Source{ID: "device-source", Owner: Owner(f.grant.Issuer, f.grant.Subject),
		Name: "Synthetic device source", Mode: "device", Format: "uri", FetchDeviceID: session.DeviceID, Enabled: true,
		ValidUntil: f.now.Add(time.Hour).Unix(), RefreshSeconds: 600, MaxStaleSeconds: 3600, NetworkModes: []string{"wifi"}},
		catalog.SecretPatch{Operation: "replace", Value: json.RawMessage(`{"url":"https://subscription.example.invalid"}`)}, "source-create", f.now)
	if err != nil {
		t.Fatal(err)
	}
	catalogStore.DeviceFetchEnabled = true
	job, err := catalogStore.Queue(ctx, actor, source.ID, source.Revision, "source-device-sync", nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(t, otherKey, "GET", deviceFetchClaimPath, other.AccessToken, other.Nonce, nil), http.StatusNoContent)
	r := f.call(t, ownerKey, "GET", deviceFetchClaimPath, session.AccessToken, session.Nonce, nil)
	expect(t, r, http.StatusOK)
	var lease catalog.DeviceFetchLease
	if err = json.Unmarshal(r.Body.Bytes(), &lease); err != nil || lease.JobID != job.ID || lease.Lease == "" ||
		lease.Credential.URL != "https://subscription.example.invalid" || lease.Until <= f.now.Unix() {
		t.Fatal("addressed lease readback", err)
	}
	body := []byte(lease.JobID + "\n" + lease.Lease + "\nhttp://node.example.invalid:443")
	post := func(s Session, proof string, raw []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", f.origin+deviceFetchResultPath, bytes.NewReader(raw))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Authorization", "DPoP "+s.AccessToken)
		r.Header.Set("DPoP", proof)
		r.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		return w
	}
	proof := signed(t, ownerKey, "POST", f.origin+deviceFetchResultPath, session.AccessToken, session.Nonce, body, f.now)
	tampered := append(append([]byte(nil), body...), 'x')
	expect(t, post(session, proof, tampered), http.StatusUnauthorized)
	foreignProof := signed(t, otherKey, "POST", f.origin+deviceFetchResultPath, other.AccessToken, other.Nonce, body, f.now)
	expect(t, post(other, foreignProof, body), http.StatusForbidden)
	expect(t, post(session, proof, body), http.StatusNoContent)
	expect(t, post(session, proof, body), http.StatusUnauthorized)
	processed, err := (&catalog.Worker{Store: catalogStore, Clock: func() time.Time { return f.now }}).ProcessOne(ctx)
	if err != nil || processed.ID != job.ID || processed.Phase != "succeeded" {
		t.Fatal("device upload did not reach source parser", err)
	}
}
