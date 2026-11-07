//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
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
	postAt := func(path string, s Session, proof string, raw []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", f.origin+path, bytes.NewReader(raw))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Authorization", "DPoP "+s.AccessToken)
		r.Header.Set("DPoP", proof)
		r.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		return w
	}
	post := func(s Session, proof string, raw []byte) *httptest.ResponseRecorder {
		return postAt(deviceFetchResultPath, s, proof, raw)
	}
	proof := signed(t, ownerKey, "POST", f.origin+deviceFetchResultPath, session.AccessToken, session.Nonce, body, f.now)
	tampered := append(append([]byte(nil), body...), 'x')
	expect(t, post(session, proof, tampered), http.StatusUnauthorized)
	foreignProof := signed(t, otherKey, "POST", f.origin+deviceFetchResultPath, other.AccessToken, other.Nonce, body, f.now)
	expect(t, post(other, foreignProof, body), http.StatusForbidden)
	expect(t, post(session, proof, body), http.StatusNoContent)
	expect(t, post(session, proof, body), http.StatusUnauthorized)
	retryProof := signed(t, ownerKey, "POST", f.origin+deviceFetchResultPath, session.AccessToken, session.Nonce, body, f.now)
	expect(t, post(session, retryProof, body), http.StatusNoContent)
	changedProof := signed(t, ownerKey, "POST", f.origin+deviceFetchResultPath, session.AccessToken, session.Nonce, tampered, f.now)
	expect(t, post(session, changedProof, tampered), http.StatusConflict)
	processed, err := (&catalog.Worker{Store: catalogStore, Clock: func() time.Time { return f.now }}).ProcessOne(ctx)
	if err != nil || processed.ID != job.ID || processed.Phase != "succeeded" {
		t.Fatal("device upload did not reach source parser", err)
	}
	claim := func(path string) catalog.DeviceFetchLease {
		t.Helper()
		r := f.call(t, ownerKey, "GET", path, session.AccessToken, session.Nonce, nil)
		expect(t, r, http.StatusOK)
		var result catalog.DeviceFetchLease
		if json.Unmarshal(r.Body.Bytes(), &result) != nil || result.JobID == "" {
			t.Fatal("invalid provider lease")
		}
		return result
	}
	sync := func(request string) {
		t.Helper()
		if _, err := catalogStore.Queue(ctx, actor, source.ID, source.Revision, request, nil, f.now); err != nil {
			t.Fatal(err)
		}
	}
	submitV2 := func(lease catalog.DeviceFetchLease, metadata, provider string) {
		t.Helper()
		data := []byte(lease.JobID + "\n" + lease.Lease + "\n")
		data = append(data, 0, 'S', '4', '4', '3', 2)
		data = binary.BigEndian.AppendUint16(data, uint16(len(metadata)))
		data = append(data, metadata...)
		data = append(data, provider...)
		proof := signed(t, ownerKey, "POST", f.origin+deviceFetchV2ResultPath, session.AccessToken, session.Nonce, data, f.now)
		expect(t, postAt(deviceFetchV2ResultPath, session, proof, data), http.StatusNoContent)
	}
	process := func(lease catalog.DeviceFetchLease) catalog.Source {
		t.Helper()
		job, err := (&catalog.Worker{Store: catalogStore, Clock: func() time.Time { return f.now }}).ProcessOne(ctx)
		if err != nil || job.ID != lease.JobID || job.Phase != "succeeded" {
			t.Fatal("provider result was not processed", err)
		}
		s, err := catalogStore.GetSource(ctx, actor, source.ID, f.now)
		if err != nil || s.ActiveSnapshot == "" {
			t.Fatal("active provider result unavailable", err)
		}
		return s
	}
	sync("v2-full")
	full := claim(deviceFetchV2ClaimPath)
	if full.Validators != nil {
		t.Fatal("legacy upload invented a conditional validator")
	}
	submitV2(full, `{"status":200,"etag":"\"fixture-v2\"","quota":"upload=1; download=2; total=10; expire=0"}`, "http://node.example.invalid:443")
	firstV2 := process(full)
	sync("v2-refresh")
	legacyLease := claim(deviceFetchClaimPath)
	conditional := claim(deviceFetchV2ClaimPath)
	if legacyLease.Validators != nil || legacyLease.JobID != conditional.JobID || legacyLease.Lease != conditional.Lease ||
		conditional.Validators == nil || conditional.Validators.ETag != `"fixture-v2"` {
		t.Fatal("validator scope or legacy compatibility")
	}
	submitV2(conditional, `{"status":304,"quota":"upload=1; download=3; total=10; expire=0"}`, "")
	next := process(conditional)
	var same bool
	err = fixtureOwner.QueryRow(`SELECT prior_row.content_hash=latest_row.content_hash AND prior_row.quota->>'used'='3'
 AND latest_row.quota->>'used'='4' FROM catalog_snapshots prior_row,catalog_snapshots latest_row WHERE prior_row.id=$1 AND latest_row.id=$2`,
		firstV2.ActiveSnapshot, next.ActiveSnapshot).Scan(&same)
	if err != nil || !same || firstV2.ActiveSnapshot == next.ActiveSnapshot {
		t.Fatal("304 did not preserve profiles and refresh scoped quota", err)
	}
	sync("v2-gone")
	gone := claim(deviceFetchV2ClaimPath)
	submitV2(gone, `{"status":410}`, "")
	revoked, err := (&catalog.Worker{Store: catalogStore, Clock: func() time.Time { return f.now }}).ProcessOne(ctx)
	if err != nil || revoked.ID != gone.JobID || revoked.Phase != "failed" || revoked.Reason != "subscription_access_revoked" {
		t.Fatal("scoped provider revocation did not reach the worker", err)
	}
}
