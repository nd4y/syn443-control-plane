//go:build postgres

package catalog

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func resourceExample() Resource {
	return Resource{ID: "panel-a", Name: "Synthetic panel", ProviderType: "panel.remnawave", APIVersion: "3.4", Enabled: true}
}
func resourceSecret(endpoint string) SecretPatch {
	raw, _ := json.Marshal(ResourceCredential{Endpoint: endpoint, Token: "synthetic-token-not-a-real-secret"})
	return SecretPatch{Operation: "replace", Value: raw}
}
func resourceDraft(r Resource) Resource { r.State = ""; r.LastSync = 0; return r }
func TestSQLResourcesAuthorityImpactAndRevisionFence(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	r := resourceExample()
	secret := resourceSecret("https://panel.example.invalid")
	noMFA := actor
	noMFA.MFAUntil = now.Unix()
	if _, e := api.PutResource(ctx, noMFA, r, secret, "", "no-mfa", now); !errors.Is(e, ErrDenied) {
		t.Fatal("resource credentials accepted without fresh assurance")
	}
	created, e := api.PutResource(ctx, actor, r, secret, "", "resource-create", now)
	if e != nil || created.Revision != 1 {
		t.Fatal("resource create", e)
	}
	retry, e := api.PutResource(ctx, actor, r, secret, "", "resource-create", now)
	if e != nil || retry.Revision != created.Revision {
		t.Fatal("lost reply not idempotent", e)
	}
	r.Name = "Changed body"
	if _, e = api.PutResource(ctx, actor, r, secret, "", "resource-create", now); !errors.Is(e, ErrConflict) {
		t.Fatal("request identity reused")
	}
	second := resourceExample()
	second.ID = "panel-b"
	if _, e = api.PutResource(ctx, actor, second, secret, "", "second", now); !errors.Is(e, ErrConflict) {
		t.Fatal("multiple active resources")
	}
	planned := Resource{ID: "future-a", Name: "Planned", ProviderType: "panel.x-ui"}
	if _, e = api.PutResource(ctx, actor, planned, SecretPatch{Operation: "keep"}, "", "planned", now); e != nil {
		t.Fatal("planned metadata", e)
	}
	planned.Revision = 1
	planned.Enabled = true
	if _, e = api.PutResource(ctx, actor, planned, SecretPatch{Operation: "keep"}, "", "activate-future", now); e == nil {
		t.Fatal("planned integration activated")
	}
	source := sourceExample(now)
	source.Mode = "resource"
	source.ResourceID = created.ID
	source.ExternalUserID = "42"
	source = mustSource(t, api, actor, source, "bind", now)
	read, impact, e := api.GetResource(ctx, actor, created.ID, now)
	if e != nil || impact.Sources != 1 || impact.Hash == "" {
		t.Fatal("impact missing", e)
	}
	if _, e = worker.GetResource(ctx, actor, created.ID, now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("worker gained admin ACL read")
	}
	_, e = api.Queue(ctx, actor, source.ID, source.Revision, "read-resource", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	job, e := worker.Claim(ctx, now)
	if e != nil || job.ResourceRevision != 1 {
		t.Fatal("resource revision not captured", e)
	}
	_, salt, _, _, e := worker.JobInput(ctx, job, now)
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := subscriptions.Import(source.ID, salt, "uri", []byte("http://proxy.example.invalid:443"))
	if e != nil {
		t.Fatal(e)
	}
	changed := resourceDraft(read)
	changed.Name = "Renamed"
	changed, e = api.PutResource(ctx, noMFA, changed, SecretPatch{Operation: "keep"}, "", "rename", now)
	if e != nil {
		t.Fatal("metadata edit", e)
	}
	if _, _, _, _, e = worker.JobInput(ctx, job, now); !errors.Is(e, ErrStale) {
		t.Fatal("old resource input accepted", e)
	}
	if _, e = worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now); !errors.Is(e, ErrStale) {
		t.Fatal("old resource completion accepted", e)
	}
	if e = worker.Fail(ctx, job, "resource_unavailable", true, now); !errors.Is(e, ErrStale) {
		t.Fatal("old resource failure altered status", e)
	}
	if e = worker.Abandon(ctx, job, now); e != nil {
		t.Fatal(e)
	}
	if n, e := worker.Schedule(ctx, now); e != nil || n != 1 {
		t.Fatal("resource revision not rescheduled", n, e)
	}
	job, e = worker.Claim(ctx, now)
	if e != nil || job.ResourceRevision != 2 {
		t.Fatal("new revision not used", e)
	}
	client, id, e := worker.ResourceClient(ctx, job, false, now)
	if e != nil || id != "42" {
		t.Fatal("resource binding", e)
	}
	client.Close()
	if _, e = worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now); e != nil {
		t.Fatal(e)
	}
	if n, e := worker.Schedule(ctx, now); e != nil || n != 0 {
		t.Fatal("successful revision repeated", n, e)
	}
	changed = resourceDraft(changed)
	if _, e = api.PutResource(ctx, actor, changed, resourceSecret("https://other.example.invalid"), impact.Hash, "endpoint-change", now); !errors.Is(e, ErrConflict) {
		t.Fatal("endpoint changed under bound users", e)
	}
	changed.Enabled = false
	if _, e = api.PutResource(ctx, actor, changed, SecretPatch{Operation: "keep"}, "wrong", "disable-stale-impact", now); !errors.Is(e, ErrConflict) {
		t.Fatal("disable without exact impact", e)
	}
	if _, e = api.PutResource(ctx, noMFA, changed, SecretPatch{Operation: "keep"}, impact.Hash, "disable-no-mfa", now); !errors.Is(e, ErrDenied) {
		t.Fatal("disable without assurance", e)
	}
	if _, e = api.PutResource(ctx, actor, changed, SecretPatch{Operation: "keep"}, impact.Hash, "disable", now); e != nil {
		t.Fatal(e)
	}
	state, e := api.GetSource(ctx, actor, source.ID, now)
	if e != nil || state.State != "resource_disabled" {
		t.Fatal("disabled resource appears healthy", e)
	}
	if _, e = api.Queue(ctx, actor, source.ID, source.Revision, "disabled-job", nil, now); !errors.Is(e, ErrDenied) {
		t.Fatal("disabled resource queued", e)
	}
	if n, e := worker.Schedule(ctx, now); e != nil || n != 0 {
		t.Fatal("disabled resource scheduled", n, e)
	}
}

func TestSQLWorkerActualHTTPSRevalidationAndCredentialFailure(t *testing.T) {
	api, store, actor, now := databaseFixture(t)
	ctx := context.Background()
	var status, calls atomic.Int32
	status.Store(200)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if status.Load() == 401 {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("ETag", `"fixture-v1"`)
		if r.Header.Get("If-None-Match") == `"fixture-v1"` {
			w.WriteHeader(304)
			return
		}
		w.Write([]byte("http://proxy.example.invalid:443"))
	}))
	defer server.Close()
	source := sourceExample(now)
	source.Mode = "server"
	credential := FetchCredential{URL: server.URL, AllowedNetworks: []string{"127.0.0.1/32"}, RootCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	raw, _ := json.Marshal(credential)
	source, e := api.PutSource(ctx, actor, source, SecretPatch{Operation: "replace", Value: raw}, "server-create", now)
	if e != nil {
		t.Fatal(e)
	}
	w := Worker{Store: store, FixtureLoopback: true, Clock: func() time.Time { return now }}
	if n, e := store.Schedule(ctx, now); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	job, e := w.ProcessOne(ctx)
	if e != nil || job.Phase != "succeeded" {
		t.Fatal("actual TLS fetch", job.Phase, e)
	}
	first, e := api.GetSource(ctx, actor, source.ID, now)
	if e != nil || first.State != "active" {
		t.Fatal(e)
	}
	if _, e = api.Queue(ctx, actor, source.ID, source.Revision, "revalidate", nil, now); e != nil {
		t.Fatal(e)
	}
	job, e = w.ProcessOne(ctx)
	if e != nil || job.Phase != "succeeded" || calls.Load() != 2 {
		t.Fatal("304 revalidation", e)
	}
	second, _ := api.GetSource(ctx, actor, source.ID, now)
	if second.ActiveSnapshot == first.ActiveSnapshot {
		t.Fatal("revalidation not committed")
	}
	status.Store(401)
	if _, e = api.Queue(ctx, actor, source.ID, source.Revision, "auth-failure", nil, now); e != nil {
		t.Fatal(e)
	}
	job, e = w.ProcessOne(ctx)
	if e != nil || job.Phase != "failed" || job.Reason != subscriptions.ErrAccess.Error() {
		t.Fatal("auth failure", job.Phase, e)
	}
	after, _ := api.GetSource(ctx, actor, source.ID, now)
	if after.ActiveSnapshot != second.ActiveSnapshot || after.State != "refresh_error" {
		t.Fatal("API credential error revoked valid cached user")
	}
	var protected []byte
	if e = fixtureOwner.QueryRow(`SELECT profiles FROM catalog_snapshots WHERE id=$1`, after.ActiveSnapshot).Scan(&protected); e != nil || strings.Contains(string(protected), "proxy.example.invalid") {
		t.Fatal("plaintext snapshot")
	}
}

func TestSQLWorkerRemnawaveCredentialFailureIsNotUserRevocation(t *testing.T) {
	api, store, actor, now := databaseFixture(t)
	ctx := context.Background()
	var state atomic.Int32
	expiry := now.Add(time.Hour).Format(time.RFC3339)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("provider write attempted")
			w.WriteHeader(405)
			return
		}
		if state.Load() == 1 {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/users/42":
			status := "ACTIVE"
			if state.Load() == 2 {
				status = "DISABLED"
			}
			json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"id": 42, "shortUuid": "synthetic-user", "status": status, "expireAt": expiry}})
		case "/api/subscriptions/by-id/42":
			json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"isFound": true, "user": map[string]any{"shortUuid": "synthetic-user", "isActive": true, "userStatus": "ACTIVE", "expiresAt": expiry, "trafficUsedBytes": "1", "trafficLimitBytes": "100"}, "links": []string{"http://proxy.example.invalid:443"}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	r := resourceExample()
	credential := ResourceCredential{Endpoint: server.URL, Token: "synthetic-token-not-a-real-secret", RootCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), AllowedNetworks: []string{"127.0.0.1/32"}}
	raw, _ := json.Marshal(credential)
	if _, e := api.PutResource(ctx, actor, r, SecretPatch{Operation: "replace", Value: raw}, "", "create", now); e != nil {
		t.Fatal(e)
	}
	source := sourceExample(now)
	source.Mode = "resource"
	source.ResourceID = r.ID
	source.ExternalUserID = "42"
	source = mustSource(t, api, actor, source, "bind", now)
	w := Worker{Store: store, FixtureLoopback: true, Clock: func() time.Time { return now }}
	if n, e := store.Schedule(ctx, now); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	job, e := w.ProcessOne(ctx)
	if e != nil || job.Phase != "succeeded" {
		t.Fatal("resource sync", e)
	}
	first, _ := api.GetSource(ctx, actor, source.ID, now)
	state.Store(1)
	if _, e = api.Queue(ctx, actor, source.ID, source.Revision, "bad-service-credential", nil, now); e != nil {
		t.Fatal(e)
	}
	job, e = w.ProcessOne(ctx)
	if e != nil || job.Reason != subscriptions.ErrAccess.Error() {
		t.Fatal("credential classification", e)
	}
	second, _ := api.GetSource(ctx, actor, source.ID, now)
	if second.ActiveSnapshot != first.ActiveSnapshot || second.State != "refresh_error" {
		t.Fatal("API authentication failure revoked user")
	}
	state.Store(2)
	if _, e = api.Queue(ctx, actor, source.ID, source.Revision, "upstream-user-disabled", nil, now); e != nil {
		t.Fatal(e)
	}
	job, e = w.ProcessOne(ctx)
	if e != nil || job.Reason != "resource_denied" {
		t.Fatal("explicit revoke classification", e)
	}
	third, _ := api.GetSource(ctx, actor, source.ID, now)
	if third.State != "revoked" || third.ActiveSnapshot != first.ActiveSnapshot {
		t.Fatal("explicit user revoke lost")
	}
}
