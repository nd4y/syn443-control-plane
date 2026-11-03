//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestConfigurationHTTPOriginalReceiptPreviewPublishAndPoll(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	api, e := catalog.NewAPI(n.api, n.f.v, c.Origin, c.AssuranceACR, false)
	if e != nil {
		t.Fatal(e)
	}
	api.Clock = func() time.Time { return n.f.now }
	call := func(action, operation string, payload any, want int) []byte {
		t.Helper()
		raw, token, proof := configurationCall(t, n, c, action, identity.Hash([]byte(operation)), payload)
		req := httptest.NewRequest("POST", c.Origin+"/v1/control/action", bytes.NewReader(raw))
		req.RemoteAddr = "127.0.0.1:8000"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s: HTTP%d %s", action, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	// Feature opt-in is fail closed even when the generic API schema knows it.
	call("configuration.preview.request", "disabled preview", configurationPreviewInput{p}, 403)
	api.Configurations = c.ControlAction
	// Actor-private draft persistence goes through the same closed HTTP schema,
	// proof verification and live ACL boundary; it does not queue publication.
	inputDraft := ConfigurationDraft{ID: p.DraftID, Proposal: p}
	var savedDraft ConfigurationDraft
	if json.Unmarshal(call("configuration.layers.draft.put", "HTTP draft save", map[string]any{"draft": inputDraft}, 200), &savedDraft) != nil || savedDraft.Revision != 1 {
		t.Fatal("HTTP draft save")
	}
	if json.Unmarshal(call("configuration.layers.draft.get", "HTTP draft read", map[string]string{"id": p.DraftID}, 200), &savedDraft) != nil || savedDraft.Revision != 1 {
		t.Fatal("HTTP draft read")
	}
	call("configuration.layers.draft.put", "HTTP draft stale edit", map[string]any{"draft": inputDraft}, 409)
	call("configuration.layers.draft.get", "HTTP draft unknown field", map[string]any{"id": p.DraftID, "approved": true}, 400)
	inputDraft.SavedAtMs = 1
	call("configuration.layers.draft.put", "HTTP draft forged observation", map[string]any{"draft": inputDraft}, 400)
	var queued ConfigurationRequestView
	if json.Unmarshal(call("configuration.preview.request", "HTTP preview", configurationPreviewInput{p}, 200), &queued) != nil || queued.State != "queued" {
		t.Fatal("HTTP queue")
	}
	if e = publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	var ready ConfigurationRequestView
	if json.Unmarshal(call("configuration.request.get", "HTTP read preview", map[string]string{"id": queued.ID}, 200), &ready) != nil || ready.State != "ready" {
		t.Fatal("HTTP ready")
	}
	var result ConfigurationPreviewResult
	if identity.DecodeConfiguration(ready.Result, &result) != nil {
		t.Fatal("HTTP preview result")
	}
	var publish ConfigurationRequestView
	if json.Unmarshal(call("configuration.publish", "HTTP publish", configurationPublishInput{result.PreviewID, result.Ticket}, 200), &publish) != nil || publish.State != "queued" {
		t.Fatal("HTTP publish queue")
	}
	if e = publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var done ConfigurationRequestView
	if json.Unmarshal(call("configuration.request.get", "HTTP read publication", map[string]string{"id": publish.ID}, 200), &done) != nil || done.State != "published" {
		t.Fatal("HTTP desired publication")
	}
	var view ConfigurationInventory
	if json.Unmarshal(call("configuration.inventory.get", "HTTP desired inventory", map[string]string{"id": n.target.Device}, 200), &view) != nil || view.Revision != 1 || view.State != "assigned" || view.Effective == nil {
		t.Fatal("HTTP desired view")
	}
	if json.Unmarshal(call("configuration.history.get", "HTTP historical inventory", map[string]any{"id": n.target.Device, "revision": 1, "hash": view.Hash}, 200), &view) != nil || !view.Historical || view.CurrentRevision != 1 {
		t.Fatal("HTTP historical view")
	}
	call("configuration.history.get", "HTTP unbound historical inventory", map[string]any{"id": n.target.Device, "revision": 0, "hash": view.Hash}, 400)
	call("configuration.publish", "HTTP mismatched ticket", configurationPublishInput{result.PreviewID, result.Ticket + "x"}, 403)
	changed := p
	changed.DraftRevision++
	call("configuration.preview.request", "HTTP preview", configurationPreviewInput{changed}, 409)
	original := c.Store
	badStore, e := enrollment.NewStore(fixtureControl, bytes.Repeat([]byte{92}, 32))
	if e != nil {
		t.Fatal(e)
	}
	c.Store = badStore
	call("configuration.publish", "HTTP unreadable encrypted artifact", configurationPublishInput{result.PreviewID, result.Ticket}, 503)
	c.Store = original
	call("configuration.request.get", "HTTP invalid envelope", map[string]any{"id": publish.ID, "ready": true}, 400)
	call("configuration.preview.request", "HTTP untrusted recipients", map[string]any{"proposal": p, "approved": true}, 400)
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	call("configuration.request.get", "HTTP revoked read", map[string]string{"id": publish.ID}, 403)
}

func TestConfigurationRuntimeStoresPreserveActualRestrictedProcessRoles(t *testing.T) {
	n, c, _, _ := layerPublisherFixture(t)
	r := runtimeConfiguration(t)
	if _, e := r.LayerStore(context.Background(), fixtureControl, false); e != nil {
		t.Fatal("API layer store", e)
	}
	if _, e := r.LayerStore(context.Background(), fixtureSigner, true); e != nil {
		t.Fatal("publisher layer store", e)
	}
	if _, e := r.SourceStore(context.Background(), fixtureSigner); e != nil {
		t.Fatal("publisher source composition", e)
	}
	for _, db := range []*sql.DB{fixtureOwner, fixtureControl, fixtureSourceWorker} {
		if _, e := r.LayerStore(context.Background(), db, true); e == nil {
			t.Fatal("wrong process obtained publisher authority")
		}
	}
	for _, db := range []*sql.DB{fixtureControl, fixtureSourceWorker, fixtureSigner, fixtureDevice} {
		rows, e := db.Query(`SELECT body FROM identity_overlay_resource_versions`)
		if e == nil {
			rows.Close()
			t.Fatal("control/source/identity process obtained overlay management PAT history")
		}
	}
	if _, e := r.SourceStore(context.Background(), fixtureSourceWorker); e == nil {
		t.Fatal("source worker obtained independent publication authority")
	}
	bad := r
	bad.LayerEncryptionKey = "invalid"
	if _, e := bad.LayerStore(context.Background(), fixtureControl, false); e == nil {
		t.Fatal("constructor bypassed protected-file validation")
	}
	if _, e := bad.SourceStore(context.Background(), fixtureSigner); e == nil {
		t.Fatal("source constructor bypassed validation")
	}
	// Bad ciphertext remains unavailable, rather than being surfaced as a SQL
	// or credential-bearing error through the administrative HTTP adapter.
	raw, token, proof := configurationCall(t, n, c, "configuration.request.get", identity.Hash([]byte("missing request")), map[string]string{"id": identity.Hash([]byte("absent"))})
	if _, e := c.ControlAction(context.Background(), token, proof, raw, n.f.now); e != catalog.ErrDenied {
		t.Fatal("unsafe error adapter", e)
	}
}
