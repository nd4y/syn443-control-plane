//go:build postgres

package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
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
)

func layerPublisherFixture(t *testing.T) (networkFixture, *ConfigurationControl, LayerProposal, *ConfigurationPublisher) {
	t.Helper()
	n, c, p, s := configurationWorkFixture(t)
	if e := n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	return n, c, p, &ConfigurationPublisher{Store: s.Store, Sources: n.authority.Sources, Verifier: c.Verifier, Origin: c.Origin, AssuranceACR: c.AssuranceACR, Key: n.f.key, KeyID: "fixture-root", Roots: map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}}
}

func prepareLayerPreview(t *testing.T, n networkFixture, c *ConfigurationControl, p LayerProposal, publisher *ConfigurationPublisher, operation string) ConfigurationPreviewResult {
	t.Helper()
	q := queueConfigurationWork(t, n, c, p, operation)
	if e := publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	var state string
	var raw []byte
	if e := fixtureOwner.QueryRow(`SELECT state,result FROM managed_configuration_requests WHERE id=$1`, q.ID).Scan(&state, &raw); e != nil || state != "ready" {
		t.Fatal("preview result", e)
	}
	var r ConfigurationPreviewResult
	if identity.DecodeConfiguration(raw, &r) != nil || r.PreviewID != q.ID {
		t.Fatal("preview output")
	}
	if _, e := configuration.VerifyPreview(context.Background(), r.Ticket, publisher.Roots, c.Origin, n.actor.ID, n.f.now.Add(time.Second)); e != nil {
		t.Fatal("independent signature", e)
	}
	return r
}

func queueLayerPublish(t *testing.T, n networkFixture, c *ConfigurationControl, r ConfigurationPreviewResult, operation string) ConfigurationRequestView {
	t.Helper()
	raw, token, proof := configurationCall(t, n, c, "configuration.publish", identity.Hash([]byte(operation)), configurationPublishInput{r.PreviewID, r.Ticket})
	v, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	return v.(ConfigurationRequestView)
}

func TestConfigurationPublisherProducesAndAtomicallyPublishesActualCompiledLayers(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	r := prepareLayerPreview(t, n, c, p, publisher, "real preview")
	for _, table := range []string{"managed_configuration_heads", "managed_configuration_layer_versions", "managed_configuration_assignments"} {
		var count int
		if e := fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("preview secretly published", table, e)
		}
	}
	q := queueLayerPublish(t, n, c, r, "real publish")
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var state string
	var raw []byte
	if e := fixtureOwner.QueryRow(`SELECT state,result FROM managed_configuration_requests WHERE id=$1`, q.ID).Scan(&state, &raw); e != nil || state != "published" {
		t.Fatal("publication receipt", e)
	}
	if strings.Contains(string(raw), "applied") || strings.Contains(string(raw), "active") {
		t.Fatal("desired publication invented device ACK")
	}
	var result struct {
		Heads []ConfigurationPublishedHead `json:"heads"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Heads) != 1 || result.Heads[0].Device != n.target.Device || result.Heads[0].Revision != 1 || result.Heads[0].Hash != r.Preview.DraftHash {
		t.Fatal("heads")
	}
	var globals, assignments int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_layer_versions`).Scan(&globals); e != nil || globals != 1 {
		t.Fatal("global version", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_assignments WHERE device=$1 AND configuration_revision=1`, n.target.Device).Scan(&assignments); e != nil || assignments != 1 {
		t.Fatal("actual assignments", e)
	}
	reader := &SQLNetworkLayers{Store: publisher.Store, ControlOrigin: c.Origin, Roots: publisher.Roots}
	// Long-lived approval works after the short preview/MFA interval, with live
	// source/account/assignment fences; no API-ready boolean is consulted.
	a := &NetworkAuthority{Sources: publisher.Sources, Layers: reader}
	target := n.target
	target.CurrentRevision = 1
	prepared, e := a.Prepare(context.Background(), target, n.f.now.Add(10*time.Minute))
	if e != nil || !strings.Contains(string(prepared.EngineConfig), "proxy.example.invalid") {
		t.Fatal("independent approved reader composition", e)
	}
	tx, e := fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = prepared.Fence.Lock(context.Background(), tx, n.f.now.Add(10*time.Minute)); e != nil {
		t.Fatal("final publication fence", e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	// Lost acknowledgement: exact operation returns its durable receipt and
	// does not mint a second configuration revision or another global body.
	again := queueLayerPublish(t, n, c, r, "real publish")
	if again.ID != q.ID || again.State != "published" || string(again.Result) != string(raw) {
		t.Fatal("lost ACK not idempotent")
	}
	if e = publisher.RunOnce(context.Background(), n.f.now.Add(2*time.Second)); e != nil {
		t.Fatal("idle", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", publisher, publisher, r, r), n.target.Device) {
		t.Fatal("diagnostic leaked configuration scope")
	}
}

func TestConfigurationPublisherRejectsChangedDependenciesACLAndImpact(t *testing.T) {
	for _, kind := range []string{"source", "acl", "account", "device", "impact", "expired", "wrong-key"} {
		t.Run(kind, func(t *testing.T) {
			n, c, p, publisher := layerPublisherFixture(t)
			if kind == "impact" {
				p.TargetKind = "user"
				p.TargetID = n.target.Owner
			}
			r := prepareLayerPreview(t, n, c, p, publisher, "preview before "+kind)
			q := queueLayerPublish(t, n, c, r, "publish after "+kind)
			exec := func(query string, args ...any) {
				t.Helper()
				if _, e := fixtureOwner.Exec(query, args...); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "source":
				changed := n.source
				changed.Name = "Changed source metadata"
				changed.State, changed.AccessState, changed.ActiveSnapshot, changed.CandidateSnapshot = "", "", "", ""
				changed.LastSync, changed.NextSync, changed.LastResourceRevision = 0, 0, 0
				if _, e := n.api.PutSource(context.Background(), n.actor, changed, catalog.SecretPatch{Operation: "keep"}, "change-source", n.f.now); e != nil {
					t.Fatal(e)
				}
			case "acl":
				exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID)
			case "account":
				exec(`UPDATE identity_accounts SET enabled=false WHERE owner=$1`, n.target.Owner)
			case "device":
				exec(`UPDATE identity_devices SET active=false WHERE id=$1`, n.target.Device)
			case "impact":
				seedConfigurationDevice(t, storedLayersFixture{n: n}, "new-device", true)
			case "wrong-key":
				publisher.Roots = map[string]*ecdsa.PublicKey{}
			}
			at := n.f.now.Add(time.Second)
			if kind == "expired" {
				at = n.f.now.Add(181 * time.Second)
			}
			if e := publisher.RunOnce(context.Background(), at); e == nil && kind != "expired" {
				t.Fatal("changed authority accepted", kind)
			}
			var count int
			if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_heads`).Scan(&count); e != nil || count != 0 {
				t.Fatal("partial head", e)
			}
			if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_layer_versions`).Scan(&count); e != nil || count != 0 {
				t.Fatal("partial global version", e)
			}
			var state string
			if e := fixtureOwner.QueryRow(`SELECT state FROM managed_configuration_requests WHERE id=$1`, q.ID).Scan(&state); e != nil || state != "rejected" && state != "expired" {
				t.Fatal("failure not bounded", state, e)
			}
		})
	}
}

func TestConfigurationProducerShortDeadlineRollsBackActualSQLAndQueue(t *testing.T) {
	n, c, p, s := configurationWorkFixture(t)
	q := queueConfigurationWork(t, n, c, p, "short producer deadline")
	w, e := s.claim(context.Background(), n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	called := false
	e = s.commitGuarded(context.Background(), w, n.f.now, n.f.now.Add(25*time.Millisecond).UnixMilli(), func(ctx context.Context, tx *sql.Tx, _ time.Time, _ invitation.Envelope) (json.RawMessage, error) {
		called = true
		if _, e := tx.ExecContext(ctx, `UPDATE identity_devices SET refresh_after=37 WHERE id=$1`, n.target.Device); e != nil {
			return nil, e
		}
		time.Sleep(35 * time.Millisecond)
		return json.RawMessage(`{"fixtureOnly":true}`), nil
	})
	if e == nil {
		t.Fatal("producer expiration accepted")
	}
	var state string
	var marker int64
	if e = fixtureOwner.QueryRow(`SELECT state FROM managed_configuration_requests WHERE id=$1`, q.ID).Scan(&state); e != nil || state != "running" {
		t.Fatal("late receipt", e)
	}
	if e = fixtureOwner.QueryRow(`SELECT refresh_after FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&marker); e != nil || marker == 37 {
		t.Fatal("expired SQL did not roll back", e)
	}
	_ = called // A slow CI runner may expire before admission; both are safe.
	if e = s.reject(context.Background(), w, n.f.now, "private free text"); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("unbounded error code accepted", e)
	}
}

func TestConfigurationPublisherSharedUpdateAndAssignmentReplacement(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	r := prepareLayerPreview(t, n, c, p, publisher, "initial shared preview")
	queueLayerPublish(t, n, c, r, "initial shared publish")
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	n.f.now = n.f.now.Add(2 * time.Second)
	p.Bundles[0].BaseRevision = 1
	p.Bundles[0].BaseHash = r.Preview.DraftHash
	// Unchanged template rows are reused, not illegally UPDATEd in place.
	p.Bundles[0].Layers = append(p.Bundles[0].Layers, configuration.Layer{Kind: "device", ID: n.target.Device, Revision: 1, Changes: []configuration.Change{{Path: "/network/dnsStrategy", Operation: "set", Value: json.RawMessage(`"ipv4_only"`)}}})
	r = prepareLayerPreview(t, n, c, p, publisher, "device override preview")
	queueLayerPublish(t, n, c, r, "device override publish")
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	n.f.now = n.f.now.Add(2 * time.Second)
	p.Bundles[0].BaseRevision = 2
	p.Bundles[0].BaseHash = r.Preview.DraftHash
	p.TargetKind = "template"
	p.TargetID = p.Bundles[0].Layers[0].ID
	p.Bundles[0].Layers[0].Revision = 2
	p.Bundles[0].Layers[0].Permissions = []configuration.Permission{{Path: "/graph", Mode: "locked"}}
	r = prepareLayerPreview(t, n, c, p, publisher, "template next preview")
	queueLayerPublish(t, n, c, r, "template next publish")
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var revision, globalRevision int64
	var count int
	if e := fixtureOwner.QueryRow(`SELECT revision FROM managed_configuration_heads WHERE device=$1`, n.target.Device).Scan(&revision); e != nil || revision != 3 {
		t.Fatal("configuration head CAS", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT revision FROM managed_configuration_layer_heads WHERE kind='template' AND id=$1`, p.TargetID).Scan(&globalRevision); e != nil || globalRevision != 2 {
		t.Fatal("shared head CAS", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_assignments WHERE device=$1 AND configuration_revision=3`, n.target.Device).Scan(&count); e != nil || count != 2 {
		t.Fatal("assignment replacement", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_layer_versions`).Scan(&count); e != nil || count != 3 {
		t.Fatal("immutable global history", e)
	}
}

func TestConfigurationPublisherRollsBackEveryRecipientOnLateSQLFailure(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	seedConfigurationDevice(t, storedLayersFixture{n: n}, "second-device", true)
	p.TargetKind = "user"
	p.TargetID = n.target.Owner
	p.Bundles = append(p.Bundles, LayerBundle{Device: "second-device", Layers: p.Bundles[0].Layers})
	if p.Bundles[0].Device > p.Bundles[1].Device {
		p.Bundles[0], p.Bundles[1] = p.Bundles[1], p.Bundles[0]
	}
	r := prepareLayerPreview(t, n, c, p, publisher, "two recipient preview")
	if len(r.Preview.Recipients) != 2 {
		t.Fatal("missing actual recipient")
	}
	q := queueLayerPublish(t, n, c, r, "two recipient publication")
	// Fail the final device refresh AFTER all heads/assignments were attempted.
	// It exercises actual database rollback, not a marker callback substitute.
	if _, e := fixtureOwner.Exec(`CREATE FUNCTION configuration_fixture_refresh_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id='second-device' THEN RAISE EXCEPTION 'synthetic late failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER configuration_fixture_refresh_failure BEFORE UPDATE ON identity_devices FOR EACH ROW EXECUTE FUNCTION configuration_fixture_refresh_failure()`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := fixtureOwner.Exec(`DROP TRIGGER IF EXISTS configuration_fixture_refresh_failure ON identity_devices; DROP FUNCTION IF EXISTS configuration_fixture_refresh_failure()`); e != nil {
			t.Error(e)
		}
	})
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal("expected late SQL failure", e)
	}
	for _, table := range []string{"managed_configuration_versions", "managed_configuration_heads", "managed_configuration_layer_versions", "managed_configuration_layer_heads", "managed_configuration_assignments"} {
		var count int
		if e := fixtureOwner.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("partial multi-recipient effect", table, e)
		}
	}
	var state string
	if e := fixtureOwner.QueryRow(`SELECT state FROM managed_configuration_requests WHERE id=$1`, q.ID).Scan(&state); e != nil || state != "running" {
		t.Fatal("failed transaction committed success", e)
	}
	if _, e := fixtureOwner.Exec(`DROP TRIGGER configuration_fixture_refresh_failure ON identity_devices`); e != nil {
		t.Fatal(e)
	}
	// Reclaim after the original lease expires. Same operation/ticket then
	// publishes once; a transient SQL error does not require another approval.
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(22*time.Second)); e != nil {
		t.Fatal("bounded retry", e)
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_heads`).Scan(&count); e != nil || count != 2 {
		t.Fatal("all recipients not committed", e)
	}
}

func TestConfigurationPublisherRollsBackFailureAtEveryPersistentBoundary(t *testing.T) {
	for _, table := range []string{"managed_configuration_layer_versions", "managed_configuration_layer_heads", "managed_configuration_versions", "managed_configuration_heads", "managed_configuration_assignments"} {
		t.Run(table, func(t *testing.T) {
			n, c, p, publisher := layerPublisherFixture(t)
			r := prepareLayerPreview(t, n, c, p, publisher, "preview persistent boundary")
			queueLayerPublish(t, n, c, r, "publish persistent boundary")
			if _, e := fixtureOwner.Exec(`CREATE FUNCTION configuration_fixture_boundary_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic persistent boundary failure'; END $$; CREATE TRIGGER configuration_fixture_boundary_failure BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION configuration_fixture_boundary_failure()`); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				if _, e := fixtureOwner.Exec(`DROP TRIGGER IF EXISTS configuration_fixture_boundary_failure ON ` + table + `; DROP FUNCTION IF EXISTS configuration_fixture_boundary_failure()`); e != nil {
					t.Error(e)
				}
			})
			if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); !errors.Is(e, enrollment.ErrUnavailable) {
				t.Fatal("persistent boundary unexpectedly committed", e)
			}
			for _, name := range []string{"managed_configuration_versions", "managed_configuration_heads", "managed_configuration_layer_versions", "managed_configuration_layer_heads", "managed_configuration_assignments"} {
				var count int
				if e := fixtureOwner.QueryRow(`SELECT count(*) FROM ` + name).Scan(&count); e != nil || count != 0 {
					t.Fatal("partial persistent boundary", name, e)
				}
			}
		})
	}
}

func TestConfigurationPublisherRequiresActualCapabilitiesAndSafeRuntime(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	for _, bad := range []*ConfigurationPublisher{nil, {}, {Store: publisher.Store, Sources: publisher.Sources, Verifier: publisher.Verifier}} {
		if e := bad.RunOnce(context.Background(), n.f.now); !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("unsafe publisher admitted", e)
		}
	}
	if e := publisher.RunOnce(nil, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("nil context")
	}
	layers := proposedNetworkLayers{}
	if _, e := layers.PrepareLayers(context.Background(), n.target, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("missing independent snapshot")
	}
	snapshot, e := prepareConfigurationLayers(context.Background(), publisher.Store, n.actor.ID, "configuration.preview", p, n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	layers.snapshot = snapshot
	foreign := n.target
	foreign.Device = "foreign-device"
	if _, e = layers.PrepareLayers(context.Background(), foreign, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("substituted actual recipient")
	}
	// An explicitly owner-seeded approved device with insufficient advertised
	// capabilities cannot borrow the initiator's capabilities or compile result.
	limited := n
	limited.target.Capabilities = []string{"policy.keybound.v2"}
	seedConfigurationDevice(t, storedLayersFixture{n: limited}, "limited-device", true)
	p.TargetID = "limited-device"
	p.Bundles[0].Device = "limited-device"
	q := queueConfigurationWork(t, n, c, p, "limited recipient preview")
	if e = publisher.RunOnce(context.Background(), n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("missing device capability", e)
	}
	var state string
	if e = fixtureOwner.QueryRow(`SELECT state FROM managed_configuration_requests WHERE id=$1`, q.ID).Scan(&state); e != nil || state != "rejected" {
		t.Fatal("capability denial not terminal", e)
	}
	head := ConfigurationPublishedHead{n.target.Device, 1, "hash"}
	if strings.Contains(fmt.Sprintf("%v %#v", head, head), n.target.Device) {
		t.Fatal("head diagnostic leaked recipient")
	}
}
