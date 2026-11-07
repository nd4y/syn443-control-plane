//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func inventoryCall(t *testing.T, n networkFixture, c *ConfigurationControl, id, operation string) (ConfigurationInventory, error) {
	t.Helper()
	raw, token, proof := configurationCall(t, n, c, "configuration.inventory.get", identity.Hash([]byte(operation)), map[string]string{"id": id})
	v, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		return ConfigurationInventory{}, e
	}
	return v.(ConfigurationInventory), nil
}

func TestConfigurationInventoryShowsOnlySelectedDeviceAndFieldProvenance(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	initial, e := inventoryCall(t, n, c, n.target.Device, "initial inventory")
	if e != nil || initial.State != "unassigned" || initial.Revision != 0 || initial.Hash != "" || len(initial.Layers) != 0 || initial.Effective != nil || initial.PolicyRevision != 1 {
		t.Fatal("unassigned desired layers confused with existing policy", e)
	}
	seedConfigurationDevice(t, storedLayersFixture{n: n}, "private-other-device", true)
	p.TargetKind = "user"
	p.TargetID = n.target.Owner
	other := LayerBundle{Device: "private-other-device", Layers: append([]configuration.Layer(nil), p.Bundles[0].Layers...)}
	other.Layers = append(other.Layers, configuration.Layer{ID: other.Device, Kind: "device", Revision: 1, Changes: []configuration.Change{{Path: "/network/dnsStrategy", Operation: "set", Value: json.RawMessage(`"ipv6_only"`)}}})
	p.Bundles = append(p.Bundles, other)
	sort.Slice(p.Bundles, func(i, j int) bool { return p.Bundles[i].Device < p.Bundles[j].Device })
	r := prepareLayerPreview(t, n, c, p, publisher, "inventory shared preview")
	queueLayerPublish(t, n, c, r, "inventory shared publication")
	if e = publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	v, e := inventoryCall(t, n, c, n.target.Device, "assigned inventory")
	if e != nil || v.State != "assigned" || v.Revision != 1 || v.Hash != r.Preview.DraftHash || v.Owner != n.target.Owner || v.Mode != "wifi" || len(v.Layers) != 1 || v.Effective == nil {
		t.Fatal("selected desired view", e)
	}
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), other.Device) || strings.Contains(string(raw), "ipv6_only") || strings.Contains(string(raw), "proxy.example.invalid") {
		t.Fatal("foreign bundle or native credential material leaked")
	}
	if v.Effective.Fields["/network/dnsStrategy"].Kind != "template" {
		t.Fatal("field inheritance missing")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", v, v), n.target.Device) {
		t.Fatal("inventory diagnostic leaked device")
	}
	if _, e = inventoryCall(t, n, c, "absent-device", "absent inventory"); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("unassigned does not mean nonexistent device", e)
	}
}

func TestConfigurationInventorySeparatesCurrentAndHistoricalDeviceReports(t *testing.T) {
	n, c, _, _ := layerPublisherFixture(t)
	view, e := inventoryCall(t, n, c, n.target.Device, "activation inventory pending")
	if e != nil || view.Activation == nil || view.Activation.State != "awaiting_report" || view.PolicyRevision != 1 {
		t.Fatal("issued policy appeared activated without a report", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_devices SET offline_until=$2,publication_grant_hash=$3 WHERE id=$1`, n.target.Device, n.f.now.Add(time.Hour).Unix(), n.target.GrantHash); e != nil {
		t.Fatal(e)
	}
	hash := identity.Hash([]byte("synthetic activation envelope"))
	if _, e = fixtureOwner.Exec(`INSERT INTO identity_policy_activation VALUES($1,1,$2,1,'committed',1,$3)`, n.target.Device, hash, n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	view, e = inventoryCall(t, n, c, n.target.Device, "current activation inventory")
	if e != nil || view.Activation == nil || view.Activation.State != "reported" || view.Activation.Outcome != "committed" || view.Activation.ActivePolicyRevision != 1 || view.Revision != 0 {
		t.Fatal("report was conflated with desired configuration", e)
	}
	raw, e := json.Marshal(view)
	if e != nil || strings.Contains(string(raw), hash) {
		t.Fatal("control response exposed envelope digest", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_devices SET revision=2 WHERE id=$1`, n.target.Device); e != nil {
		t.Fatal(e)
	}
	view, e = inventoryCall(t, n, c, n.target.Device, "historical activation inventory")
	if e != nil || view.Activation == nil || view.Activation.State != "historical" || view.Activation.PolicyRevision != 1 || view.PolicyRevision != 2 {
		t.Fatal("old observation was relabelled for a newer issuance", e)
	}
	if _, e = fixtureControl.Exec(`UPDATE identity_policy_activation SET outcome='degraded'`); e == nil {
		t.Fatal("control reader gained activation mutation authority")
	}
}

func TestConfigurationInventoryBindsIssuedPolicyToExactApprovedRevision(t *testing.T) {
	n, c, proposal, publisher := layerPublisherFixture(t)
	ctx := context.Background()
	publishDesired := func(label string) ConfigurationPreviewResult {
		t.Helper()
		preview := prepareLayerPreview(t, n, c, proposal, publisher, label+" preview")
		queueLayerPublish(t, n, c, preview, label+" publish")
		if e := publisher.RunOnce(ctx, n.f.now.Add(time.Second)); e != nil {
			t.Fatal(e)
		}
		n.f.now = n.f.now.Add(2 * time.Second)
		return preview
	}
	expect := func(label, source string, desired, issued int64) {
		t.Helper()
		view, e := inventoryCall(t, n, c, n.target.Device, label)
		if e != nil || view.Revision != desired || view.PolicyRevision != issued || view.PublicationSource != source {
			t.Fatalf("%s: wrong desired or issued configuration relation: %v", label, e)
		}
	}
	first := publishDesired("first desired origin")
	expect("legacy issuance", "unlinked", 1, 1)
	n.publisher.Configurations = &NetworkAuthority{Sources: publisher.Sources,
		Layers: &SQLNetworkLayers{Store: publisher.Store, ControlOrigin: c.Origin, Roots: publisher.Roots}}
	if e := n.publisher.RunOnce(ctx, n.f.now); e != nil {
		t.Fatal(e)
	}
	expect("first managed issuance", "matches_desired", 1, 2)
	if _, e := fixtureControl.Exec(`UPDATE identity_devices SET publication_source_hash=$2 WHERE id=$1`, n.target.Device, strings.Repeat("a", 64)); e == nil {
		t.Fatal("control API gained publication source write authority")
	}
	if _, e := fixtureSigner.Exec(`UPDATE identity_devices SET publication_source_hash=$2 WHERE id=$1`, n.target.Device, strings.Repeat("b", 64)); e == nil {
		t.Fatal("publisher could rewrite the source of an existing envelope")
	}
	if _, e := fixtureSigner.Exec(`UPDATE identity_devices SET publication=$2 WHERE id=$1`, n.target.Device, []byte("synthetic changed envelope")); e == nil {
		t.Fatal("publisher could replace an envelope without advancing its bound revision")
	}
	proposal.Bundles[0].BaseRevision = 1
	proposal.Bundles[0].BaseHash = first.Preview.DraftHash
	proposal.Bundles[0].Layers = append(proposal.Bundles[0].Layers, configuration.Layer{
		Kind: "device", ID: n.target.Device, Revision: 1,
		Changes: []configuration.Change{{Path: "/network/dnsStrategy", Operation: "set", Value: json.RawMessage(`"ipv4_only"`)}},
	})
	publishDesired("second desired origin")
	expect("new desired awaiting issuance", "different_revision", 2, 2)
	if e := n.publisher.RunOnce(ctx, n.f.now); e != nil {
		t.Fatal(e)
	}
	expect("second managed issuance", "matches_desired", 2, 3)
	// An older publisher only updates the envelope and its policy revision.
	if _, e := fixtureSigner.Exec(`UPDATE identity_devices SET revision=revision+1,publication=$2 WHERE id=$1`, n.target.Device, []byte("synthetic legacy envelope")); e != nil {
		t.Fatal(e)
	}
	expect("later untracked issuance", "unlinked", 2, 4)
}

func TestConfigurationInventoryRequiresLiveDeviceParentACLAndCipherIntegrity(t *testing.T) {
	for _, kind := range []string{"parent-read", "account", "device", "cipher", "cancelled", "expired-session"} {
		t.Run(kind, func(t *testing.T) {
			n, c, p, publisher := layerPublisherFixture(t)
			r := prepareLayerPreview(t, n, c, p, publisher, "guarded inventory preview")
			queueLayerPublish(t, n, c, r, "guarded inventory publication")
			if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			exec := func(query string, args ...any) {
				t.Helper()
				if _, e := fixtureOwner.Exec(query, args...); e != nil {
					t.Fatal(e)
				}
			}
			ctx := context.Background()
			at := n.f.now
			until := at.Unix() + 180
			switch kind {
			case "parent-read":
				exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID)
				exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'configuration.drafts.read','device',$2,$3)`, n.actor.ID, n.target.Device, at.Unix()+3600)
			case "account":
				exec(`UPDATE identity_accounts SET enabled=false WHERE owner=$1`, n.target.Owner)
			case "device":
				exec(`UPDATE identity_devices SET active=false WHERE id=$1`, n.target.Device)
			case "cipher":
				bad, e := enrollment.NewStore(fixtureControl, bytes.Repeat([]byte{92}, 32))
				if e != nil {
					t.Fatal(e)
				}
				c.Store = bad
			case "cancelled":
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelCtx
			case "expired-session":
				until = at.Unix()
			}
			if _, e := c.inventory(ctx, n.actor.ID, n.target.Device, until, at); e == nil {
				t.Fatal("unsafe desired view admitted", kind)
			}
			for _, column := range []string{"active", "approved", "request_body", "receipt", "owner", "jkt"} {
				var write bool
				if e := fixtureControl.QueryRow(`SELECT has_column_privilege(current_user,'identity_devices',$1,'UPDATE')`, column).Scan(&write); e != nil || write {
					t.Fatal("row lock guard conferred identity mutation", column, e)
				}
			}
		})
	}
}

func TestConfigurationHistoryBindsImmutableBaseWhileRecheckingLiveAuthority(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	first := prepareLayerPreview(t, n, c, p, publisher, "history initial preview")
	queueLayerPublish(t, n, c, first, "history initial publish")
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	n.f.now = n.f.now.Add(2 * time.Second)
	p.DraftRevision++
	p.Bundles[0].BaseRevision = 1
	p.Bundles[0].BaseHash = first.Preview.DraftHash
	p.Bundles[0].Layers = append(p.Bundles[0].Layers, configuration.Layer{Kind: "device", ID: n.target.Device, Revision: 1, Changes: []configuration.Change{{Path: "/network/dnsStrategy", Operation: "set", Value: json.RawMessage(`"ipv4_only"`)}}})
	second := prepareLayerPreview(t, n, c, p, publisher, "history second preview")
	queueLayerPublish(t, n, c, second, "history second publish")
	if e := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	call := func(revision int64, hash string) (ConfigurationInventory, error) {
		t.Helper()
		raw, token, proof := configurationCall(t, n, c, "configuration.history.get", identity.Hash([]byte(fmt.Sprintf("history %d %s", revision, hash))), map[string]any{"id": n.target.Device, "revision": revision, "hash": hash})
		v, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
		if e != nil {
			return ConfigurationInventory{}, e
		}
		return v.(ConfigurationInventory), nil
	}
	old, e := call(1, first.Preview.DraftHash)
	if e != nil || !old.Historical || old.Revision != 1 || old.CurrentRevision != 2 || old.Hash != first.Preview.DraftHash || len(old.Layers) != 1 || old.Effective == nil {
		t.Fatal("immutable historical base", e)
	}
	current, e := inventoryCall(t, n, c, n.target.Device, "history current desired")
	if e != nil || current.Historical || current.Revision != 2 || current.CurrentRevision != 2 || len(current.Layers) != 2 {
		t.Fatal("current view confused with historical base", e)
	}
	for _, test := range []struct {
		revision int64
		hash     string
	}{{0, first.Preview.DraftHash}, {1, second.Preview.DraftHash}, {3, first.Preview.DraftHash}, {1, "invalid"}} {
		if _, e = call(test.revision, test.hash); !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("unbound historical revision", e)
		}
	}
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = call(1, first.Preview.DraftHash); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("historical rights survived live withdrawal", e)
	}
}
