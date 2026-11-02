//go:build postgres

package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func configurationCatalogFixture(t *testing.T) (storedLayersFixture, LayerProposal) {
	t.Helper()
	f := newStoredLayersFixture(t, "")
	if e := f.n.publisher.RunOnce(context.Background(), f.n.f.now); e != nil {
		t.Fatal(e)
	}
	var approved bool
	if e := fixtureOwner.QueryRow(`SELECT approved FROM identity_devices WHERE id=$1`, f.n.target.Device).Scan(&approved); e != nil || !approved {
		t.Fatal("recipient fixture is not independently approved", e)
	}
	p := f.proposal
	p.Bundles = append([]LayerBundle(nil), p.Bundles...)
	p.Bundles[0].BaseRevision = 1
	p.Bundles[0].BaseHash = f.preview.DraftHash
	return f, p
}
func seedConfigurationGlobal(t *testing.T, f storedLayersFixture, layer configuration.Layer) {
	t.Helper()
	raw, e := json.Marshal(layer)
	if e != nil {
		t.Fatal(e)
	}
	hash := configurationHash(raw)
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_layer_versions(kind,id,revision,body_hash,body,actor,preview,approved_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, layer.Kind, layer.ID, layer.Revision, hash, f.n.publisher.Store.Seal(raw, globalLayerAAD(layer.Kind, layer.ID, layer.Revision)), f.n.actor.ID, f.id, f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_layer_heads(kind,id,revision,body_hash) VALUES($1,$2,$3,$4)`, layer.Kind, layer.ID, layer.Revision, hash); e != nil {
		t.Fatal(e)
	}
}
func seedConfigurationAssignment(t *testing.T, f storedLayersFixture, layer configuration.Layer, position int) {
	t.Helper()
	raw, _ := json.Marshal(layer)
	if _, e := fixtureOwner.Exec(`INSERT INTO managed_configuration_assignments(device,position,kind,id,revision,body_hash,configuration_revision) VALUES($1,$2,$3,$4,$5,$6,1)`, f.n.target.Device, position, layer.Kind, layer.ID, layer.Revision, configurationHash(raw)); e != nil {
		t.Fatal(e)
	}
}

// Owner-only recipient seed tests the resolver, not an enrollment receipt producer.
func seedConfigurationDevice(t *testing.T, f storedLayersFixture, id string, approved bool) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	jwk := identity.PublicJWK(&key.PublicKey)
	thumb, _ := jwk.Thumbprint()
	raw, _ := json.Marshal(enrollment.Request{RequestID: identity.Hash([]byte("synthetic device/" + id)), Key: jwk, Capabilities: append([]string(nil), f.n.target.Capabilities...)})
	if _, e = fixtureOwner.Exec(`INSERT INTO identity_devices(id,owner,jkt,request_body,receipt,approved) VALUES($1,$2,$3,$4,$5,$6)`, id, f.n.target.Owner, thumb, raw, []byte("synthetic fixture receipt"), approved); e != nil {
		t.Fatal(e)
	}
}
func prepareCatalog(t *testing.T, f storedLayersFixture, p LayerProposal) *configurationLayerSnapshot {
	t.Helper()
	s, e := prepareConfigurationLayers(context.Background(), f.n.publisher.Store, f.n.actor.ID, "configuration.preview", p, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestConfigurationCatalogResolvesActualIdentityAndPreservesOwnedSnapshot(t *testing.T) {
	f, p := configurationCatalogFixture(t)
	s := prepareCatalog(t, f, p)
	if len(s.Targets) != 1 || s.Targets[0].Device != f.n.target.Device || s.Targets[0].CurrentRevision != 1 || s.Recipients[0].BaseRevision != 1 || s.Recipients[0].BaseHash != p.Bundles[0].BaseHash || len(s.Changes) != 1 || s.Changes[0].OldRevision != 0 {
		t.Fatal("actual recipient/base/layer resolution")
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", s, s, s.Changes[0], s.Changes[0]), f.n.target.Device) {
		t.Fatal("snapshot diagnostic leaked scope")
	}
	p.Bundles[0].Layers[0].Changes[0].Value = json.RawMessage(`999`)
	tx, e := fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = s.Lock(context.Background(), tx, f.now); e != nil {
		t.Fatal("caller mutation changed owned proposal", e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_devices SET revision=revision+1 WHERE id=$1`, f.n.target.Device); e != nil {
		t.Fatal(e)
	}
	tx, e = fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = s.Lock(context.Background(), tx, f.now); e != nil {
		t.Fatal("policy renewal incorrectly changed configuration impact", e)
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_layer_versions`).Scan(&count); e != nil || count != 0 {
		t.Fatal("snapshot secretly published a layer", e)
	}
}
func TestConfigurationCatalogEnforcesSharedParentVersionAndTargetScope(t *testing.T) {
	f, p := configurationCatalogFixture(t)
	layer := p.Bundles[0].Layers[0]
	seedConfigurationGlobal(t, f, layer)
	seedConfigurationAssignment(t, f, layer, 0)
	s := prepareCatalog(t, f, p)
	if s.Changes[0].OldRevision != 1 {
		t.Fatal("existing global layer not read")
	}
	p.Bundles[0].Layers[0].Revision = 2
	p.Bundles[0].Layers[0].Permissions = []configuration.Permission{{Path: "/network", Mode: "locked"}}
	if _, e := prepareConfigurationLayers(context.Background(), f.n.publisher.Store, f.n.actor.ID, "configuration.preview", p, f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("device draft changed a shared parent", e)
	}
	p.TargetKind = "template"
	p.TargetID = layer.ID
	s = prepareCatalog(t, f, p)
	if s.Changes[0].Revision != 2 || s.Changes[0].OldRevision != 1 || s.Changes[0].Hash == s.Changes[0].OldHash {
		t.Fatal("scoped next layer version")
	}
	p.Bundles[0].Layers[0].Revision = 3
	if _, e := prepareConfigurationLayers(context.Background(), f.n.publisher.Store, f.n.actor.ID, "configuration.preview", p, f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("global revision skipped", e)
	}
	for _, statement := range []string{`UPDATE managed_configuration_layer_versions SET body='changed'`, `DELETE FROM managed_configuration_layer_versions`, `UPDATE managed_configuration_layer_heads SET body_hash='wrong'`, `UPDATE managed_configuration_layer_heads SET revision=revision+2`} {
		if _, e := fixtureOwner.Exec(statement); e == nil {
			t.Fatal("immutable/CAS/FK guard missing", statement)
		}
	}
}
func TestConfigurationCatalogUserAndGroupImpactComesOnlyFromCommittedRows(t *testing.T) {
	f, p := configurationCatalogFixture(t)
	seedConfigurationDevice(t, f, "second-device", true)
	seedConfigurationDevice(t, f, "pending-device", false)
	p.TargetKind = "user"
	p.TargetID = f.n.target.Owner
	if _, e := prepareConfigurationLayers(context.Background(), f.n.publisher.Store, f.n.actor.ID, "configuration.preview", p, f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("caller omitted active approved user device", e)
	}
	p.Bundles = append(p.Bundles, LayerBundle{Device: "second-device", Layers: p.Bundles[0].Layers})
	sort.Slice(p.Bundles, func(i, j int) bool { return p.Bundles[i].Device < p.Bundles[j].Device })
	s := prepareCatalog(t, f, p)
	if len(s.Targets) != 2 {
		t.Fatal("user recipient set")
	}
	layer := f.proposal.Bundles[0].Layers[0]
	seedConfigurationGlobal(t, f, layer)
	seedConfigurationAssignment(t, f, layer, 0)
	group := configuration.Layer{ID: "group-a", Kind: "group", Revision: 1, Changes: []configuration.Change{}, Permissions: []configuration.Permission{}}
	seedConfigurationGlobal(t, f, group)
	seedConfigurationAssignment(t, f, group, 1)
	p.TargetKind = "group"
	p.TargetID = group.ID
	if _, e := prepareConfigurationLayers(context.Background(), f.n.publisher.Store, f.n.actor.ID, "configuration.preview", p, f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("caller-supplied group member trusted", e)
	}
	for i, b := range p.Bundles {
		if b.Device == f.n.target.Device {
			p.Bundles = []LayerBundle{p.Bundles[i]}
			break
		}
	}
	p.Bundles[0].Layers = append(p.Bundles[0].Layers, group)
	s = prepareCatalog(t, f, p)
	if len(s.Assignments) != 2 || len(s.Targets) != 1 || s.Targets[0].Device != f.n.target.Device {
		t.Fatal("committed group membership not resolved")
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET active=false WHERE id=$1`, f.n.target.Device); e != nil {
		t.Fatal(e)
	}
	tx, e := fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = s.Lock(context.Background(), tx, f.now); e == nil {
		t.Fatal("revoked device retained group authority")
	}
}
func TestConfigurationCatalogFinalFenceRejectsChangedGrantHeadMembershipAndCorruption(t *testing.T) {
	for _, kind := range []string{"account", "expired-account", "grant", "key-row", "base", "new-device", "cipher", "layer-head", "ACL", "expired-proposal"} {
		t.Run(kind, func(t *testing.T) {
			f, p := configurationCatalogFixture(t)
			layer := p.Bundles[0].Layers[0]
			seedConfigurationGlobal(t, f, layer)
			seedConfigurationAssignment(t, f, layer, 0)
			p.TargetKind = "user"
			p.TargetID = f.n.target.Owner
			s := prepareCatalog(t, f, p)
			at := f.now
			var e error
			switch kind {
			case "account":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false`)
			case "expired-account":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET valid_until=$1`, f.now.Unix())
			case "grant":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET grant_hash=$1`, identity.Hash([]byte("changed grant")))
			case "key-row":
				_, e = fixtureOwner.Exec(`UPDATE identity_devices SET active=false`)
			case "base":
				_, e = fixtureOwner.Exec(`DELETE FROM managed_configuration_heads WHERE device=$1`, f.n.target.Device)
			case "new-device":
				seedConfigurationDevice(t, f, "new-device", true)
			case "cipher":
				// Owner-only corruption injection explicitly bypasses the fixture
				// trigger; no runtime role can do this.
				_, e = fixtureOwner.Exec(`ALTER TABLE managed_configuration_layer_versions DISABLE TRIGGER managed_configuration_layer_version_guard`)
				if e != nil {
					t.Fatal(e)
				}
				_, e = fixtureOwner.Exec(`UPDATE managed_configuration_layer_versions SET body=$1`, []byte(strings.Repeat("x", 40)))
				if _, x := fixtureOwner.Exec(`ALTER TABLE managed_configuration_layer_versions ENABLE TRIGGER managed_configuration_layer_version_guard`); x != nil {
					t.Fatal(x)
				}
			case "layer-head":
				next := layer
				next.Revision = 2
				raw, _ := json.Marshal(next)
				_, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_layer_versions(kind,id,revision,body_hash,body,actor,preview,approved_at_ms) VALUES($1,$2,2,$3,$4,$5,$6,$7)`, next.Kind, next.ID, configurationHash(raw), f.n.publisher.Store.Seal(raw, globalLayerAAD(next.Kind, next.ID, 2)), f.n.actor.ID, f.id, f.now.UnixMilli())
				if e == nil {
					_, e = fixtureOwner.Exec(`UPDATE managed_configuration_layer_heads SET revision=2,body_hash=$1`, configurationHash(raw))
				}
			case "ACL":
				_, e = fixtureOwner.Exec(`DELETE FROM catalog_acl`)
			case "expired-proposal":
				at = time.UnixMilli(p.ApprovalUntilMs)
			}
			if e != nil {
				t.Fatal(e)
			}
			tx, e := fixtureSigner.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if e = s.Lock(context.Background(), tx, at); e == nil {
				t.Fatal("changed authority accepted", kind)
			}
		})
	}
}

func TestConfigurationCatalogRejectsUnboundTargetsAndLayerPrivileges(t *testing.T) {
	for _, kind := range []string{"missing-target", "wrong-base", "unknown-kind", "wrong-user-layer", "wrong-device-layer", "wrong-local-layer", "new-layer-revision", "shared-conflict", "layer-read", "layer-create", "assignment"} {
		t.Run(kind, func(t *testing.T) {
			f, p := configurationCatalogFixture(t)
			switch kind {
			case "missing-target":
				p.TargetID = "missing-device"
			case "wrong-base":
				p.Bundles[0].BaseHash = configurationHash([]byte("wrong base"))
			case "unknown-kind":
				p.TargetKind = "untrusted"
			case "wrong-user-layer", "wrong-device-layer", "wrong-local-layer":
				k := strings.TrimSuffix(strings.TrimPrefix(kind, "wrong-"), "-layer")
				p.Bundles[0].Layers = append(p.Bundles[0].Layers, configuration.Layer{ID: "foreign", Kind: k, Revision: 1, Changes: []configuration.Change{}, Permissions: []configuration.Permission{}})
			case "new-layer-revision":
				p.Bundles[0].Layers[0].Revision = 2
			case "shared-conflict":
				seedConfigurationDevice(t, f, "second-device", true)
				p.TargetKind = "user"
				p.TargetID = f.n.target.Owner
				var copy configuration.Layer
				raw, _ := json.Marshal(p.Bundles[0].Layers[0])
				json.Unmarshal(raw, &copy)
				copy.Permissions = []configuration.Permission{{Path: "/network", Mode: "locked"}}
				p.Bundles = append(p.Bundles, LayerBundle{Device: "second-device", Layers: []configuration.Layer{copy}})
				sort.Slice(p.Bundles, func(i, j int) bool { return p.Bundles[i].Device < p.Bundles[j].Device })
			case "layer-read", "layer-create", "assignment":
				if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl`); e != nil {
					t.Fatal(e)
				}
				actions := []string{"configuration.preview"}
				if kind != "assignment" {
					actions = append(actions, "configuration.assignments.write")
				}
				if kind != "layer-read" {
					actions = append(actions, "configuration.layers.read")
				}
				if kind != "layer-create" {
					actions = append(actions, "configuration.layers.create")
				}
				for _, action := range actions {
					if _, e := fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,$2,'*','*',$3)`, f.n.actor.ID, action, f.now.Unix()+300); e != nil {
						t.Fatal(e)
					}
				}
			}
			if _, e := prepareConfigurationLayers(context.Background(), f.n.publisher.Store, f.n.actor.ID, "configuration.preview", p, f.now); e == nil {
				t.Fatal("invalid authority admitted", kind)
			}
		})
	}
}

func TestConfigurationCatalogRejectsApiRoleMalformedInputAndRevokedAssignment(t *testing.T) {
	f, p := configurationCatalogFixture(t)
	for _, kind := range []string{"nil-context", "nil-store", "bad-actor", "bad-action", "bad-shape", "API-role", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			store := f.n.publisher.Store
			actor, action := f.n.actor.ID, "configuration.preview"
			proposal := p
			switch kind {
			case "nil-context":
				ctx = nil
			case "nil-store":
				store = nil
			case "bad-actor":
				actor = "short"
			case "bad-action":
				action = "configuration.ready"
			case "bad-shape":
				proposal.Mode = "untrusted"
			case "API-role":
				store, _ = enrollment.NewStore(fixtureControl, []byte(strings.Repeat("x", 32)))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, e := prepareConfigurationLayers(ctx, store, actor, action, proposal, f.now); e == nil {
				t.Fatal("invalid entry accepted", kind)
			}
		})
	}
	layer := p.Bundles[0].Layers[0]
	seedConfigurationGlobal(t, f, layer)
	seedConfigurationAssignment(t, f, layer, 0)
	p.TargetKind = "template"
	p.TargetID = layer.ID
	s := prepareCatalog(t, f, p)
	if _, e := fixtureOwner.Exec(`DELETE FROM managed_configuration_assignments`); e != nil {
		t.Fatal(e)
	}
	tx, e := fixtureSigner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = s.Lock(context.Background(), tx, f.now); e == nil {
		t.Fatal("removed template membership retained authority")
	}
	var absent *configurationLayerSnapshot
	if e = absent.Lock(context.Background(), tx, f.now); e == nil {
		t.Fatal("nil snapshot")
	}
	if e = s.Lock(nil, tx, f.now); e == nil {
		t.Fatal("nil fence context")
	}
	if e = s.Lock(context.Background(), nil, f.now); e == nil {
		t.Fatal("nil transaction")
	}
	for _, statement := range []string{`INSERT INTO managed_configuration_layer_heads VALUES('template','unauthorized',1,'bad')`, `DELETE FROM managed_configuration_assignments`, `UPDATE managed_configuration_layer_versions SET body='changed'`} {
		if _, e = fixtureControl.Exec(statement); e == nil {
			t.Fatal("API gained layer authority", statement)
		}
	}
	if _, e = fixtureOwner.Exec(`GRANT INSERT ON managed_configuration_layer_versions TO syn443_control_api`); e != nil {
		t.Fatal(e)
	}
	defer fixtureOwner.Exec(`REVOKE INSERT ON managed_configuration_layer_versions FROM syn443_control_api`)
	if e = ConfigurationRuntimeRole(context.Background(), fixtureControl, false); e == nil {
		t.Fatal("broadened API role accepted")
	}
}
