//go:build postgres

package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

type storedLayersFixture struct {
	n        networkFixture
	reader   *SQLNetworkLayers
	proposal LayerProposal
	preview  configuration.Preview
	id       string
	now      time.Time
}

// These tests seed immutable approved evidence as the fixture owner. They test
// the persistent reader/final fence, not the still separate request approval UI.
func newStoredLayersFixture(t *testing.T, change string) storedLayersFixture {
	t.Helper()
	n := newNetworkFixture(t)
	now := n.f.now
	proposal := LayerProposal{DraftID: "draft-a", DraftRevision: 1, TargetKind: "device", TargetID: n.target.Device, Mode: "wifi", ApprovalUntilMs: now.Add(30 * 24 * time.Hour).UnixMilli(), Bundles: []LayerBundle{{Device: n.target.Device, Layers: n.approved.Layers}}}
	capabilities, e := configuration.PreviewCapabilitiesHash(n.target.Capabilities)
	if e != nil {
		t.Fatal(e)
	}
	preview := configuration.Preview{SchemaVersion: 1, Origin: "https://control.example.invalid", Actor: n.actor.ID, RequestID: identity.Hash([]byte("synthetic-stored-preview-operation")), DraftID: proposal.DraftID, DraftRevision: proposal.DraftRevision, TargetKind: "device", TargetID: n.target.Device, Mode: "wifi", DependencyHash: configurationHash([]byte("synthetic immutable dependency vector")), IssuedAtMs: now.UnixMilli(), ExpiresAtMs: now.Add(3 * time.Minute).UnixMilli(), Recipients: []configuration.PreviewRecipient{{Owner: n.target.Owner, Device: n.target.Device, Thumbprint: n.target.Thumbprint, GrantHash: n.target.GrantHash, CapabilitiesHash: capabilities}}}
	switch change {
	case "expired":
		proposal.ApprovalUntilMs = now.Add(time.Second).UnixMilli()
	case "long-approval":
		proposal.ApprovalUntilMs = now.Add(367 * 24 * time.Hour).UnixMilli()
	case "draft":
		proposal.DraftID = "other-draft"
	case "draft-revision":
		proposal.DraftRevision++
	case "scope":
		proposal.TargetID = "other-device"
	case "mode":
		proposal.Mode = "cellular"
	case "empty-bundles":
		proposal.Bundles = nil
	case "bundle-device":
		proposal.Bundles[0].Device = "other-device"
	case "bundle-base":
		proposal.Bundles[0].BaseRevision = 1
	case "invalid-plan":
		proposal.Bundles[0].Layers[0].Changes[1].Value = json.RawMessage(`{"profiles":{},"chains":{},"balancers":{},"final":"direct","inbounds":[]}`)
	case "invalid-layers":
		proposal.Bundles[0].Layers = nil
	case "no-selection":
		preview.TargetKind = "group"
		preview.TargetID = "group-a"
		proposal.TargetKind = "group"
		proposal.TargetID = "group-a"
		proposal.Bundles[0].Device = "other-device"
		preview.Recipients[0].Device = "other-device"
	case "base-head":
		proposal.Bundles[0].BaseRevision = 1
		proposal.Bundles[0].BaseHash = configurationHash([]byte("previous head"))
		preview.Recipients[0].BaseRevision = 1
		preview.Recipients[0].BaseHash = proposal.Bundles[0].BaseHash
	case "capabilities":
		preview.Recipients[0].CapabilitiesHash = configurationHash([]byte("other capabilities"))
	}
	raw, e := json.Marshal(proposal)
	if e != nil {
		t.Fatal(e)
	}
	if change == "decode-body" {
		raw = []byte(`[]`)
	}
	preview.DraftHash = configurationHash(raw)
	preview.EffectiveHash, e = effectiveProposalHash(context.Background(), proposal)
	if e != nil {
		preview.EffectiveHash = configurationHash([]byte("invalid effective proposal"))
	}
	if change == "effective" {
		preview.EffectiveHash = configurationHash([]byte("different effective plan"))
	}
	ticket, e := configuration.SignPreview(context.Background(), preview, "fixture-root", n.f.key, now)
	if e != nil {
		t.Fatal(e)
	}
	id := identity.Hash([]byte("synthetic stored preview/" + change))
	protected := n.publisher.Store.Seal(raw, layerProposalAAD(id))
	if change == "cipher" {
		protected[0] ^= 1
	}
	if change == "body-hash" {
		protected = n.publisher.Store.Seal(append(raw, ' '), layerProposalAAD(id))
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_previews(id,actor,request_id,body_hash,body,ticket,issued_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, n.actor.ID, preview.RequestID, preview.DraftHash, protected, ticket, preview.IssuedAtMs, preview.ExpiresAtMs); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_versions(device,revision,owner,jkt,grant_hash,actor,preview,body_hash,approved_at_ms,approval_receipt) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9)`, n.target.Device, n.target.Owner, n.target.Thumbprint, n.target.GrantHash, n.actor.ID, id, preview.DraftHash, now.Add(time.Second).UnixMilli(), n.publisher.Store.Seal([]byte("synthetic independently accepted receipt fixture"), "fixture-receipt")); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO managed_configuration_heads(device,revision,body_hash) VALUES($1,1,$2)`, n.target.Device, preview.DraftHash); e != nil {
		t.Fatal(e)
	}
	a := &SQLNetworkLayers{Store: n.publisher.Store, ControlOrigin: preview.Origin, Roots: map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}}
	return storedLayersFixture{n, a, proposal, preview, id, now.Add(2 * time.Second)}
}

func TestSQLStoredLayersCompileAndRefreshAfterOriginalAdminSessionExpiry(t *testing.T) {
	f := newStoredLayersFixture(t, "")
	ctx := context.Background()
	n := f.n
	if e := ConfigurationRuntimeRole(ctx, fixtureControl, false); e != nil {
		t.Fatal(e)
	}
	n.publisher.Configurations = &NetworkAuthority{Layers: f.reader, Sources: n.authority.Sources}
	if e := n.publisher.RunOnce(ctx, f.now); e != nil {
		t.Fatal("first persisted publication", e)
	}
	// Refresh uses an already approved immutable artifact. It cannot rely on the
	// expired browser token, and the current policy revision is not the head ID.
	later := n.f.now.Add(10 * time.Minute)
	if later.Unix() <= n.f.v.p.Expires {
		t.Fatal("expiry fixture")
	}
	if e := n.publisher.RunOnce(ctx, later); e != nil {
		t.Fatal("refresh after admin expiry", e)
	}
	var revision int64
	var protected []byte
	if e := fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&revision, &protected); e != nil || revision != 2 {
		t.Fatal("refresh revision", revision, e)
	}
	raw, e := n.publisher.Store.Open(protected, "publication/v1/"+n.target.Device+"/"+fmt.Sprint(revision))
	if e != nil {
		t.Fatal(e)
	}
	verified, e := policy.VerifyBound(string(raw), f.reader.Roots, n.target.Device, n.target.Thumbprint, later)
	if e != nil {
		t.Fatal(e)
	}
	engine, _ := base64.RawURLEncoding.DecodeString(verified.EngineConfigB64)
	if !strings.Contains(string(engine), "proxy.example.invalid") || verified.OfflineUntilMs > n.f.now.Add(time.Hour).UnixMilli() {
		t.Fatal("template fallback or source lease extension")
	}
	target := n.target
	target.CurrentRevision = revision
	stored, e := f.reader.PrepareLayers(ctx, target, later)
	if e != nil || stored.Target.CurrentRevision != revision || stored.UntilMs > later.Add(7*24*time.Hour).UnixMilli() {
		t.Fatal("head/policy revision or lease", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", f.reader, f.reader, stored.Fence, stored.Fence), n.target.Device) {
		t.Fatal("diagnostic disclosure")
	}
}

func TestSQLStoredLayersRejectForeignCorruptExpiredAndUnapprovedEvidence(t *testing.T) {
	for _, change := range []string{"expired", "long-approval", "draft", "draft-revision", "scope", "mode", "empty-bundles", "bundle-device", "bundle-base", "invalid-plan", "invalid-layers", "no-selection", "base-head", "capabilities", "effective", "cipher", "decode-body", "body-hash"} {
		t.Run(change, func(t *testing.T) {
			f := newStoredLayersFixture(t, change)
			if value, e := f.reader.PrepareLayers(context.Background(), f.n.target, f.now); e == nil || value != nil {
				t.Fatal("unapproved evidence became a layer authority")
			}
		})
	}
	f := newStoredLayersFixture(t, "")
	for _, change := range []string{"device", "owner", "key", "grant", "revision", "capability", "root", "origin", "early", "cancelled", "role"} {
		t.Run(change, func(t *testing.T) {
			target := f.n.target
			a := *f.reader
			now := f.now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "device":
				target.Device = "unowned-device"
			case "owner":
				target.Owner = identity.Hash([]byte("foreign owner"))
			case "key":
				target.Thumbprint = identity.Hash([]byte("foreign key"))
			case "grant":
				target.GrantHash = identity.Hash([]byte("changed grant"))
			case "revision":
				target.CurrentRevision = -1
			case "capability":
				target.Capabilities = nil
			case "root":
				a.Roots = nil
			case "origin":
				a.ControlOrigin = "https://foreign.example.invalid"
			case "early":
				now = f.n.f.now
			case "cancelled":
				cancel()
			case "role":
				store, e := enrollment.NewStore(fixtureControl, make([]byte, 32))
				if e != nil {
					t.Fatal(e)
				}
				a.Store = store
			}
			if value, e := a.PrepareLayers(ctx, target, now); e == nil || value != nil {
				t.Fatal("foreign/obsolete authority accepted")
			}
		})
	}
	if _, e := (*SQLNetworkLayers)(nil).PrepareLayers(context.Background(), f.n.target, f.now); e == nil {
		t.Fatal("nil authority")
	}
	if _, e := f.reader.PrepareLayers(nil, f.n.target, f.now); e == nil {
		t.Fatal("nil context")
	}
}

func TestSQLStoredLayersFinalFenceRechecksHeadACLAndActualAccount(t *testing.T) {
	for _, change := range []string{"head", "acl", "expired-acl", "account", "expired-account", "grant", "device", "deadline", "cancelled", "source"} {
		t.Run(change, func(t *testing.T) {
			f := newStoredLayersFixture(t, "")
			ctx := context.Background()
			prepared, e := (&NetworkAuthority{Layers: f.reader, Sources: f.n.authority.Sources}).Prepare(ctx, f.n.target, f.now)
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "head":
				if _, e = fixtureOwner.Exec(`WITH next AS (INSERT INTO managed_configuration_versions SELECT device,2,owner,jkt,grant_hash,actor,preview,body_hash,approved_at_ms,approval_receipt FROM managed_configuration_versions WHERE device=$1 RETURNING device) UPDATE managed_configuration_heads h SET revision=2 FROM next WHERE h.device=next.device`, f.n.target.Device); e != nil {
					t.Fatal(e)
				}
			case "acl":
				_, e = fixtureOwner.Exec(`DELETE FROM catalog_acl`)
			case "expired-acl":
				_, e = fixtureOwner.Exec(`UPDATE catalog_acl SET expires=$1`, f.now.Unix())
			case "account":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false`)
			case "expired-account":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET valid_until=$1`, f.now.Unix())
			case "grant":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET grant_hash=$1`, identity.Hash([]byte("changed live grant")))
			case "device":
				_, e = fixtureOwner.Exec(`UPDATE identity_devices SET active=false`)
			case "deadline":
				f.now = time.UnixMilli(prepared.UntilMs)
			case "source":
				_, e = fixtureOwner.Exec(`UPDATE catalog_sources SET enabled=false`)
			}
			if e != nil {
				t.Fatal(e)
			}
			tx, e := fixtureSigner.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if change == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if e = prepared.Fence.Lock(ctx, tx, f.now); e == nil {
				t.Fatal("late invalidation bypassed final transaction fence")
			}
		})
	}
}

func TestSQLStoredLayersRolesImmutabilityAndLatePrivilegeContamination(t *testing.T) {
	f := newStoredLayersFixture(t, "")
	for _, db := range []*sql.DB{fixtureControl, fixtureSourceWorker, fixtureDevice} {
		for _, query := range []string{`INSERT INTO managed_configuration_heads(device,revision,body_hash) VALUES('foreign',1,'unapproved')`, `UPDATE managed_configuration_versions SET approved_at_ms=0`, `UPDATE managed_configuration_previews SET ticket='unapproved'`} {
			if _, e := db.Exec(query); e == nil {
				t.Fatal("runtime borrowed approval write authority")
			}
		}
	}
	for _, query := range []string{`UPDATE managed_configuration_versions SET approved_at_ms=0`, `DELETE FROM managed_configuration_previews`, `UPDATE managed_configuration_heads SET revision=revision+2`} {
		if _, e := fixtureOwner.Exec(query); e == nil {
			t.Fatal("immutable approval evidence or monotonic head overwritten")
		}
	}
	if _, e := fixtureSourceWorker.Exec(`SELECT body FROM managed_configuration_previews`); e == nil {
		t.Fatal("source worker read administrative evidence")
	}
	if _, e := fixtureOwner.Exec(`GRANT INSERT ON managed_configuration_versions TO syn443_control_api`); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if _, e := fixtureOwner.Exec(`REVOKE INSERT ON managed_configuration_versions FROM syn443_control_api`); e != nil {
			t.Error(e)
		}
	}()
	if !errors.Is(ConfigurationRuntimeRole(context.Background(), fixtureControl, false), enrollment.ErrDenied) {
		t.Fatal("broadened API role started")
	}
	if e := ConfigurationRuntimeRole(context.Background(), fixtureSigner, true); e != nil {
		t.Fatal(e)
	}
	if e := ConfigurationRuntimeRole(context.Background(), fixtureOwner, true); e == nil {
		t.Fatal("owner used as runtime")
	}
	if e := ConfigurationRuntimeRole(nil, fixtureSigner, true); e == nil {
		t.Fatal("nil context")
	}
	if e := ConfigurationRuntimeRole(context.Background(), nil, true); e == nil {
		t.Fatal("nil database")
	}
	if strings.Contains(fmt.Sprint(f.proposal, f.proposal.Bundles[0]), f.n.target.Device) {
		t.Fatal("proposal logging")
	}
}
