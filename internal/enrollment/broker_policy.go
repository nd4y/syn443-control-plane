package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

// BrokerPolicyResource is public-to-the-signer metadata, never a provider PAT.
// Per-user auto-groups must also be present in the independently authorized Grant.
type BrokerPolicyResource struct {
	ResourceID       string   `json:"resourceId"`
	Revision         int64    `json:"revision"`
	AccountID        string   `json:"accountId"`
	ManagementOrigin string   `json:"managementOrigin"`
	NetworkID        string   `json:"networkId"`
	Groups           []string `json:"groups"`
}

func (BrokerPolicyResource) String() string   { return "OverlayBrokerPolicyResource([redacted])" }
func (BrokerPolicyResource) GoString() string { return "OverlayBrokerPolicyResource([redacted])" }

type BrokerPolicies struct {
	store     *Store
	service   string
	resources map[string]BrokerPolicyResource
}

func (*BrokerPolicies) String() string   { return "OverlayBrokerPolicies([redacted])" }
func (*BrokerPolicies) GoString() string { return "OverlayBrokerPolicies([redacted])" }
func NewBrokerPolicies(store *Store, service string, resources []BrokerPolicyResource) (*BrokerPolicies, error) {
	if store == nil || store.DB == nil || !brokerIdentifier.MatchString(service) || len(service) > 64 || len(resources) < 1 || len(resources) > 16 {
		return nil, identity.ErrInvalid
	}
	result := &BrokerPolicies{store: store, service: service, resources: map[string]BrokerPolicyResource{}}
	for _, r := range resources {
		origin, e := overlay.ManagementOrigin(r.ManagementOrigin)
		if e != nil || origin != r.ManagementOrigin || !brokerIdentifier.MatchString(r.ResourceID) || len(r.ResourceID) > 64 || !brokerIdentifier.MatchString(r.AccountID) || !brokerIdentifier.MatchString(r.NetworkID) || len(r.NetworkID) > 64 || r.Revision < 1 || r.Revision > 9007199254740991 || len(r.Groups) < 1 || len(r.Groups) > 16 {
			return nil, identity.ErrInvalid
		}
		if _, exists := result.resources[r.ResourceID]; exists {
			return nil, identity.ErrInvalid
		}
		seen := map[string]bool{}
		for _, g := range r.Groups {
			if !brokerIdentifier.MatchString(g) || seen[g] {
				return nil, identity.ErrInvalid
			}
			seen[g] = true
		}
		r.Groups = append([]string(nil), r.Groups...)
		result.resources[r.ResourceID] = r
	}
	return result, nil
}

type brokerPolicyHead struct {
	namespace, device, owner, jkt, reference string
	version                                  int64
}
type brokerPolicyChange struct {
	before  *brokerPolicyHead
	after   brokerPolicyHead
	scope   BrokerScope
	reserve bool
}
type brokerPolicyFence struct {
	policies *BrokerPolicies
	changes  []brokerPolicyChange
	until    int64
}

func sameGroups(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
func (m *BrokerPolicies) metadata(b BrokerScope) error {
	r, ok := m.resources[b.Binding.Address.ResourceID]
	management, e := overlay.ManagementOrigin(b.Binding.Address.ManagementURL)
	if !ok || e != nil || r.Revision != b.ResourceRevision || r.AccountID != b.Account || r.ManagementOrigin != management || r.NetworkID != b.Binding.Address.NetworkID || len(b.Groups) < 1 || len(b.Groups) > 16 {
		return ErrDenied
	}
	for _, g := range b.Groups {
		if !slices.Contains(r.Groups, g) {
			return ErrDenied
		}
	}
	return nil
}
func (m *BrokerPolicies) readHead(ctx context.Context, namespace string) (*brokerPolicyHead, error) {
	h := &brokerPolicyHead{namespace: namespace}
	e := m.store.DB.QueryRowContext(ctx, `SELECT device,owner,jkt,reference,version FROM identity_overlay_reference_heads WHERE namespace=$1`, namespace).Scan(&h.device, &h.owner, &h.jkt, &h.reference, &h.version)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return h, nil
}
func (m *BrokerPolicies) readHeadScope(ctx context.Context, h brokerPolicyHead) (BrokerScope, string, int64, error) {
	var protected []byte
	var hash, state string
	var used int64
	e := m.store.DB.QueryRowContext(ctx, `SELECT scope,scope_hash,state,provider_used FROM identity_overlay_broker WHERE device=$1 AND reference=$2 AND version=$3`, h.device, h.reference, h.version).Scan(&protected, &hash, &state, &used)
	if e != nil {
		return BrokerScope{}, "", 0, e
	}
	raw, e := m.store.Open(protected, brokerAAD(h.device, h.reference, h.version, "scope"))
	var b BrokerScope
	if e != nil || identity.Hash(raw) != hash || identity.Decode(raw, &b, true) != nil {
		return BrokerScope{}, "", 0, ErrUnavailable
	}
	namespace, e := overlay.Namespace(b.Binding.Address)
	if e != nil || namespace != h.namespace || b.Owner != h.owner || b.Binding.KeyThumbprint != h.jkt || b.Binding.Address.DeviceID != h.device || b.Binding.Reference != h.reference || b.Binding.Version != h.version {
		return BrokerScope{}, "", 0, ErrUnavailable
	}
	return b, state, used, nil
}

// Prepare replaces only server-owned reference/version fields and keeps a stable
// namespace across ordinary refreshes. It has no provider HTTP/secret access.
// New reference admission and dispatch scope are committed with the publication.
func (m *BrokerPolicies) Prepare(ctx context.Context, target ConfigurationTarget, g Grant, p *policy.Payload, now time.Time) (ApprovalFence, error) {
	if ctx == nil || m == nil || p == nil || target.Owner != Owner(g.Issuer, g.Subject) || target.GrantHash != g.Hash() {
		return nil, ErrDenied
	}
	if e := m.store.RuntimeRole(ctx, true); e != nil {
		return nil, e
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(p.EngineConfigB64)
	if e != nil {
		return nil, identity.ErrInvalid
	}
	var root map[string]json.RawMessage
	if identity.DecodeConfiguration(raw, &root) != nil || root == nil {
		return nil, identity.ErrInvalid
	}
	var outbounds []map[string]json.RawMessage
	if identity.DecodeConfiguration(root["outbounds"], &outbounds) != nil || len(outbounds) < 1 || len(outbounds) > 64 {
		return nil, identity.ErrInvalid
	}
	fence := &brokerPolicyFence{policies: m, until: p.OfflineUntilMs}
	for _, outbound := range outbounds {
		var kind string
		if json.Unmarshal(outbound["type"], &kind) != nil {
			return nil, identity.ErrInvalid
		}
		if kind != "netbird" {
			continue
		}
		if len(fence.changes) != 0 || !hasCapability(target.Capabilities, "overlay.credentials.v1") {
			return nil, ErrDenied
		}
		for _, field := range []string{"setup_key", "state_directory", "managed_namespace", "credential_pending", "recover_existing"} {
			if _, exists := outbound[field]; exists {
				return nil, identity.ErrInvalid
			}
		}
		var ref ManagedOverlayReference
		var management string
		if identity.Decode(outbound["managed"], &ref, true) != nil || identity.Decode(outbound["management_url"], &management, true) != nil {
			return nil, identity.ErrInvalid
		}
		resource, ok := m.resources[ref.ResourceID]
		groups := g.OverlayGroups[ref.ResourceID]
		if !ok || len(groups) < 1 {
			return nil, ErrDenied
		}
		address := overlay.Address{ServiceID: m.service, OwnerTag: overlayOwner(m.service, g.Issuer, g.Subject), DeviceID: target.Device, OverlayID: ref.OverlayID, Provider: "netbird", ResourceID: ref.ResourceID, NetworkID: ref.NetworkID, IdentityEpoch: ref.IdentityEpoch, ManagementURL: management}
		namespace, e := overlay.Namespace(address)
		if e != nil {
			return nil, e
		}
		scope := BrokerScope{Binding: overlay.CredentialBinding{Address: address, KeyThumbprint: target.Thumbprint, SecurityEpoch: p.SecurityEpoch, OfflineUntilMs: p.OfflineUntilMs}, Owner: target.Owner, GrantHash: target.GrantHash, ResourceRevision: resource.Revision, Account: resource.AccountID, Groups: append([]string(nil), groups...), DeadlineMs: min(p.OfflineUntilMs, now.Add(5*time.Minute).UnixMilli())}
		if e = m.metadata(scope); e != nil {
			return nil, e
		}
		before, e := m.readHead(ctx, namespace)
		if e != nil {
			return nil, e
		}
		change := brokerPolicyChange{before: before, after: brokerPolicyHead{namespace: namespace, device: target.Device, owner: target.Owner, jkt: target.Thumbprint, reference: random(), version: 1}, reserve: true}
		if before != nil {
			if before.device != target.Device || before.owner != target.Owner || before.jkt != target.Thumbprint {
				return nil, ErrDenied
			}
			existing, state, used, e := m.readHeadScope(ctx, *before)
			if e != nil {
				return nil, e
			}
			if !sameGroups(existing.Groups, scope.Groups) {
				return nil, ErrDenied
			}
			change.after = *before
			change.reserve = false
			if state == "cleared" && used == 0 && existing.DeadlineMs <= now.UnixMilli() {
				if before.version >= 9007199254740991 {
					return nil, ErrUnavailable
				}
				change.after.reference = random()
				change.after.version++
				change.reserve = true
			}
		}
		scope.Binding.Reference = change.after.reference
		scope.Binding.Version = change.after.version
		change.scope = scope
		ref.SetupReference = change.after.reference
		ref.SetupVersion = change.after.version
		encoded, _ := json.Marshal(ref)
		outbound["managed"] = encoded
		fence.changes = append(fence.changes, change)
	}
	if len(fence.changes) == 0 {
		return nil, nil
	}
	root["outbounds"], e = json.Marshal(outbounds)
	if e != nil {
		return nil, e
	}
	raw, e = json.Marshal(root)
	if e != nil {
		return nil, e
	}
	p.EngineConfigB64 = base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256(raw)
	p.ContentHash = hex.EncodeToString(hash[:])
	if !hasCapability(p.RequiredCapabilities, "overlay.credentials.v1") {
		p.RequiredCapabilities = append(p.RequiredCapabilities, "overlay.credentials.v1")
	}
	if e = p.Validate(now); e != nil {
		return nil, e
	}
	return fence, nil
}

func (f *brokerPolicyFence) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if f == nil || tx == nil || now.UnixMilli() >= f.until {
		return ErrDenied
	}
	for _, c := range f.changes {
		if e := f.policies.metadata(c.scope); e != nil {
			return e
		}
		var current brokerPolicyHead
		current.namespace = c.after.namespace
		e := tx.QueryRowContext(ctx, `SELECT device,owner,jkt,reference,version FROM identity_overlay_reference_heads WHERE namespace=$1 FOR UPDATE`, current.namespace).Scan(&current.device, &current.owner, &current.jkt, &current.reference, &current.version)
		if errors.Is(e, sql.ErrNoRows) {
			if c.before != nil {
				return ErrConflict
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO identity_overlay_reference_heads(namespace,device,owner,jkt,reference,version) VALUES($1,$2,$3,$4,$5,$6)`, c.after.namespace, c.after.device, c.after.owner, c.after.jkt, c.after.reference, c.after.version)
		} else if e == nil && current != c.after {
			if c.before == nil || current != *c.before {
				return ErrConflict
			}
			// Renew only a durable cleared/unused result. A registered/unknown record
			// cannot be bypassed by inserting a fresh setup reference.
			var state string
			var used int64
			if e = tx.QueryRowContext(ctx, `SELECT state,provider_used FROM identity_overlay_broker WHERE device=$1 AND reference=$2 AND version=$3 FOR UPDATE`, current.device, current.reference, current.version).Scan(&state, &used); e != nil {
				return e
			}
			if state != "cleared" || used != 0 {
				return ErrDenied
			}
			if _, e = tx.ExecContext(ctx, `UPDATE identity_overlay_broker SET retire=true WHERE device=$1 AND reference=$2 AND version=$3`, current.device, current.reference, current.version); e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, `UPDATE identity_overlay_reference_heads SET reference=$2,version=$3 WHERE namespace=$1`, current.namespace, c.after.reference, c.after.version)
		}
		if e != nil {
			return e
		}
		if c.reserve {
			if e = f.policies.store.ReserveOverlayBroker(ctx, tx, c.scope, brokerResourcePolicyFence{f.policies, c.scope}, now); e != nil {
				return e
			}
		}
	}
	return nil
}

type brokerResourcePolicyFence struct {
	policies *BrokerPolicies
	scope    BrokerScope
}

func (f brokerResourcePolicyFence) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || now.UnixMilli() >= f.scope.Binding.OfflineUntilMs {
		return ErrDenied
	}
	return f.policies.metadata(f.scope)
}

func ReadBrokerPolicyResources(path string) ([]BrokerPolicyResource, error) {
	raw, e := PrivateFile(path, 65536)
	if e != nil {
		return nil, e
	}
	var result []BrokerPolicyResource
	if identity.DecodeOperatorDocument(raw, &result) != nil || len(result) < 1 || len(result) > 16 {
		return nil, identity.ErrInvalid
	}
	return result, nil
}

// Maintenance and wrapping are polled independently of the long policy refresh.
// No provider HTTP runs here. A known unused/cleared old key schedules a new
// policy/ref publication; established/unknown identities never trigger renewal.
func (m *BrokerPolicies) Schedule(ctx context.Context, now time.Time) error {
	if e := m.store.RuntimeRole(ctx, true); e != nil {
		return e
	}
	if e := m.store.RetireWithdrawnOverlayBrokers(ctx, now); e != nil {
		return e
	}
	_, e := m.store.DB.ExecContext(ctx, `UPDATE identity_devices d SET refresh_after=LEAST(d.refresh_after,$1) FROM identity_overlay_reference_heads h,identity_overlay_broker b WHERE d.id=h.device AND d.active AND b.device=h.device AND b.reference=h.reference AND b.version=h.version AND b.state='cleared' AND b.provider_used=0 AND NOT b.retire AND b.deadline_ms<=$2`, now.Unix(), now.UnixMilli())
	return e
}
func (m *BrokerPolicies) DeliverReady(ctx context.Context, p *Publisher, roots map[string]*ecdsa.PublicKey, now time.Time) error {
	if p == nil || p.Store != m.store || p.Key == nil {
		return ErrDenied
	}
	rows, e := m.store.DB.QueryContext(ctx, `SELECT h.namespace,h.device,h.owner,h.jkt,h.reference,h.version FROM identity_overlay_reference_heads h JOIN identity_overlay_broker b ON b.device=h.device AND b.reference=h.reference AND b.version=h.version WHERE b.state='issued' AND NOT b.retire AND b.deadline_ms>$1 AND NOT EXISTS(SELECT 1 FROM identity_overlay_grants g WHERE g.device=b.device AND g.reference=b.reference AND g.version=b.version) ORDER BY b.created_ms,h.device LIMIT 16`, now.UnixMilli())
	if e != nil {
		return e
	}
	var heads []brokerPolicyHead
	for rows.Next() {
		var h brokerPolicyHead
		if e = rows.Scan(&h.namespace, &h.device, &h.owner, &h.jkt, &h.reference, &h.version); e != nil {
			rows.Close()
			return e
		}
		heads = append(heads, h)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	var failed bool
	for _, h := range heads {
		b, _, _, err := m.readHeadScope(ctx, h)
		g, ok := p.Grants[h.owner]
		if err != nil || !ok || g.Hash() != b.GrantHash || !sameGroups(g.OverlayGroups[b.Binding.Address.ResourceID], b.Groups) || m.metadata(b) != nil {
			failed = true
			continue
		}
		err = m.store.InstallReadyOverlayBroker(ctx, h.device, h.reference, h.version, m.service, p.KeyID, p.Key, roots, brokerResourcePolicyFence{m, b}, now)
		if err != nil {
			failed = true
		}
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}
