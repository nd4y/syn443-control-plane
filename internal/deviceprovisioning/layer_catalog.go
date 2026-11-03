package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type configurationAssignment struct {
	Device                          string
	Position                        int
	Kind, ID, Hash                  string
	Revision, ConfigurationRevision int64
}
type configurationLayerChange struct {
	Kind, ID, Hash, OldHash string
	Revision, OldRevision   int64
	Body                    []byte
}
type configurationLayerSnapshot struct {
	store         *enrollment.Store
	actor, action string
	proposal      LayerProposal
	Targets       []enrollment.ConfigurationTarget
	Recipients    []configuration.PreviewRecipient
	Assignments   []configurationAssignment
	Changes       []configurationLayerChange
	Hash          string
}

func (*configurationLayerSnapshot) String() string   { return "ConfigurationLayerSnapshot([redacted])" }
func (*configurationLayerSnapshot) GoString() string { return "ConfigurationLayerSnapshot([redacted])" }
func (configurationAssignment) String() string       { return "ConfigurationAssignment([redacted])" }
func (configurationAssignment) GoString() string     { return "ConfigurationAssignment([redacted])" }
func (configurationLayerChange) String() string      { return "ConfigurationLayerChange([redacted])" }
func (configurationLayerChange) GoString() string    { return "ConfigurationLayerChange([redacted])" }
func globalLayerAAD(kind, id string, revision int64) string {
	raw, _ := json.Marshal([]any{kind, id, revision})
	return "configuration-global-layer/v1/" + string(raw)
}

// Fixed cause names help administrative conflict diagnosis without exposing
// recipient identifiers, layer bodies or provider material.
func configurationConflict(cause string) error {
	return fmt.Errorf("configuration_%s: %w", cause, enrollment.ErrConflict)
}

// Resolve actual live recipients and globally immutable layer versions. This
// is private publisher input, never proof that an API draft was approved. All
// network/IdP work stays outside this short account/device/config transaction.
func prepareConfigurationLayers(ctx context.Context, store *enrollment.Store, actor, action string, p LayerProposal, now time.Time) (*configurationLayerSnapshot, error) {
	if ctx == nil || store == nil || !configurationRequestID.MatchString(actor) || action != "configuration.preview" && action != "configuration.publish" || validateProposalShape(ctx, p, now) != nil {
		return nil, enrollment.ErrDenied
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 262144 {
		return nil, enrollment.ErrDenied
	}
	var owned LayerProposal
	if identity.DecodeConfiguration(raw, &owned) != nil {
		return nil, enrollment.ErrDenied
	}
	p = owned
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if e := ConfigurationRuntimeRole(ctx, store.DB, true); e != nil {
		return nil, e
	}
	tx, e := store.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	s, e := resolveConfigurationLayers(ctx, tx, store, actor, action, p, now)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, enrollment.ErrUnavailable
	}
	return s, nil
}

func configurationDevices(ctx context.Context, tx *sql.Tx, p LayerProposal) ([]string, error) {
	query := `SELECT id,owner FROM identity_devices WHERE id=$1 AND active AND approved ORDER BY id LIMIT 65`
	switch p.TargetKind {
	case "device":
	case "user":
		query = `SELECT id,owner FROM identity_devices WHERE owner=$1 AND active AND approved ORDER BY id LIMIT 65`
	case "group", "template":
		query = `SELECT DISTINCT d.id,d.owner FROM identity_devices d JOIN managed_configuration_assignments a ON a.device=d.id JOIN managed_configuration_heads h ON h.device=a.device AND h.revision=a.configuration_revision WHERE a.id=$1 AND a.kind=$2 AND d.active AND d.approved ORDER BY d.id LIMIT 65`
	default:
		return nil, enrollment.ErrDenied
	}
	var rows *sql.Rows
	var e error
	if p.TargetKind == "group" || p.TargetKind == "template" {
		rows, e = tx.QueryContext(ctx, query, p.TargetID, p.TargetKind)
	} else {
		rows, e = tx.QueryContext(ctx, query, p.TargetID)
	}
	if e != nil {
		return nil, enrollment.ErrUnavailable
	}
	defer rows.Close()
	ids := []string{}
	owners := map[string]string{}
	for rows.Next() {
		var id, owner string
		if e = rows.Scan(&id, &owner); e != nil {
			return nil, enrollment.ErrUnavailable
		}
		ids = append(ids, id)
		owners[id] = owner
	}
	if rows.Err() != nil {
		return nil, enrollment.ErrUnavailable
	}
	if len(ids) < 1 || len(ids) > 64 {
		return nil, enrollment.ErrDenied
	}
	// PostgreSQL locale ordering may differ from the byte ordering used by the
	// signed Go/Kotlin manifest, especially for mixed-case opaque identifiers.
	sort.Slice(ids, func(i, j int) bool { return owners[ids[i]]+"/"+ids[i] < owners[ids[j]]+"/"+ids[j] })
	return ids, nil
}

func resolveConfigurationLayers(ctx context.Context, tx *sql.Tx, store *enrollment.Store, actor, action string, p LayerProposal, now time.Time) (*configurationLayerSnapshot, error) {
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	if _, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('configuration-layer-authority',0))`); e != nil {
		return nil, enrollment.ErrUnavailable
	}
	if e := layerACL(ctx, tx, actor, action, p.TargetKind, p.TargetID, current().Unix()); e != nil {
		return nil, e
	}
	// Parent membership is publisher-only. The user account lock additionally
	// fences a concurrent enrollment FK insert before resolving its full impact.
	owners := map[string]bool{}
	if p.TargetKind == "user" {
		owners[p.TargetID] = true
	} else {
		ids, e := configurationDevices(ctx, tx, p)
		if e != nil {
			return nil, e
		}
		for _, id := range ids {
			var owner string
			if e = tx.QueryRowContext(ctx, `SELECT owner FROM identity_devices WHERE id=$1`, id).Scan(&owner); e != nil {
				return nil, enrollment.ErrDenied
			}
			owners[owner] = true
		}
	}
	ordered := make([]string, 0, len(owners))
	for owner := range owners {
		ordered = append(ordered, owner)
	}
	sort.Strings(ordered)
	type account struct {
		grant string
		until int64
	}
	accounts := map[string]account{}
	for _, owner := range ordered {
		var a account
		var enabled bool
		if e := tx.QueryRowContext(ctx, `SELECT enabled,grant_hash,valid_until FROM identity_accounts WHERE owner=$1 FOR UPDATE`, owner).Scan(&enabled, &a.grant, &a.until); e != nil || !enabled || a.until <= current().Unix() {
			return nil, enrollment.ErrDenied
		}
		accounts[owner] = a
	}
	ids, e := configurationDevices(ctx, tx, p)
	if e != nil {
		return nil, e
	}
	if len(ids) != len(p.Bundles) {
		return nil, configurationConflict("recipient_impact_changed")
	}
	s := &configurationLayerSnapshot{store: store, actor: actor, action: action, proposal: p}
	shared := map[string]configurationLayerChange{}
	for i, id := range ids {
		bundle := p.Bundles[i]
		if bundle.Device != id {
			return nil, configurationConflict("recipient_order_changed")
		}
		var target enrollment.ConfigurationTarget
		var raw []byte
		var active, approved bool
		target.Device = id
		if e = tx.QueryRowContext(ctx, `SELECT owner,jkt,request_body,active,approved,revision FROM identity_devices WHERE id=$1 FOR SHARE`, id).Scan(&target.Owner, &target.Thumbprint, &raw, &active, &approved, &target.CurrentRevision); e != nil || !active || !approved {
			return nil, enrollment.ErrDenied
		}
		a, ok := accounts[target.Owner]
		if !ok {
			return nil, configurationConflict("recipient_owner_changed")
		}
		target.GrantHash = a.grant
		var request enrollment.Request
		if identity.Decode(raw, &request, true) != nil {
			return nil, enrollment.ErrDenied
		}
		thumb, e := request.Key.Thumbprint()
		if e != nil || thumb != target.Thumbprint {
			return nil, enrollment.ErrDenied
		}
		available, e := enrollment.EffectiveCapabilities(ctx, tx, id, request.Capabilities)
		if e != nil {
			return nil, e
		}
		target.Capabilities = append([]string(nil), available.Capabilities...)
		caps, e := configuration.PreviewCapabilitiesHash(target.Capabilities)
		if e != nil {
			return nil, enrollment.ErrDenied
		}
		var revision int64
		var hash string
		e = tx.QueryRowContext(ctx, `SELECT revision,body_hash FROM managed_configuration_heads WHERE device=$1 FOR SHARE`, id).Scan(&revision, &hash)
		if e != nil && e != sql.ErrNoRows {
			return nil, enrollment.ErrUnavailable
		}
		if revision != bundle.BaseRevision || hash != bundle.BaseHash {
			return nil, configurationConflict("base_changed")
		}
		if e = layerACL(ctx, tx, actor, "configuration.assignments.write", "device", id, current().Unix()); e != nil {
			return nil, e
		}
		rows, e := tx.QueryContext(ctx, `SELECT position,kind,id,revision,body_hash,configuration_revision FROM managed_configuration_assignments WHERE device=$1 ORDER BY position FOR SHARE`, id)
		if e != nil {
			return nil, enrollment.ErrUnavailable
		}
		for rows.Next() {
			v := configurationAssignment{Device: id}
			if e = rows.Scan(&v.Position, &v.Kind, &v.ID, &v.Revision, &v.Hash, &v.ConfigurationRevision); e != nil {
				rows.Close()
				return nil, enrollment.ErrUnavailable
			}
			if v.ConfigurationRevision != revision {
				rows.Close()
				return nil, configurationConflict("assignment_version_changed")
			}
			s.Assignments = append(s.Assignments, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, enrollment.ErrUnavailable
		}
		for _, layer := range bundle.Layers {
			if (layer.Kind == "user" && layer.ID != target.Owner) || ((layer.Kind == "device" || layer.Kind == "local") && layer.ID != id) {
				return nil, enrollment.ErrDenied
			}
			if e = layerACL(ctx, tx, actor, "configuration.layers.read", layer.Kind, layer.ID, current().Unix()); e != nil {
				return nil, e
			}
			body, e := json.Marshal(layer)
			if e != nil || len(body) > 262144 {
				return nil, enrollment.ErrDenied
			}
			change := configurationLayerChange{Kind: layer.Kind, ID: layer.ID, Revision: layer.Revision, Hash: configurationHash(body), Body: body}
			key := layer.Kind + "\x00" + layer.ID
			if prior, ok := shared[key]; ok {
				if prior.Revision != change.Revision || prior.Hash != change.Hash {
					return nil, configurationConflict("shared_layer_body_changed")
				}
				continue
			}
			var protected []byte
			e = tx.QueryRowContext(ctx, `SELECT h.revision,h.body_hash,v.body FROM managed_configuration_layer_heads h JOIN managed_configuration_layer_versions v ON v.kind=h.kind AND v.id=h.id AND v.revision=h.revision AND v.body_hash=h.body_hash WHERE h.kind=$1 AND h.id=$2 FOR SHARE OF h`, layer.Kind, layer.ID).Scan(&change.OldRevision, &change.OldHash, &protected)
			if e == nil {
				old, e := store.Open(protected, globalLayerAAD(layer.Kind, layer.ID, change.OldRevision))
				if e != nil || configurationHash(old) != change.OldHash {
					return nil, enrollment.ErrUnavailable
				}
				if change.Revision == change.OldRevision && change.Hash == change.OldHash {
					shared[key] = change
					continue
				}
				isTarget := layer.Kind == p.TargetKind && layer.ID == p.TargetID || p.TargetKind == "device" && layer.Kind == "local" && layer.ID == p.TargetID
				if !isTarget || change.Revision != change.OldRevision+1 {
					return nil, configurationConflict("parent_or_revision_changed")
				}
			} else if e == sql.ErrNoRows {
				if change.Revision != 1 {
					return nil, configurationConflict("initial_layer_revision")
				}
				if e = layerACL(ctx, tx, actor, "configuration.layers.create", layer.Kind, layer.ID, current().Unix()); e != nil {
					return nil, e
				}
			} else {
				return nil, enrollment.ErrUnavailable
			}
			shared[key] = change
		}
		s.Targets = append(s.Targets, target)
		s.Recipients = append(s.Recipients, configuration.PreviewRecipient{Owner: target.Owner, Device: id, Thumbprint: target.Thumbprint, GrantHash: target.GrantHash, BaseRevision: revision, BaseHash: hash, CapabilitiesHash: caps})
	}
	keys := make([]string, 0, len(shared))
	for key := range shared {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s.Changes = append(s.Changes, shared[key])
	}
	for _, a := range accounts {
		if a.until <= current().Unix() {
			return nil, enrollment.ErrDenied
		}
	}
	if current().UnixMilli() >= p.ApprovalUntilMs {
		return nil, enrollment.ErrDenied
	}
	// Exclude the periodically renewed VPN policy revision. Actual configuration
	// heads, memberships, grants, keys, capabilities and layer heads are fenced.
	raw, e := json.Marshal(struct {
		Recipients  []configuration.PreviewRecipient
		Assignments []configurationAssignment
		Layers      []configurationLayerChange
	}{s.Recipients, s.Assignments, s.Changes})
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	s.Hash = configurationHash(raw)
	return s, nil
}

func (s *configurationLayerSnapshot) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if s == nil || ctx == nil || tx == nil {
		return enrollment.ErrDenied
	}
	current, e := resolveConfigurationLayers(ctx, tx, s.store, s.actor, s.action, s.proposal, now)
	if e != nil {
		return e
	}
	if current.Hash != s.Hash {
		return configurationConflict("authority_changed")
	}
	return nil
}
