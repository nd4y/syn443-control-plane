package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

//go:embed layer_schema.sql
var ConfigurationSchema string

//go:embed layer_roles.sql
var ConfigurationRoles string

type LayerBundle struct {
	Device       string                `json:"device"`
	BaseRevision int64                 `json:"baseRevision"`
	BaseHash     string                `json:"baseHash"`
	Layers       []configuration.Layer `json:"layers"`
}

// LayerProposal is portable, credential-free input. No field supplies the
// actual owner, device key, account grant or advertised capabilities.
type LayerProposal struct {
	DraftID         string        `json:"draftId"`
	DraftRevision   int64         `json:"draftRevision"`
	TargetKind      string        `json:"targetKind"`
	TargetID        string        `json:"targetId"`
	Mode            string        `json:"mode"`
	ApprovalUntilMs int64         `json:"approvalUntilMs"`
	Bundles         []LayerBundle `json:"bundles"`
}

func (LayerProposal) String() string   { return "ConfigurationProposal([redacted])" }
func (LayerProposal) GoString() string { return "ConfigurationProposal([redacted])" }
func (LayerBundle) String() string     { return "ConfigurationLayerBundle([redacted])" }
func (LayerBundle) GoString() string   { return "ConfigurationLayerBundle([redacted])" }

func configurationHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// effectiveProposalHash validates every recipient's complete inherited layers.
// The preview hashes portable effective values, not native profile credentials.
func effectiveProposalHash(ctx context.Context, proposal LayerProposal) (string, error) {
	if ctx == nil || len(proposal.Bundles) < 1 || len(proposal.Bundles) > 64 || !networkMode(proposal.Mode) {
		return "", enrollment.ErrDenied
	}
	type value struct{ Device, Hash string }
	values := make([]value, 0, len(proposal.Bundles))
	seen := map[string]bool{}
	for _, bundle := range proposal.Bundles {
		if bundle.Device == "" || seen[bundle.Device] {
			return "", enrollment.ErrDenied
		}
		seen[bundle.Device] = true
		effective, e := configuration.Merge(ctx, bundle.Layers, func(raw json.RawMessage) error {
			_, e := configuration.DecodeNetworkPlan(raw)
			return e
		})
		if e != nil {
			return "", e
		}
		values = append(values, value{bundle.Device, configurationHash(effective.Document)})
	}
	raw, e := json.Marshal(values)
	if e != nil {
		return "", enrollment.ErrDenied
	}
	return configurationHash(raw), nil
}

// SQLNetworkLayers is a read/fence authority for already approved immutable
// artifacts. Its constructor does not approve a request. Only the independently
// verified publication transaction may INSERT versions or advance SQL heads.
type SQLNetworkLayers struct {
	Store         *enrollment.Store
	ControlOrigin string
	Roots         map[string]*ecdsa.PublicKey
}

// ConfigurationRuntimeRole is opt-in with this feature's owner migration. A
// broadened API role must fail before any request or approved body is opened.
func ConfigurationRuntimeRole(ctx context.Context, db *sql.DB, publisher bool) error {
	if ctx == nil || db == nil {
		return enrollment.ErrDenied
	}
	expected := "syn443_control_api"
	if publisher {
		expected = "syn443_identity_publisher"
	}
	var current, session string
	var unsafe bool
	if e := db.QueryRowContext(ctx, `SELECT current_user,session_user,rolsuper OR rolinherit OR rolbypassrls OR rolcreatedb OR rolcreaterole OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) OR has_schema_privilege(current_user,'public','CREATE') FROM pg_roles r WHERE rolname=current_user`).Scan(&current, &session, &unsafe); e != nil || current != expected || session != expected || unsafe {
		return enrollment.ErrDenied
	}
	for _, table := range []string{"managed_configuration_previews", "managed_configuration_versions", "managed_configuration_heads"} {
		var read, insert, update, remove bool
		if e := db.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,$1::text,'SELECT'),has_any_column_privilege(current_user,$1::text,'INSERT'),has_any_column_privilege(current_user,$1::text,'UPDATE'),has_table_privilege(current_user,$1::text,'DELETE')`, table).Scan(&read, &insert, &update, &remove); e != nil || !read || remove || insert != publisher || update != (publisher && table == "managed_configuration_heads") {
			return enrollment.ErrDenied
		}
	}
	var insertRequest, updateRequest, mutableReceipt, insertState bool
	if e := db.QueryRowContext(ctx, `SELECT has_any_column_privilege(current_user,'managed_configuration_requests','INSERT'),has_any_column_privilege(current_user,'managed_configuration_requests','UPDATE'),has_column_privilege(current_user,'managed_configuration_requests','receipt','UPDATE'),has_column_privilege(current_user,'managed_configuration_requests','state','INSERT')`).Scan(&insertRequest, &updateRequest, &mutableReceipt, &insertState); e != nil || insertRequest == publisher || updateRequest != publisher || mutableReceipt || insertState {
		return enrollment.ErrDenied
	}
	for _, table := range []string{"managed_configuration_layer_versions", "managed_configuration_layer_heads", "managed_configuration_assignments"} {
		var read, insert, update, remove bool
		if e := db.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,$1::text,'SELECT'),has_any_column_privilege(current_user,$1::text,'INSERT'),has_any_column_privilege(current_user,$1::text,'UPDATE'),has_table_privilege(current_user,$1::text,'DELETE')`, table).Scan(&read, &insert, &update, &remove); e != nil || !read || insert != publisher || update != (publisher && table != "managed_configuration_layer_versions") || remove != (publisher && table == "managed_configuration_assignments") {
			return enrollment.ErrDenied
		}
	}
	return nil
}

func (*SQLNetworkLayers) String() string   { return "SQLNetworkLayers([redacted])" }
func (*SQLNetworkLayers) GoString() string { return "SQLNetworkLayers([redacted])" }

type approvedLayerRow struct {
	device, owner, jkt, grant, actor, preview, hash, ticket string
	revision, issued, approved, expires                     int64
	body                                                    []byte
}

func (approvedLayerRow) String() string   { return "ApprovedLayerRow([redacted])" }
func (approvedLayerRow) GoString() string { return "ApprovedLayerRow([redacted])" }

func layerProposalAAD(id string) string { return "configuration-preview/v1/" + id }

func (a *SQLNetworkLayers) read(ctx context.Context, device string) (approvedLayerRow, error) {
	var r approvedLayerRow
	e := a.Store.DB.QueryRowContext(ctx, `SELECT v.device,v.revision,v.owner,v.jkt,v.grant_hash,v.actor,v.preview,v.body_hash,v.approved_at_ms,p.body,p.ticket,p.issued_at_ms,p.expires_at_ms FROM managed_configuration_heads h JOIN managed_configuration_versions v ON v.device=h.device AND v.revision=h.revision AND v.body_hash=h.body_hash JOIN managed_configuration_previews p ON p.id=v.preview AND p.actor=v.actor AND p.body_hash=v.body_hash WHERE h.device=$1`, device).Scan(&r.device, &r.revision, &r.owner, &r.jkt, &r.grant, &r.actor, &r.preview, &r.hash, &r.approved, &r.body, &r.ticket, &r.issued, &r.expires)
	if e == sql.ErrNoRows {
		return r, enrollment.ErrConfigurationUnassigned
	}
	if e != nil {
		return r, enrollment.ErrUnavailable
	}
	return r, nil
}

func (a *SQLNetworkLayers) PrepareLayers(ctx context.Context, target enrollment.ConfigurationTarget, now time.Time) (*ApprovedNetworkLayers, error) {
	if ctx == nil || a == nil || a.Store == nil || a.Store.DB == nil || target.CurrentRevision < 0 {
		return nil, enrollment.ErrDenied
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	target.Capabilities = append([]string(nil), target.Capabilities...)
	if e := a.Store.RuntimeRole(ctx, true); e != nil {
		return nil, e
	}
	if e := ConfigurationRuntimeRole(ctx, a.Store.DB, true); e != nil {
		return nil, e
	}
	r, e := a.read(ctx, target.Device)
	if e != nil {
		return nil, e
	}
	if r.owner != target.Owner || r.jkt != target.Thumbprint || r.grant != target.GrantHash || r.approved < r.issued || r.approved >= r.expires || r.approved > now.UnixMilli() {
		return nil, enrollment.ErrDenied
	}
	// The active artifact was accepted inside the ticket's original interval.
	// Refresh authenticates that same publisher statement, not an expired admin
	// access token. Current SQL authority and every source fence still repeat.
	preview, e := configuration.VerifyPreview(ctx, r.ticket, a.Roots, a.ControlOrigin, r.actor, time.UnixMilli(r.issued))
	if e != nil || preview.IssuedAtMs != r.issued || preview.ExpiresAtMs != r.expires || preview.DraftHash != r.hash {
		return nil, enrollment.ErrDenied
	}
	raw, e := a.Store.Open(r.body, layerProposalAAD(r.preview))
	if e != nil || configurationHash(raw) != r.hash {
		return nil, enrollment.ErrUnavailable
	}
	var proposal LayerProposal
	if identity.DecodeConfiguration(raw, &proposal) != nil || proposal.DraftID != preview.DraftID || proposal.DraftRevision != preview.DraftRevision || proposal.TargetKind != preview.TargetKind || proposal.TargetID != preview.TargetID || proposal.Mode != preview.Mode || proposal.ApprovalUntilMs <= now.UnixMilli() || proposal.ApprovalUntilMs < r.approved || proposal.ApprovalUntilMs-r.approved > 366*24*time.Hour.Milliseconds() || len(proposal.Bundles) != len(preview.Recipients) {
		return nil, enrollment.ErrDenied
	}
	effective, e := effectiveProposalHash(ctx, proposal)
	if e != nil || effective != preview.EffectiveHash {
		return nil, enrollment.ErrDenied
	}
	capabilities, e := configuration.PreviewCapabilitiesHash(target.Capabilities)
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	var selected *LayerBundle
	for i, bundle := range proposal.Bundles {
		recipient := preview.Recipients[i]
		if bundle.Device != recipient.Device || bundle.BaseRevision != recipient.BaseRevision || bundle.BaseHash != recipient.BaseHash {
			return nil, enrollment.ErrDenied
		}
		if bundle.Device == target.Device {
			if recipient.Owner != r.owner || recipient.Thumbprint != r.jkt || recipient.GrantHash != r.grant || recipient.CapabilitiesHash != capabilities || bundle.BaseRevision != r.revision-1 || selected != nil {
				return nil, enrollment.ErrDenied
			}
			copy := bundle
			selected = &copy
		}
	}
	if selected == nil {
		return nil, enrollment.ErrDenied
	}
	fence := &storedLayerFence{authority: a, row: r, kind: proposal.TargetKind, id: proposal.TargetID, until: min(proposal.ApprovalUntilMs, now.Add(7*24*time.Hour).UnixMilli())}
	tx, e := a.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	if e = fence.Lock(ctx, tx, now); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, enrollment.ErrUnavailable
	}
	return &ApprovedNetworkLayers{Target: target, Layers: selected.Layers, Mode: proposal.Mode, UntilMs: fence.until, Fence: fence}, nil
}

type storedLayerFence struct {
	authority *SQLNetworkLayers
	row       approvedLayerRow
	kind, id  string
	until     int64
}

func (*storedLayerFence) String() string   { return "ApprovedLayerFence([redacted])" }
func (*storedLayerFence) GoString() string { return "ApprovedLayerFence([redacted])" }

func layerACL(ctx context.Context, tx *sql.Tx, actor, action, kind, id string, now int64) error {
	var allowed string
	e := tx.QueryRowContext(ctx, `SELECT target_id FROM catalog_acl WHERE actor=$1 AND (action=$2 OR action='*') AND (target_kind=$3 OR target_kind='*') AND (target_id=$4 OR target_id='*') AND expires>$5 ORDER BY target_id LIMIT 1 FOR SHARE`, actor, action, kind, id, now).Scan(&allowed)
	if e == sql.ErrNoRows {
		return enrollment.ErrDenied
	}
	if e != nil {
		return enrollment.ErrUnavailable
	}
	return nil
}

func (f *storedLayerFence) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if ctx == nil || tx == nil || f == nil || now.UnixMilli() >= f.until {
		return enrollment.ErrDenied
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	r := f.row
	var grant, owner, jkt string
	var active, enabled bool
	var until int64
	if e := tx.QueryRowContext(ctx, `SELECT enabled,grant_hash,valid_until FROM identity_accounts WHERE owner=$1 FOR SHARE`, r.owner).Scan(&enabled, &grant, &until); e != nil {
		return enrollment.ErrDenied
	}
	if e := tx.QueryRowContext(ctx, `SELECT owner,jkt,active FROM identity_devices WHERE id=$1 FOR SHARE`, r.device).Scan(&owner, &jkt, &active); e != nil {
		return enrollment.ErrDenied
	}
	if !active || !enabled || until*1000 <= now.UnixMilli() || grant != r.grant || owner != r.owner || jkt != r.jkt {
		return enrollment.ErrDenied
	}
	var revision int64
	var hash string
	if e := tx.QueryRowContext(ctx, `SELECT revision,body_hash FROM managed_configuration_heads WHERE device=$1 FOR SHARE`, r.device).Scan(&revision, &hash); e != nil {
		return enrollment.ErrDenied
	}
	if revision != r.revision || hash != r.hash {
		return enrollment.ErrConflict
	}
	if e := layerACL(ctx, tx, r.actor, "configuration.publish", f.kind, f.id, now.Unix()); e != nil {
		return e
	}
	return layerACL(ctx, tx, r.actor, "configuration.assignments.write", "device", r.device, now.Unix())
}

var _ NetworkLayerAuthority = (*SQLNetworkLayers)(nil)
