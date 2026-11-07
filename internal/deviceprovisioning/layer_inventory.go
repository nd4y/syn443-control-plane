package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// A device view never returns the complete multi-recipient proposal or native
// source credentials. Revision/hash describe desired server configuration;
// PolicyRevision is issued policy history, not a claim of Android activation.
type ConfigurationInventory struct {
	Device          string                   `json:"device"`
	Owner           string                   `json:"owner"`
	State           string                   `json:"state"`
	Revision        int64                    `json:"revision"`
	Hash            string                   `json:"hash"`
	PolicyRevision  int64                    `json:"policyRevision"`
	Mode            string                   `json:"mode"`
	ApprovalUntilMs int64                    `json:"approvalUntilMs"`
	Layers          []configuration.Layer    `json:"layers"`
	Effective       *configuration.Effective `json:"effective,omitempty"`
	CurrentRevision int64                    `json:"currentRevision"`
	Historical      bool                     `json:"historical,omitempty"`
	Activation      *ConfigurationActivation `json:"activation,omitempty"`
}

type ConfigurationActivation struct {
	State                string `json:"state"`
	PolicyRevision       int64  `json:"policyRevision,omitempty"`
	Outcome              string `json:"outcome,omitempty"`
	ActivePolicyRevision int64  `json:"activePolicyRevision"`
	ReceivedAtMs         int64  `json:"receivedAtMs,omitempty"`
}

func (ConfigurationInventory) String() string   { return "ConfigurationInventory([redacted])" }
func (ConfigurationInventory) GoString() string { return "ConfigurationInventory([redacted])" }

func (c *ConfigurationControl) inventory(ctx context.Context, actor, device string, authorityUntil int64, now time.Time) (ConfigurationInventory, error) {
	return c.inventoryAt(ctx, actor, device, 0, "", authorityUntil, now)
}

// Historical reads have the same live identity, grant and per-layer ACL gates
// as current reads. A caller must bind the expected immutable revision/hash.
func (c *ConfigurationControl) inventoryAt(ctx context.Context, actor, device string, revision int64, hash string, authorityUntil int64, now time.Time) (ConfigurationInventory, error) {
	r := ConfigurationInventory{Device: device, State: "unassigned", Layers: []configuration.Layer{}, Historical: revision > 0}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return r, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	if e = layerACL(ctx, tx, actor, "configuration.drafts.read", "device", device, current().Unix()); e != nil {
		return r, e
	}
	var grant string
	var active, approved, enabled bool
	var accountUntil int64
	var publicationUntil int64
	var publicationGrant string
	var jkt string
	// Lock the live authorization rows. The API has only a non-authoritative
	// guard-column UPDATE grant needed by PostgreSQL for SELECT FOR SHARE.
	e = tx.QueryRowContext(ctx, `SELECT d.owner,d.jkt,d.active,d.approved,d.revision,a.enabled,a.valid_until,a.grant_hash,d.offline_until,d.publication_grant_hash FROM identity_devices d JOIN identity_accounts a ON a.owner=d.owner WHERE d.id=$1 FOR SHARE OF a,d`, device).Scan(&r.Owner, &jkt, &active, &approved, &r.PolicyRevision, &enabled, &accountUntil, &grant, &publicationUntil, &publicationGrant)
	if e != nil || !active || !approved || !enabled || accountUntil <= current().Unix() {
		return r, enrollment.ErrDenied
	}
	var body []byte
	var preview, owner, thumb, versionGrant string
	e = tx.QueryRowContext(ctx, `SELECT v.revision,v.body_hash,p.body,v.preview,v.owner,v.jkt,v.grant_hash,h.revision FROM managed_configuration_heads h JOIN managed_configuration_versions v ON v.device=h.device AND v.revision=CASE WHEN $2::bigint=0 THEN h.revision ELSE $2::bigint END AND v.revision<=h.revision JOIN managed_configuration_previews p ON p.id=v.preview AND p.actor=v.actor AND p.body_hash=v.body_hash WHERE h.device=$1 AND ($2::bigint=0 AND v.body_hash=h.body_hash OR $2::bigint>0 AND v.body_hash=$3)`, device, revision, hash).Scan(&r.Revision, &r.Hash, &body, &preview, &owner, &thumb, &versionGrant, &r.CurrentRevision)
	if e == sql.ErrNoRows && revision > 0 {
		return r, enrollment.ErrDenied
	}
	if e != nil && e != sql.ErrNoRows {
		return r, enrollment.ErrUnavailable
	}
	if e == nil {
		if owner != r.Owner || thumb != jkt || versionGrant != grant {
			return r, enrollment.ErrDenied
		}
		raw, e := c.Store.Open(body, layerProposalAAD(preview))
		var proposal LayerProposal
		if e != nil || configurationHash(raw) != r.Hash || identity.DecodeConfiguration(raw, &proposal) != nil {
			return r, enrollment.ErrUnavailable
		}
		selected := false
		for _, bundle := range proposal.Bundles {
			if bundle.Device != device {
				continue
			}
			if selected || bundle.BaseRevision != r.Revision-1 {
				return r, enrollment.ErrUnavailable
			}
			selected = true
			r.Layers = bundle.Layers
		}
		if !selected {
			return r, enrollment.ErrUnavailable
		}
		for _, layer := range r.Layers {
			if e = layerACL(ctx, tx, actor, "configuration.layers.read", layer.Kind, layer.ID, current().Unix()); e != nil {
				return r, e
			}
		}
		effective, e := configuration.Merge(ctx, r.Layers, func(raw json.RawMessage) error { _, e := configuration.DecodeNetworkPlan(raw); return e })
		if e != nil || !networkMode(proposal.Mode) {
			return r, enrollment.ErrUnavailable
		}
		r.State = "assigned"
		r.Mode = proposal.Mode
		r.ApprovalUntilMs = proposal.ApprovalUntilMs
		r.Effective = &effective
		if r.ApprovalUntilMs <= current().UnixMilli() {
			r.State = "expired"
		}
	}
	if current().Unix() >= min(authorityUntil, accountUntil) {
		return r, enrollment.ErrDenied
	}
	if !r.Historical {
		observation := ConfigurationActivation{State: "awaiting_report"}
		if r.PolicyRevision == 0 {
			observation.State = "not_issued"
		}
		e = tx.QueryRowContext(ctx, `SELECT policy_revision,outcome,active_policy_revision,received_at_ms FROM identity_policy_activation WHERE device=$1`, device).Scan(
			&observation.PolicyRevision, &observation.Outcome, &observation.ActivePolicyRevision, &observation.ReceivedAtMs)
		if e == nil {
			observation.State = "historical"
			if observation.PolicyRevision == r.PolicyRevision && publicationGrant == grant && publicationUntil > current().Unix() {
				observation.State = "reported"
			}
		} else if e != sql.ErrNoRows {
			return r, enrollment.ErrUnavailable
		}
		r.Activation = &observation
	}
	if e = layerACL(ctx, tx, actor, "configuration.drafts.read", "device", device, current().Unix()); e != nil {
		return r, e
	}
	if current().Unix() >= min(authorityUntil, accountUntil) {
		return r, enrollment.ErrDenied
	}
	if e = ctx.Err(); e != nil {
		return r, e
	}
	if e = tx.Commit(); e != nil {
		return r, enrollment.ErrUnavailable
	}
	return r, nil
}
