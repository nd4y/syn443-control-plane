package deviceprovisioning

import (
	"context"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

// An assurance challenge is only a denial for an otherwise scoped actor. Do
// not turn an unknown/foreign object or a withdrawn grant into a sign-in hint.
// This preflight reads metadata only and never queues, edits, approves or signs.
func (c *ConfigurationControl) reauthenticationAuthority(ctx context.Context, actor string, envelope invitation.Envelope, until int64, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() int64 { return now.Add(time.Since(started)).Unix() }
	if current() >= until {
		return enrollment.ErrDenied
	}
	permission, kind, target := "", "", ""
	var id struct {
		ID string `json:"id"`
	}
	switch envelope.Action {
	case "configuration.preview.request":
		var input configurationPreviewInput
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil || validateProposalShape(ctx, input.Proposal, now) != nil {
			return enrollment.ErrDenied
		}
		permission, kind, target = "configuration.preview", input.Proposal.TargetKind, input.Proposal.TargetID
	case "configuration.publish":
		var input configurationPublishInput
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil || !configurationRequestID.MatchString(input.PreviewID) {
			return enrollment.ErrDenied
		}
		var protected []byte
		var hash string
		if e := c.Store.DB.QueryRowContext(ctx, `SELECT body,body_hash FROM managed_configuration_previews WHERE id=$1 AND actor=$2 AND ticket=$3`, input.PreviewID, actor, input.Ticket).Scan(&protected, &hash); e != nil {
			return enrollment.ErrDenied
		}
		raw, e := c.Store.Open(protected, layerProposalAAD(input.PreviewID))
		var proposal LayerProposal
		if e != nil || configurationHash(raw) != hash || identity.DecodeConfiguration(raw, &proposal) != nil {
			return enrollment.ErrUnavailable
		}
		permission, kind, target = "configuration.publish", proposal.TargetKind, proposal.TargetID
	case "configuration.layers.draft.put":
		var input struct {
			Draft ConfigurationDraft `json:"draft"`
		}
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil {
			return enrollment.ErrDenied
		}
		permission, kind, target = "configuration.drafts.write", input.Draft.Proposal.TargetKind, input.Draft.Proposal.TargetID
	case "configuration.layers.draft.discard":
		var input ConfigurationDraftDiscard
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil || !configurationObjectID.MatchString(input.ID) || input.Revision < 1 {
			return enrollment.ErrDenied
		}
		permission, kind, target = "configuration.drafts.write", input.TargetKind, input.TargetID
	case "configuration.layers.draft.get", "configuration.request.get":
		if identity.DecodeConfiguration(envelope.Payload, &id) != nil || envelope.Action == "configuration.layers.draft.get" && !configurationObjectID.MatchString(id.ID) || envelope.Action == "configuration.request.get" && !configurationRequestID.MatchString(id.ID) {
			return enrollment.ErrDenied
		}
		query := `SELECT target_kind,target_id FROM managed_configuration_drafts WHERE actor=$1 AND id=$2`
		args := []any{actor, id.ID}
		permission = "configuration.drafts.read"
		if envelope.Action == "configuration.request.get" {
			query = `SELECT target_kind,target_id FROM managed_configuration_requests WHERE actor=$1 AND id=$2`
			permission = "configuration.requests.read"
		} else {
			query += ` AND NOT discarded AND expires_ms>$3`
			args = append(args, now.Add(time.Since(started)).UnixMilli())
		}
		if e := c.Store.DB.QueryRowContext(ctx, query, args...).Scan(&kind, &target); e != nil {
			return enrollment.ErrDenied
		}
	case "configuration.history.get":
		var input struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Hash     string `json:"hash"`
		}
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil || input.Revision < 1 || !configurationBodyHash.MatchString(input.Hash) {
			return enrollment.ErrDenied
		}
		var exists bool
		if e := c.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM managed_configuration_versions v JOIN managed_configuration_heads h ON h.device=v.device WHERE v.device=$1 AND v.revision=$2 AND v.body_hash=$3 AND v.revision<=h.revision)`, input.ID, input.Revision, input.Hash).Scan(&exists); e != nil || !exists {
			return enrollment.ErrDenied
		}
		permission, kind, target = "configuration.drafts.read", "device", input.ID
	default:
		return enrollment.ErrDenied
	}
	if !configurationTargetShape(kind, target) {
		return enrollment.ErrDenied
	}
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	if e = layerACL(ctx, tx, actor, permission, kind, target, current()); e != nil {
		return e
	}
	if current() >= until {
		return enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return enrollment.ErrUnavailable
	}
	return nil
}
