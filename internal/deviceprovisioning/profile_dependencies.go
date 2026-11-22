package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// The caller owns the current configuration head lock. Even an empty effective
// graph must mark the revision as indexed, so it is distinct from a legacy head.
func replaceProfileReferences(ctx context.Context, tx *sql.Tx, device string, revision int64, refs []catalog.ProfileReference) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM managed_configuration_profile_refs WHERE device=$1`, device); err != nil {
		return enrollment.ErrUnavailable
	}
	if len(refs) > 0 {
		raw, err := json.Marshal(refs)
		if err != nil {
			return enrollment.ErrDenied
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO managed_configuration_profile_refs(device,source_id,profile_id)
			SELECT $1,r."sourceId",r."profileId" FROM jsonb_to_recordset($2::jsonb) AS r("sourceId" text,"profileId" text)`, device, string(raw)); err != nil {
			return enrollment.ErrUnavailable
		}
	}
	r, err := tx.ExecContext(ctx, `UPDATE managed_configuration_heads SET indexed_profile_revision=revision,profile_retry_after_ms=0 WHERE device=$1 AND revision=$2`, device, revision)
	if err != nil {
		return enrollment.ErrUnavailable
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return enrollment.ErrConflict
	}
	return nil
}

// Recover only the source/profile identities from one previously committed
// proposal. This does not issue a grant, renew a lease or replay a publication.
func (p *ConfigurationPublisher) recoverProfileReferences(ctx context.Context, now time.Time) error {
	tx, err := p.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	var device, hash, previewID, actor, ticket string
	var revision, issued int64
	var protected []byte
	err = tx.QueryRowContext(ctx, `SELECT h.device,h.revision,h.body_hash,v.preview,v.actor,p.ticket,p.issued_at_ms,p.body
		FROM managed_configuration_heads h JOIN managed_configuration_versions v ON (v.device,v.revision,v.body_hash)=(h.device,h.revision,h.body_hash)
		JOIN managed_configuration_previews p ON (p.id,p.actor,p.body_hash)=(v.preview,v.actor,v.body_hash)
		WHERE h.indexed_profile_revision<>h.revision AND h.profile_retry_after_ms<=$1
		ORDER BY h.profile_retry_after_ms,h.device LIMIT 1 FOR UPDATE OF h SKIP LOCKED`, now.UnixMilli()).
		Scan(&device, &revision, &hash, &previewID, &actor, &ticket, &issued, &protected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return enrollment.ErrUnavailable
	}
	raw, err := p.Store.Open(protected, layerProposalAAD(previewID))
	auth, verification := configuration.VerifyPreview(ctx, ticket, p.Roots, p.Origin, actor, time.UnixMilli(issued))
	var proposal LayerProposal
	var refs []catalog.ProfileReference
	if err == nil && verification == nil && auth.IssuedAtMs == issued && auth.DraftHash == hash && configurationHash(raw) == hash && identity.DecodeConfiguration(raw, &proposal) == nil {
		for _, bundle := range proposal.Bundles {
			if bundle.Device != device || bundle.BaseRevision != revision-1 {
				continue
			}
			_, err = configuration.Merge(ctx, bundle.Layers, func(raw json.RawMessage) error {
				plan, err := configuration.DecodeNetworkPlan(raw)
				if err != nil {
					return err
				}
				refs, err = networkSelectionReferences(plan)
				return err
			})
			break
		}
	}
	if err != nil || refs == nil {
		// Keep the conservative fence and let other devices recover first.
		if _, err = tx.ExecContext(ctx, `UPDATE managed_configuration_heads SET profile_retry_after_ms=$2 WHERE device=$1`, device, now.Add(15*time.Minute).UnixMilli()); err != nil {
			return enrollment.ErrUnavailable
		}
		if err = tx.Commit(); err != nil {
			return enrollment.ErrUnavailable
		}
		return enrollment.ErrDenied
	}
	if err = replaceProfileReferences(ctx, tx, device, revision, refs); err != nil {
		return err
	}
	return tx.Commit()
}
