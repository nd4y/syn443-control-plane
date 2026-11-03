package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Mutable actor-private data. Saving or expiring a draft cannot alter an approved
// layer, configuration head, source grant or device policy.
type ConfigurationDraft struct {
	ID        string        `json:"id"`
	Revision  int64         `json:"revision"`
	Proposal  LayerProposal `json:"proposal"`
	SavedAtMs int64         `json:"savedAtMs"`
}

func (ConfigurationDraft) String() string   { return "ConfigurationDraft([redacted])" }
func (ConfigurationDraft) GoString() string { return "ConfigurationDraft([redacted])" }
func configurationDraftAAD(actor, id string, revision int64) string {
	return "configuration-draft/v1/" + actor + "/" + id + "/" + strconv.FormatInt(revision, 10)
}
func configurationDraftOpAAD(actor, request string) string {
	return "configuration-draft-operation/v1/" + actor + "/" + request
}

func (c *ConfigurationControl) getDraft(ctx context.Context, actor, id string, until int64, now time.Time) (ConfigurationDraft, error) {
	var draft ConfigurationDraft
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return draft, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	var kind, target, hash string
	var revision, saved, expires int64
	var protected []byte
	e = tx.QueryRowContext(ctx, `SELECT target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms FROM managed_configuration_drafts WHERE actor=$1 AND id=$2 FOR SHARE`, actor, id).Scan(&kind, &target, &revision, &hash, &protected, &saved, &expires)
	if e == sql.ErrNoRows {
		return draft, enrollment.ErrDenied
	}
	if e != nil {
		return draft, enrollment.ErrUnavailable
	}
	if e = layerACL(ctx, tx, actor, "configuration.drafts.read", kind, target, current().Unix()); e != nil {
		return draft, e
	}
	plain, e := c.Store.Open(protected, configurationDraftAAD(actor, id, revision))
	if e != nil || configurationHash(plain) != hash || identity.DecodeConfiguration(plain, &draft) != nil || draft.ID != id || draft.Revision != revision || draft.Proposal.DraftID != id || draft.Proposal.DraftRevision != revision || draft.SavedAtMs != saved || draft.Proposal.TargetKind != kind || draft.Proposal.TargetID != target {
		return draft, enrollment.ErrUnavailable
	}
	if current().UnixMilli() >= expires || current().Unix() >= until {
		return draft, enrollment.ErrDenied
	}
	if e = layerACL(ctx, tx, actor, "configuration.drafts.read", kind, target, current().Unix()); e != nil {
		return draft, e
	}
	if current().Unix() >= until {
		return draft, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return draft, enrollment.ErrUnavailable
	}
	return draft, nil
}

func (c *ConfigurationControl) putDraft(ctx context.Context, actor, request, bodyHash string, draft ConfigurationDraft, until int64, now time.Time) (ConfigurationDraft, error) {
	if !configurationObjectID.MatchString(draft.ID) || draft.Revision < 0 || draft.Revision >= 9007199254740991 || draft.SavedAtMs != 0 || draft.Proposal.DraftID != draft.ID || draft.Proposal.DraftRevision != draft.Revision+1 || !configurationTargetShape(draft.Proposal.TargetKind, draft.Proposal.TargetID) {
		return draft, enrollment.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	kind, target := draft.Proposal.TargetKind, draft.Proposal.TargetID
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return draft, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	if e = layerACL(ctx, tx, actor, "configuration.drafts.write", kind, target, current().Unix()); e != nil {
		return draft, e
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "configuration-private-drafts/"+actor); e != nil {
		return draft, enrollment.ErrUnavailable
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM managed_configuration_draft_ops WHERE actor=$1 AND expires_ms<=$2`, actor, current().UnixMilli()); e != nil {
		return draft, enrollment.ErrUnavailable
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM managed_configuration_drafts WHERE actor=$1 AND expires_ms<=$2`, actor, current().UnixMilli()); e != nil {
		return draft, enrollment.ErrUnavailable
	}
	var previous string
	var response []byte
	e = tx.QueryRowContext(ctx, `SELECT body_hash,response FROM managed_configuration_draft_ops WHERE actor=$1 AND request_id=$2`, actor, request).Scan(&previous, &response)
	if e == nil {
		if previous != bodyHash {
			return draft, enrollment.ErrConflict
		}
		plain, e := c.Store.Open(response, configurationDraftOpAAD(actor, request))
		var saved ConfigurationDraft
		if e != nil || identity.DecodeConfiguration(plain, &saved) != nil || saved.ID != draft.ID || saved.Proposal.TargetKind != kind || saved.Proposal.TargetID != target {
			return draft, enrollment.ErrUnavailable
		}
		if current().Unix() >= until {
			return draft, enrollment.ErrDenied
		}
		if e = layerACL(ctx, tx, actor, "configuration.drafts.write", kind, target, current().Unix()); e != nil {
			return draft, e
		}
		if current().Unix() >= until {
			return draft, enrollment.ErrDenied
		}
		if e = tx.Commit(); e != nil {
			return draft, enrollment.ErrUnavailable
		}
		return saved, nil
	}
	if e != sql.ErrNoRows {
		return draft, enrollment.ErrUnavailable
	}
	if validateProposalShape(ctx, draft.Proposal, current()) != nil {
		return draft, enrollment.ErrDenied
	}
	var operations int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_configuration_draft_ops WHERE actor=$1`, actor).Scan(&operations); e != nil {
		return draft, enrollment.ErrUnavailable
	}
	if operations >= 256 {
		return draft, enrollment.ErrDenied
	}
	var oldKind, oldTarget string
	var oldRevision int64
	e = tx.QueryRowContext(ctx, `SELECT target_kind,target_id,revision FROM managed_configuration_drafts WHERE actor=$1 AND id=$2 FOR UPDATE`, actor, draft.ID).Scan(&oldKind, &oldTarget, &oldRevision)
	if e != nil && e != sql.ErrNoRows {
		return draft, enrollment.ErrUnavailable
	}
	exists := e == nil
	if exists && (oldKind != kind || oldTarget != target) || oldRevision != draft.Revision {
		return draft, enrollment.ErrConflict
	}
	if !exists {
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_configuration_drafts WHERE actor=$1`, actor).Scan(&count); e != nil {
			return draft, enrollment.ErrUnavailable
		}
		if count >= 64 {
			return draft, enrollment.ErrDenied
		}
	}
	draft.Revision++
	draft.SavedAtMs = current().UnixMilli()
	raw, e := json.Marshal(draft)
	if e != nil || len(raw) > 262144 {
		return draft, enrollment.ErrDenied
	}
	protected := c.Store.Seal(raw, configurationDraftAAD(actor, draft.ID, draft.Revision))
	expires := current().Add(30 * 24 * time.Hour).UnixMilli()
	if exists {
		_, e = tx.ExecContext(ctx, `UPDATE managed_configuration_drafts SET revision=$3,body_hash=$4,body=$5,saved_ms=$6,expires_ms=$7 WHERE actor=$1 AND id=$2`, actor, draft.ID, draft.Revision, configurationHash(raw), protected, draft.SavedAtMs, expires)
	} else {
		_, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_drafts(actor,id,target_kind,target_id,revision,body_hash,body,saved_ms,expires_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, actor, draft.ID, kind, target, draft.Revision, configurationHash(raw), protected, draft.SavedAtMs, expires)
	}
	if e != nil {
		return draft, enrollment.ErrUnavailable
	}
	op := c.Store.Seal(raw, configurationDraftOpAAD(actor, request))
	if _, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_draft_ops(actor,request_id,body_hash,response,expires_ms) VALUES($1,$2,$3,$4,$5)`, actor, request, bodyHash, op, current().Add(24*time.Hour).UnixMilli()); e != nil {
		return draft, enrollment.ErrUnavailable
	}
	if e = layerACL(ctx, tx, actor, "configuration.drafts.write", kind, target, current().Unix()); e != nil {
		return draft, e
	}
	if current().Unix() >= until {
		return draft, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return draft, enrollment.ErrUnavailable
	}
	return draft, nil
}
