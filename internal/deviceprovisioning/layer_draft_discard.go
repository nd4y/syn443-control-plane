package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type ConfigurationDraftDiscard struct {
	ID         string `json:"id"`
	Revision   int64  `json:"revision"`
	TargetKind string `json:"targetKind"`
	TargetID   string `json:"targetId"`
}

type ConfigurationDraftDiscarded struct {
	ID        string `json:"id"`
	Revision  int64  `json:"revision"`
	Discarded bool   `json:"discarded"`
}

func (ConfigurationDraftDiscard) String() string     { return "PrivateDraftDiscard([redacted])" }
func (ConfigurationDraftDiscard) GoString() string   { return "PrivateDraftDiscard([redacted])" }
func (ConfigurationDraftDiscarded) String() string   { return "PrivateDraftDiscarded([redacted])" }
func (ConfigurationDraftDiscarded) GoString() string { return "PrivateDraftDiscarded([redacted])" }

// Only actor-private mutable storage changes. A tombstone fences old save
// replies and ID reuse; it grants no authority over approvals or active heads.
func (c *ConfigurationControl) discardDraft(ctx context.Context, actor, request, bodyHash string, input ConfigurationDraftDiscard, until int64, now time.Time) (ConfigurationDraftDiscarded, error) {
	result := ConfigurationDraftDiscarded{ID: input.ID, Revision: input.Revision, Discarded: true}
	if ctx == nil || c == nil || c.Store == nil || c.Store.DB == nil {
		return result, enrollment.ErrUnavailable
	}
	if !configurationObjectID.MatchString(input.ID) || input.Revision < 1 || input.Revision > 9007199254740991 || !configurationTargetShape(input.TargetKind, input.TargetID) || now.Unix() >= until {
		return result, enrollment.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	if e = layerACL(ctx, tx, actor, "configuration.drafts.write", input.TargetKind, input.TargetID, current().Unix()); e != nil {
		return result, e
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "configuration-private-drafts/"+actor); e != nil {
		return result, enrollment.ErrUnavailable
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM managed_configuration_draft_ops WHERE actor=$1 AND expires_ms<=$2`, actor, current().UnixMilli()); e != nil {
		return result, enrollment.ErrUnavailable
	}
	var kind, target string
	var revision, expires int64
	var discarded bool
	e = tx.QueryRowContext(ctx, `SELECT target_kind,target_id,revision,expires_ms,discarded FROM managed_configuration_drafts WHERE actor=$1 AND id=$2 FOR UPDATE`, actor, input.ID).Scan(&kind, &target, &revision, &expires, &discarded)
	if e == sql.ErrNoRows {
		return result, enrollment.ErrDenied
	}
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	if kind != input.TargetKind || target != input.TargetID || revision != input.Revision {
		return result, enrollment.ErrConflict
	}
	if current().UnixMilli() >= expires {
		return result, enrollment.ErrDenied
	}
	var previous string
	var response []byte
	e = tx.QueryRowContext(ctx, `SELECT body_hash,response FROM managed_configuration_draft_ops WHERE actor=$1 AND request_id=$2`, actor, request).Scan(&previous, &response)
	if e == nil {
		if previous != bodyHash {
			return result, enrollment.ErrConflict
		}
		plain, err := c.Store.Open(response, configurationDraftOpAAD(actor, request))
		var saved ConfigurationDraftDiscarded
		if err != nil || identity.DecodeConfiguration(plain, &saved) != nil || saved != result || !discarded {
			return result, enrollment.ErrUnavailable
		}
	} else {
		if e != sql.ErrNoRows {
			return result, enrollment.ErrUnavailable
		}
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_configuration_draft_ops WHERE actor=$1`, actor).Scan(&count); e != nil {
			return result, enrollment.ErrUnavailable
		}
		if count >= 256 {
			return result, enrollment.ErrDenied
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return result, enrollment.ErrUnavailable
		}
		if !discarded {
			// Overwrite the encrypted proposal with a small encrypted receipt. Old
			// operation receipts retain their existing maximum24h lifetime, but
			// the put path cannot return them after this tombstone commits.
			protected := c.Store.Seal(raw, configurationDraftAAD(actor, input.ID, input.Revision))
			if _, e = tx.ExecContext(ctx, `UPDATE managed_configuration_drafts SET discarded=true,body_hash=$3,body=$4,saved_ms=$5,expires_ms=$6 WHERE actor=$1 AND id=$2`, actor, input.ID, configurationHash(raw), protected, current().UnixMilli(), current().Add(30*24*time.Hour).UnixMilli()); e != nil {
				return result, enrollment.ErrUnavailable
			}
		}
		protected := c.Store.Seal(raw, configurationDraftOpAAD(actor, request))
		if _, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_draft_ops(actor,request_id,body_hash,response,expires_ms) VALUES($1,$2,$3,$4,$5)`, actor, request, bodyHash, protected, current().Add(24*time.Hour).UnixMilli()); e != nil {
			return result, enrollment.ErrUnavailable
		}
	}
	if e = layerACL(ctx, tx, actor, "configuration.drafts.write", kind, target, current().Unix()); e != nil {
		return result, e
	}
	if current().Unix() >= until || current().UnixMilli() >= expires {
		return result, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return result, enrollment.ErrUnavailable
	}
	return result, nil
}
