package deviceprovisioning

import (
	"context"
	"math"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

type ConfigurationDraftSummary struct {
	ID        string `json:"id"`
	Revision  int64  `json:"revision"`
	SavedAtMs int64  `json:"savedAtMs"`
}

type ConfigurationDraftInventory struct {
	TargetKind string                      `json:"targetKind"`
	TargetID   string                      `json:"targetId"`
	Drafts     []ConfigurationDraftSummary `json:"drafts"`
}

func (ConfigurationDraftSummary) String() string   { return "PrivateDraftSummary([redacted])" }
func (ConfigurationDraftSummary) GoString() string { return "PrivateDraftSummary([redacted])" }
func (ConfigurationDraftInventory) String() string { return "PrivateDraftInventory([redacted])" }
func (ConfigurationDraftInventory) GoString() string {
	return "PrivateDraftInventory([redacted])"
}

// Metadata discovery only. Content remains behind the authenticated get/decrypt
// path. Listing cannot create an approval, alter a draft or publish a policy.
func (c *ConfigurationControl) draftInventory(ctx context.Context, actor, kind, target string, until int64, now time.Time) (ConfigurationDraftInventory, error) {
	result := ConfigurationDraftInventory{TargetKind: kind, TargetID: target, Drafts: []ConfigurationDraftSummary{}}
	if ctx == nil || c == nil || c.Store == nil || c.Store.DB == nil {
		return result, enrollment.ErrUnavailable
	}
	if !configurationTargetShape(kind, target) || now.Unix() >= until {
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
	if e = layerACL(ctx, tx, actor, "configuration.drafts.read", kind, target, current().Unix()); e != nil {
		return result, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT id,revision,saved_ms,expires_ms FROM managed_configuration_drafts WHERE actor=$1 AND target_kind=$2 AND target_id=$3 AND expires_ms>$4 ORDER BY saved_ms DESC,id LIMIT 65 FOR SHARE`, actor, kind, target, current().UnixMilli())
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	defer rows.Close()
	earliestExpiry := int64(math.MaxInt64)
	for rows.Next() {
		var row ConfigurationDraftSummary
		var expires int64
		if e = rows.Scan(&row.ID, &row.Revision, &row.SavedAtMs, &expires); e != nil || !configurationObjectID.MatchString(row.ID) || row.Revision < 1 || row.Revision > 9007199254740991 || row.SavedAtMs < 1 || row.SavedAtMs > 9007199254740991 || expires <= row.SavedAtMs || expires > 9007199254740991 {
			return result, enrollment.ErrUnavailable
		}
		earliestExpiry = min(earliestExpiry, expires)
		result.Drafts = append(result.Drafts, row)
		if len(result.Drafts) > 64 {
			return result, enrollment.ErrUnavailable
		}
	}
	if e = rows.Err(); e != nil {
		return result, enrollment.ErrUnavailable
	}
	rows.Close()
	if current().UnixMilli() >= earliestExpiry || current().Unix() >= until {
		return result, enrollment.ErrDenied
	}
	if e = layerACL(ctx, tx, actor, "configuration.drafts.read", kind, target, current().Unix()); e != nil {
		return result, e
	}
	if current().Unix() >= until {
		return result, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return result, enrollment.ErrUnavailable
	}
	return result, nil
}
