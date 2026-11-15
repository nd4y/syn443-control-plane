package catalog

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// NetworkDraft is an actor-private proposal. Its declared base is untrusted until
// independent preview/approval resolves actual immutable layer heads. Saving a
// draft never changes assignments, active heads, source grants or publications.
type NetworkDraft struct {
	ID           string                    `json:"id"`
	Revision     int64                     `json:"revision"`
	TargetKind   string                    `json:"targetKind"`
	TargetID     string                    `json:"targetId"`
	BaseRevision int64                     `json:"baseRevision"`
	BaseHash     string                    `json:"baseHash"`
	Plan         configuration.NetworkPlan `json:"plan"`
	SavedAt      int64                     `json:"savedAt"`
}

func (NetworkDraft) String() string   { return "NetworkDraft([redacted])" }
func (NetworkDraft) GoString() string { return "NetworkDraft([redacted])" }

func (d NetworkDraft) validate() error {
	if !identifier.MatchString(d.ID) || !identifier.MatchString(d.TargetID) || d.Revision < 0 || d.Revision > 9007199254740991 || d.BaseRevision < 0 || d.BaseRevision > 9007199254740991 {
		return ErrInvalid
	}
	switch d.TargetKind {
	case "template", "group", "user", "device":
	default:
		return ErrInvalid
	}
	hash, e := hex.DecodeString(d.BaseHash)
	if d.BaseRevision == 0 && d.BaseHash != "" || d.BaseRevision > 0 && (e != nil || len(hash) != 32 || strings.ToLower(d.BaseHash) != d.BaseHash) {
		return ErrInvalid
	}
	raw, e := json.Marshal(d.Plan)
	if e != nil {
		return ErrInvalid
	}
	if _, e = configuration.DecodeNetworkPlan(raw); e != nil {
		return ErrInvalid
	}
	return nil
}

func draftAAD(actor, id string, revision int64) string {
	return "catalog-network-draft/v1/" + actor + "/" + id + "/" + strconv.FormatInt(revision, 10)
}

func (s *Store) readNetworkDraft(ctx context.Context, tx *sql.Tx, actor, id, expectedKind, expectedTarget string, lock bool) (NetworkDraft, error) {
	var protected []byte
	var revision, saved int64
	var kind, target string
	query := `SELECT revision,target_kind,target_id,saved_at,body FROM catalog_network_drafts WHERE actor=$1 AND id=$2`
	if lock {
		query += " FOR UPDATE"
	}
	e := tx.QueryRowContext(ctx, query, actor, id).Scan(&revision, &kind, &target, &saved, &protected)
	if e == sql.ErrNoRows {
		return NetworkDraft{}, ErrDenied
	}
	if e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	if kind != expectedKind || target != expectedTarget {
		return NetworkDraft{}, ErrConflict
	}
	raw, e := s.open(protected, draftAAD(actor, id, revision))
	var draft NetworkDraft
	if e != nil || identity.DecodeConfiguration(raw, &draft) != nil || draft.validate() != nil || draft.ID != id || draft.Revision != revision || draft.TargetKind != kind || draft.TargetID != target || draft.SavedAt != saved {
		return NetworkDraft{}, ErrUnavailable
	}
	return draft, nil
}

func (s *Store) GetNetworkDraft(ctx context.Context, actor Actor, id string, now time.Time) (NetworkDraft, error) {
	started := time.Now()
	if !identifier.MatchString(id) || !identifier.MatchString(actor.ID) {
		return NetworkDraft{}, ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	defer tx.Rollback()
	// Authorize from clear bounded metadata before decrypting the private body.
	var kind, target string
	if e = tx.QueryRowContext(ctx, `SELECT target_kind,target_id FROM catalog_network_drafts WHERE actor=$1 AND id=$2 FOR SHARE`, actor.ID, id).Scan(&kind, &target); e == sql.ErrNoRows {
		return NetworkDraft{}, ErrDenied
	} else if e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	if e = authorize(ctx, tx, actor, "configuration.drafts.read", kind, target, now.Unix(), false); e != nil {
		return NetworkDraft{}, e
	}
	draft, e := s.readNetworkDraft(ctx, tx, actor.ID, id, kind, target, false)
	if e != nil {
		return NetworkDraft{}, e
	}
	if e = authorize(ctx, tx, actor, "configuration.drafts.read", kind, target, now.Add(time.Since(started)).Unix(), false); e != nil {
		return NetworkDraft{}, e
	}
	if e = tx.Commit(); e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	return draft, nil
}

func (s *Store) PutNetworkDraft(ctx context.Context, actor Actor, draft NetworkDraft, request string, now time.Time) (NetworkDraft, error) {
	started := time.Now()
	if draft.validate() != nil || draft.Revision == 9007199254740991 || draft.SavedAt != 0 || !identifier.MatchString(request) {
		return NetworkDraft{}, ErrInvalid
	}
	body, _ := json.Marshal(draft)
	hash := s.hash(body)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	defer tx.Rollback()
	if e = authorize(ctx, tx, actor, "configuration.drafts.write", draft.TargetKind, draft.TargetID, now.Unix(), false); e != nil {
		return NetworkDraft{}, e
	}
	for _, name := range []string{"catalog-drafts/" + actor.ID, actor.ID + "/" + request} {
		if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, name); e != nil {
			return NetworkDraft{}, ErrUnavailable
		}
	}
	prior, e := s.priorOperation(ctx, tx, actor.ID, request, "configuration.draft.put", draft.ID, hash, now.Unix())
	if e != nil {
		return NetworkDraft{}, e
	}
	if prior != nil {
		var result NetworkDraft
		if identity.DecodeConfiguration(prior, &result) != nil || result.validate() != nil {
			return NetworkDraft{}, ErrUnavailable
		}
		if e = authorize(ctx, tx, actor, "configuration.drafts.write", draft.TargetKind, draft.TargetID, now.Add(time.Since(started)).Unix(), false); e != nil {
			return NetworkDraft{}, e
		}
		if e = tx.Commit(); e != nil {
			return NetworkDraft{}, ErrUnavailable
		}
		return result, nil
	}
	var operations int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM catalog_operations WHERE actor=$1 AND action='configuration.draft.put'`, actor.ID).Scan(&operations); e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	if operations >= 256 {
		return NetworkDraft{}, ErrQuota
	}
	old, e := s.readNetworkDraft(ctx, tx, actor.ID, draft.ID, draft.TargetKind, draft.TargetID, true)
	if e != nil && e != ErrDenied {
		return NetworkDraft{}, e
	}
	if e == nil {
		if old.Revision != draft.Revision || old.TargetKind != draft.TargetKind || old.TargetID != draft.TargetID {
			return NetworkDraft{}, ErrConflict
		}
	} else {
		if draft.Revision != 0 {
			return NetworkDraft{}, ErrConflict
		}
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM catalog_network_drafts WHERE actor=$1`, actor.ID).Scan(&count); e != nil {
			return NetworkDraft{}, ErrUnavailable
		}
		if count >= 64 {
			return NetworkDraft{}, ErrQuota
		}
	}
	draft.Revision++
	draft.SavedAt = now.Unix()
	raw, _ := json.Marshal(draft)
	protected, e := s.seal(raw, draftAAD(actor.ID, draft.ID, draft.Revision))
	if e != nil {
		return NetworkDraft{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO catalog_network_drafts(actor,id,revision,target_kind,target_id,saved_at,body) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(actor,id) DO UPDATE SET revision=excluded.revision,saved_at=excluded.saved_at,body=excluded.body`, actor.ID, draft.ID, draft.Revision, draft.TargetKind, draft.TargetID, draft.SavedAt, protected); e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	before := ""
	if old.Revision > 0 {
		raw, _ := json.Marshal(old)
		before = s.hash(raw)
	}
	if e = audit(ctx, tx, actor.ID, "configuration.draft.put", draft.ID, request, before, s.hash(raw), "saved", now.Unix()); e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	if e = s.recordOperation(ctx, tx, actor.ID, request, "configuration.draft.put", draft.ID, hash, draft, now.Unix()); e != nil {
		return NetworkDraft{}, e
	}
	if e = authorize(ctx, tx, actor, "configuration.drafts.write", draft.TargetKind, draft.TargetID, now.Add(time.Since(started)).Unix(), false); e != nil {
		return NetworkDraft{}, e
	}
	if e = tx.Commit(); e != nil {
		return NetworkDraft{}, ErrUnavailable
	}
	return draft, nil
}
