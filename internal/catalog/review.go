package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"
)

type Recipient struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type Shares struct {
	Revision   int64       `json:"revision"`
	Recipients []Recipient `json:"recipients"`
}

func readShares(ctx context.Context, tx *sql.Tx, id string) (Shares, error) {
	var result Shares
	result.Recipients = []Recipient{}
	e := tx.QueryRowContext(ctx, `SELECT revision FROM catalog_share_heads WHERE source_id=$1`, id).Scan(&result.Revision)
	if e != nil && e != sql.ErrNoRows {
		return result, ErrUnavailable
	}
	rows, e := tx.QueryContext(ctx, `SELECT target_kind,target_id FROM catalog_source_grants WHERE source_id=$1 ORDER BY target_kind,target_id`, id)
	if e != nil {
		return result, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var recipient Recipient
		if rows.Scan(&recipient.Kind, &recipient.ID) != nil {
			return result, ErrUnavailable
		}
		result.Recipients = append(result.Recipients, recipient)
	}
	if rows.Err() != nil {
		return result, ErrUnavailable
	}
	return result, nil
}
func (s *Store) GetShares(ctx context.Context, actor Actor, id string, now time.Time) (Shares, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Shares{}, ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, id, true)
	if e != nil {
		return Shares{}, e
	}
	if e = authorize(ctx, tx, actor, "sources.share", "user", source.Owner, now.Unix(), false); e != nil {
		return Shares{}, e
	}
	result, e := readShares(ctx, tx, id)
	if e != nil {
		return result, e
	}
	return result, tx.Commit()
}
func (s *Store) SetShares(ctx context.Context, actor Actor, id string, expectedSource int64, shares Shares, request string, now time.Time) (Shares, error) {
	if !sourceIdentifier.MatchString(id) || !identifier.MatchString(request) || shares.Revision < 0 || shares.Revision > 9007199254740991 || expectedSource < 1 || len(shares.Recipients) > 256 {
		return Shares{}, ErrInvalid
	}
	shares.Recipients = append([]Recipient{}, shares.Recipients...)
	sort.Slice(shares.Recipients, func(i, j int) bool {
		a, b := shares.Recipients[i], shares.Recipients[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.ID < b.ID
	})
	for i, r := range shares.Recipients {
		if r.Kind != "user" && r.Kind != "group" && r.Kind != "device" || !identifier.MatchString(r.ID) || i > 0 && r == shares.Recipients[i-1] {
			return Shares{}, ErrInvalid
		}
	}
	body, _ := json.Marshal(struct {
		Source   string
		Revision int64
		Shares   Shares
	}{id, expectedSource, shares})
	hash := s.hash(body)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Shares{}, ErrUnavailable
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, actor.ID+"/"+request); e != nil {
		return Shares{}, ErrUnavailable
	}
	source, e := s.readSource(ctx, tx, id, true)
	if e != nil {
		return Shares{}, e
	}
	if e = authorize(ctx, tx, actor, "sources.share", "user", source.Owner, now.Unix(), true); e != nil {
		return Shares{}, e
	}
	prior, e := s.priorOperation(ctx, tx, actor.ID, request, "source.share", id, hash, now.Unix())
	if e != nil {
		return Shares{}, e
	}
	if prior != nil {
		var result Shares
		if json.Unmarshal(prior, &result) != nil {
			return result, ErrUnavailable
		}
		return result, tx.Commit()
	}
	current, e := readShares(ctx, tx, id)
	if e != nil {
		return Shares{}, e
	}
	if source.Revision != expectedSource || current.Revision != shares.Revision {
		return Shares{}, ErrConflict
	}
	// Serialize recipient-impact changes with resource disable/token rotation.
	if source.Mode == "resource" {
		var resource string
		if e = tx.QueryRowContext(ctx, `SELECT id FROM catalog_resources WHERE id=$1 FOR SHARE`, source.ResourceID).Scan(&resource); e != nil {
			return Shares{}, ErrUnavailable
		}
	}
	for _, r := range shares.Recipients {
		if source.Mode == "device" && (r.Kind != "user" || r.ID != source.Owner) {
			return Shares{}, ErrDenied
		}
		if e = authorize(ctx, tx, actor, "sources.receive", r.Kind, r.ID, now.Unix(), false); e != nil {
			return Shares{}, e
		}
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM catalog_source_grants WHERE source_id=$1`, id); e != nil {
		return Shares{}, ErrUnavailable
	}
	for _, r := range shares.Recipients {
		if _, e = tx.ExecContext(ctx, `INSERT INTO catalog_source_grants(source_id,target_kind,target_id) VALUES($1,$2,$3)`, id, r.Kind, r.ID); e != nil {
			return Shares{}, ErrUnavailable
		}
	}
	shares.Revision++
	if _, e = tx.ExecContext(ctx, `INSERT INTO catalog_share_heads(source_id,revision) VALUES($1,$2) ON CONFLICT(source_id) DO UPDATE SET revision=excluded.revision`, id, shares.Revision); e != nil {
		return Shares{}, ErrUnavailable
	}
	if e = s.recordOperation(ctx, tx, actor.ID, request, "source.share", id, hash, shares, now.Unix()); e != nil {
		return Shares{}, ErrUnavailable
	}
	if e = audit(ctx, tx, actor.ID, "source.share", id, request, "", hash, "saved", now.Unix()); e != nil {
		return Shares{}, ErrUnavailable
	}
	return shares, tx.Commit()
}

type Review struct {
	SourceID       string `json:"sourceId"`
	SourceRevision int64  `json:"sourceRevision"`
	Candidate      string `json:"candidate"`
	Hash           string `json:"hash"`
	Active         string `json:"active"`
	Approve        bool   `json:"approve"`
}

// ReviewSnapshot permits a deliberate mass-removal decision, never broken
// references, expired access, exhausted quota or a changed candidate/head.
func (s *Store) ReviewSnapshot(ctx context.Context, actor Actor, review Review, request string, now time.Time) (Snapshot, error) {
	if !sourceIdentifier.MatchString(review.SourceID) || !identifier.MatchString(review.Candidate) || !identifier.MatchString(request) || review.SourceRevision < 1 {
		return Snapshot{}, ErrInvalid
	}
	raw, _ := json.Marshal(review)
	hash := s.hash(raw)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, actor.ID+"/"+request); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	source, e := s.readSource(ctx, tx, review.SourceID, true)
	if e != nil {
		return Snapshot{}, e
	}
	if e = authorize(ctx, tx, actor, "sources.review", "user", source.Owner, now.Unix(), true); e != nil {
		return Snapshot{}, e
	}
	prior, e := s.priorOperation(ctx, tx, actor.ID, request, "source.review", source.ID, hash, now.Unix())
	if e != nil {
		return Snapshot{}, e
	}
	if prior != nil {
		var result Snapshot
		if json.Unmarshal(prior, &result) != nil {
			return result, ErrUnavailable
		}
		return result, tx.Commit()
	}
	if source.Revision != review.SourceRevision || source.ActiveSnapshot != review.Active || source.CandidateSnapshot != review.Candidate || !source.Enabled || source.ValidUntil <= now.Unix() {
		return Snapshot{}, ErrConflict
	}
	candidate, profiles, e := s.readSnapshot(ctx, tx, source.ID, review.Candidate)
	if e != nil {
		return Snapshot{}, e
	}
	if candidate.Hash != review.Hash || candidate.State != "quarantined" || candidate.SourceRevision != source.Revision {
		return Snapshot{}, ErrConflict
	}
	if source.Mode == "resource" {
		if e = resourceCurrent(ctx, tx, Job{ResourceRevision: candidate.ResourceRevision}, source); e != nil {
			return Snapshot{}, e
		}
	}
	state := "rejected"
	if review.Approve {
		if source.State != "quarantined" {
			return Snapshot{}, ErrDenied
		}
		if candidate.ValidUntil <= now.Unix() || candidate.Quota.Known && candidate.Quota.Limit > 0 && candidate.Quota.Used >= candidate.Quota.Limit {
			return Snapshot{}, ErrDenied
		}
		ids := map[string]bool{}
		for _, p := range profiles {
			ids[p.ID] = true
		}
		rows, e := tx.QueryContext(ctx, `SELECT DISTINCT profile_id FROM catalog_dependencies WHERE source_id=$1`, source.ID)
		if e != nil {
			return Snapshot{}, ErrUnavailable
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return Snapshot{}, ErrUnavailable
			}
			if !ids[id] {
				rows.Close()
				return Snapshot{}, ErrConflict
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return Snapshot{}, ErrUnavailable
		}
		if source.ActiveSnapshot != "" {
			if _, e = tx.ExecContext(ctx, `UPDATE catalog_snapshots SET state='superseded' WHERE id=$1`, source.ActiveSnapshot); e != nil {
				return Snapshot{}, ErrUnavailable
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE catalog_sources SET active_snapshot=$2,candidate_snapshot=NULL,state='active',access_state='allowed' WHERE id=$1`, source.ID, candidate.ID); e != nil {
			return Snapshot{}, ErrUnavailable
		}
		state = "active"
	} else {
		if _, e = tx.ExecContext(ctx, `UPDATE catalog_sources SET candidate_snapshot=NULL,state='review_rejected' WHERE id=$1`, source.ID); e != nil {
			return Snapshot{}, ErrUnavailable
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE catalog_snapshots SET state=$2 WHERE id=$1`, candidate.ID, state); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	candidate.State = state
	event, e := random()
	if e != nil {
		return Snapshot{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO catalog_outbox(id,event_version,kind,source_id,snapshot_id,created_at) VALUES($1,1,$2,$3,$4,$5)`, event, "source."+state, source.ID, candidate.ID, now.Unix()); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	if e = s.recordOperation(ctx, tx, actor.ID, request, "source.review", source.ID, hash, candidate, now.Unix()); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	if e = audit(ctx, tx, actor.ID, "source.review", source.ID, request, "", candidate.Hash, state, now.Unix()); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	return candidate, tx.Commit()
}
