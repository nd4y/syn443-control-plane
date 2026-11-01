package catalog

import (
	"context"
	"database/sql"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

type SourcePage struct {
	Sources []Source `json:"sources"`
	Next    string   `json:"next"`
}

func (s *Store) ListSources(ctx context.Context, actor Actor, owner, after string, now time.Time) (SourcePage, error) {
	result := SourcePage{Sources: []Source{}}
	if !identifier.MatchString(owner) || after != "" && !sourceIdentifier.MatchString(after) {
		return result, ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, ErrUnavailable
	}
	defer tx.Rollback()
	if e = authorize(ctx, tx, actor, "sources.read", "user", owner, now.Unix(), false); e != nil {
		return result, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT id FROM catalog_sources WHERE owner=$1 AND id>$2 ORDER BY id LIMIT 33`, owner, after)
	if e != nil {
		return result, ErrUnavailable
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return result, ErrUnavailable
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, ErrUnavailable
	}
	if len(ids) > 32 {
		ids = ids[:32]
		result.Next = ids[31]
	}
	for _, id := range ids {
		source, e := s.readSource(ctx, tx, id, false)
		if e != nil {
			return result, e
		}
		source, e = sourceStatus(ctx, tx, source, now)
		if e != nil {
			return result, e
		}
		result.Sources = append(result.Sources, source)
	}
	return result, tx.Commit()
}

type SnapshotView struct {
	Snapshot Snapshot                `json:"snapshot"`
	Profiles []subscriptions.Profile `json:"profiles"`
}

func (s *Store) GetSnapshot(ctx context.Context, actor Actor, id, snapshot string, now time.Time) (SnapshotView, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return SnapshotView{}, ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, id, false)
	if e != nil {
		return SnapshotView{}, e
	}
	if e = authorize(ctx, tx, actor, "sources.read", "user", source.Owner, now.Unix(), false); e != nil {
		return SnapshotView{}, e
	}
	if snapshot == "" {
		snapshot = source.ActiveSnapshot
	}
	value, profiles, e := s.readSnapshot(ctx, tx, id, snapshot)
	if e != nil {
		return SnapshotView{}, e
	}
	return SnapshotView{value, profiles}, tx.Commit()
}

type JobView struct {
	Job            Job   `json:"job"`
	LeaseExpiresAt int64 `json:"leaseExpiresAt"`
	ObservedAt     int64 `json:"observedAt"`
}

func (s *Store) GetJob(ctx context.Context, actor Actor, id string, now time.Time) (JobView, error) {
	result := JobView{ObservedAt: now.Unix()}
	if !identifier.MatchString(id) {
		return result, ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, ErrUnavailable
	}
	defer tx.Rollback()
	j := &result.Job
	if e = tx.QueryRowContext(ctx, `SELECT id,source_id,source_revision,kind,phase,attempts,deadline,reason,lease_until FROM catalog_jobs WHERE id=$1`, id).Scan(&j.ID, &j.SourceID, &j.SourceRevision, &j.Kind, &j.Phase, &j.Attempts, &j.Deadline, &j.Reason, &result.LeaseExpiresAt); e == sql.ErrNoRows {
		return result, ErrDenied
	}
	if e != nil {
		return result, ErrUnavailable
	}
	source, e := s.readSource(ctx, tx, j.SourceID, false)
	if e != nil {
		return result, e
	}
	if e = authorize(ctx, tx, actor, "sources.read", "user", source.Owner, now.Unix(), false); e != nil {
		return result, e
	}
	return result, tx.Commit()
}
