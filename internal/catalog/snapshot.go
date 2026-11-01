package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func (s *Store) readSnapshot(ctx context.Context, tx *sql.Tx, source, id string) (Snapshot, []subscriptions.Profile, error) {
	var result Snapshot
	var protected, quota []byte
	e := tx.QueryRowContext(ctx, `SELECT id,source_id,source_revision,content_hash,observed_at,valid_until,count,state,reason,profiles,quota,resource_revision FROM catalog_snapshots WHERE source_id=$1 AND id=$2`, source, id).Scan(&result.ID, &result.SourceID, &result.SourceRevision, &result.Hash, &result.ObservedAt, &result.ValidUntil, &result.Count, &result.State, &result.Reason, &protected, &quota, &result.ResourceRevision)
	if e == sql.ErrNoRows {
		return result, nil, ErrDenied
	}
	if e != nil {
		return result, nil, ErrUnavailable
	}
	raw, e := s.open(protected, aad("snapshot", source+"/"+id, result.SourceRevision))
	if e != nil || s.hash(raw) != result.Hash {
		return Snapshot{}, nil, ErrUnavailable
	}
	var profiles []StoredProfile
	if json.Unmarshal(raw, &profiles) != nil || len(profiles) != result.Count || len(profiles) > subscriptions.MaxProfiles || json.Unmarshal(quota, &result.Quota) != nil {
		return Snapshot{}, nil, ErrUnavailable
	}
	values := make([]subscriptions.Profile, 0, len(profiles))
	for _, p := range profiles {
		values = append(values, subscriptions.Profile{ID: p.ID, Name: p.Name, Kind: p.Kind, Outbound: p.Outbound})
	}
	return result, values, nil
}
func verifyProfileIDs(source string, salt []byte, profiles []subscriptions.Profile) error {
	if len(salt) != 32 {
		return ErrUnavailable
	}
	for _, p := range profiles {
		raw, _ := json.Marshal(map[string]any{"outbounds": []json.RawMessage{p.Outbound}})
		checked, e := subscriptions.Import(source, salt, "singbox", raw)
		if e != nil || len(checked) != 1 || checked[0].ID != p.ID || checked[0].Kind != p.Kind {
			return ErrInvalid
		}
	}
	return nil
}

// SyncCache exposes protected working data only to the isolated source worker.
// It is not an inventory/export endpoint and does not extend its lease.
func (s *Store) SyncCache(ctx context.Context, job Job, now time.Time) (subscriptions.Cache, Snapshot, []subscriptions.Profile, error) {
	var cache subscriptions.Cache
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return cache, Snapshot{}, nil, ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, job.SourceID, true)
	if e != nil {
		return cache, Snapshot{}, nil, e
	}
	if source.Revision != job.SourceRevision || source.ActiveSnapshot != job.BaseSnapshot {
		return cache, Snapshot{}, nil, ErrStale
	}
	if e = jobCurrent(ctx, tx, job, now.Unix()); e != nil {
		return cache, Snapshot{}, nil, e
	}
	if e = resourceCurrent(ctx, tx, job, source); e != nil {
		return cache, Snapshot{}, nil, e
	}
	var protected []byte
	if e = tx.QueryRowContext(ctx, `SELECT fetch_cache FROM catalog_sources WHERE id=$1`, source.ID).Scan(&protected); e != nil {
		return cache, Snapshot{}, nil, ErrUnavailable
	}
	if len(protected) > 0 {
		raw, e := s.open(protected, aad("fetch-cache", source.ID, source.Revision))
		if e != nil || json.Unmarshal(raw, &cache) != nil {
			return cache, Snapshot{}, nil, ErrUnavailable
		}
	}
	var previous Snapshot
	var profiles []subscriptions.Profile
	if source.ActiveSnapshot != "" {
		previous, profiles, e = s.readSnapshot(ctx, tx, source.ID, source.ActiveSnapshot)
		if e != nil {
			return cache, Snapshot{}, nil, e
		}
	}
	return cache, previous, profiles, tx.Commit()
}

// Complete prepares encryption outside the final transaction, then repeats the
// source/head/lease fence before publishing a snapshot and its outbox event.
func (s *Store) Complete(ctx context.Context, job Job, profiles []subscriptions.Profile, quota subscriptions.Quota, cache subscriptions.Cache, now time.Time) (Snapshot, error) {
	source, salt, _, _, e := s.JobInput(ctx, job, now)
	if e != nil {
		return Snapshot{}, e
	}
	if e = verifyProfileIDs(source.ID, salt, profiles); e != nil {
		return Snapshot{}, e
	}
	raw, e := protectedProfiles(profiles)
	if e != nil {
		return Snapshot{}, e
	}
	id, e := random()
	if e != nil {
		return Snapshot{}, e
	}
	result := Snapshot{ID: id, SourceID: source.ID, SourceRevision: source.Revision, Hash: s.hash(raw), ObservedAt: now.Unix(), Count: len(profiles), State: "candidate", Quota: quota, ResourceRevision: job.ResourceRevision}
	protected, e := s.seal(raw, aad("snapshot", source.ID+"/"+id, source.Revision))
	if e != nil {
		return Snapshot{}, e
	}
	cacheRaw, _ := json.Marshal(cache)
	protectedCache, e := s.seal(cacheRaw, aad("fetch-cache", source.ID, source.Revision))
	if e != nil {
		return Snapshot{}, e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	defer tx.Rollback()
	current, e := s.readSource(ctx, tx, source.ID, true)
	if e != nil {
		return Snapshot{}, e
	}
	if current.Revision != job.SourceRevision || current.ActiveSnapshot != job.BaseSnapshot || !current.Enabled || current.ValidUntil <= now.Unix() {
		return Snapshot{}, ErrStale
	}
	if e = jobCurrent(ctx, tx, job, now.Unix()); e != nil {
		return Snapshot{}, e
	}
	if e = resourceCurrent(ctx, tx, job, current); e != nil {
		return Snapshot{}, e
	}
	var previous []subscriptions.Profile
	if current.ActiveSnapshot != "" {
		old, values, e := s.readSnapshot(ctx, tx, source.ID, current.ActiveSnapshot)
		if e != nil {
			return Snapshot{}, e
		}
		previous = values
		if !quota.Known && old.Quota.Known {
			result.Quota = old.Quota
		}
	}
	result.ValidUntil = min(current.ValidUntil, now.Unix()+current.MaxStaleSeconds)
	if result.Quota.ExpiresAt > 0 {
		result.ValidUntil = min(result.ValidUntil, result.Quota.ExpiresAt)
	}
	if result.ValidUntil <= now.Unix() {
		return Snapshot{}, subscriptions.ErrExpired
	}
	refs := map[string]bool{}
	rows, e := tx.QueryContext(ctx, `SELECT DISTINCT profile_id FROM catalog_dependencies WHERE source_id=$1`, source.ID)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	for rows.Next() {
		var ref string
		if rows.Scan(&ref) != nil {
			rows.Close()
			return Snapshot{}, ErrUnavailable
		}
		refs[ref] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	promotion, e := subscriptions.Assess(previous, profiles, refs)
	if e != nil {
		return Snapshot{}, e
	}
	result.Reason = promotion.Reason
	result.State = "quarantined"
	if promotion.Allowed {
		result.State = "active"
	}
	if result.Quota.Known && result.Quota.Limit > 0 && result.Quota.Used >= result.Quota.Limit {
		result.State = "quarantined"
		result.Reason = "quota_exhausted"
	}
	quotaRaw, _ := json.Marshal(result.Quota)
	_, e = tx.ExecContext(ctx, `INSERT INTO catalog_snapshots(id,source_id,source_revision,content_hash,observed_at,valid_until,count,profiles,state,reason,quota,resource_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, result.ID, result.SourceID, result.SourceRevision, result.Hash, result.ObservedAt, result.ValidUntil, result.Count, protected, result.State, result.Reason, quotaRaw, result.ResourceRevision)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	state := "quarantined"
	active := current.ActiveSnapshot
	if result.State == "active" {
		state = "active"
		active = result.ID
		if current.ActiveSnapshot != "" {
			if _, e = tx.ExecContext(ctx, `UPDATE catalog_snapshots SET state='superseded' WHERE id=$1`, current.ActiveSnapshot); e != nil {
				return Snapshot{}, ErrUnavailable
			}
		}
	}
	if result.Reason == "quota_exhausted" {
		state = "quota_exhausted"
	}
	var activeValue any
	if active != "" {
		activeValue = active
	}
	_, e = tx.ExecContext(ctx, `UPDATE catalog_sources SET active_snapshot=$2,candidate_snapshot=$3,state=$4,last_sync=$5,next_sync=$6,fetch_cache=$7,last_resource_revision=$8 WHERE id=$1`, source.ID, activeValue, result.ID, state, now.Unix(), now.Unix()+source.RefreshSeconds, protectedCache, job.ResourceRevision)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	_, e = tx.ExecContext(ctx, `UPDATE catalog_jobs SET phase='succeeded',reason=$2,lease='',lease_until=0,updated_at=$3,payload=NULL WHERE id=$1`, job.ID, result.Reason, now.Unix())
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO catalog_outbox(id,event_version,kind,source_id,snapshot_id,created_at) VALUES($1,1,$2,$3,$4,$5)`, result.ID, "source."+result.State, source.ID, result.ID, now.Unix())
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	if e = audit(ctx, tx, "", "source.snapshot", source.ID, job.ID, "", result.Hash, result.State, now.Unix()); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	return result, tx.Commit()
}

func (s *Store) Abandon(ctx context.Context, job Job, now time.Time) error {
	_, e := s.DB.ExecContext(ctx, `UPDATE catalog_jobs SET phase='cancelled',reason='stale_inputs',lease='',lease_until=0,updated_at=$3 WHERE id=$1 AND lease=$2 AND phase='running'`, job.ID, job.Lease, now.Unix())
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
