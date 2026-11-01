package catalog

import (
	"context"
	"database/sql"
	"strconv"
	"time"
)

// Queue returns the same job after a lost reply. Updating source definitions
// cancels older jobs; a new request cannot revive their stale lease.
func (s *Store) Queue(ctx context.Context, actor Actor, id string, expectedRevision int64, request string, raw []byte, now time.Time) (Job, error) {
	var result Job
	if !sourceIdentifier.MatchString(id) || expectedRevision < 1 || !identifier.MatchString(request) || len(raw) > 10*1024*1024 {
		return result, ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, id, true)
	if e != nil {
		return result, e
	}
	if e = authorize(ctx, tx, actor, "sources.sync", "user", source.Owner, now.Unix(), false); e != nil {
		return result, e
	}
	if !source.Enabled || source.ValidUntil <= now.Unix() {
		return result, ErrDenied
	}
	if source.Mode == "manual" && len(raw) == 0 || source.Mode != "manual" && len(raw) != 0 {
		return result, ErrInvalid
	}
	if source.Mode == "device" {
		return result, ErrDenied
	}
	hash := s.hash(append([]byte(id+"\x00"+strconv.FormatInt(expectedRevision, 10)+"\x00"), raw...))
	var previousHash, phase, kind string
	var previousRevision int64
	e = tx.QueryRowContext(ctx, `SELECT id,body_hash,phase,kind,source_revision FROM catalog_jobs WHERE actor=$1 AND request_id=$2`, actor.ID, request).Scan(&result.ID, &previousHash, &phase, &kind, &previousRevision)
	if e == nil {
		if previousHash != hash {
			return Job{}, ErrConflict
		}
		result.SourceID = id
		result.SourceRevision = previousRevision
		result.Phase = phase
		result.Kind = kind
		return result, tx.Commit()
	}
	if e != sql.ErrNoRows {
		return result, ErrUnavailable
	}
	if source.Revision != expectedRevision {
		return result, ErrConflict
	}
	var active int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM catalog_jobs WHERE source_id=$1 AND phase IN('queued','running')`, id).Scan(&active); e != nil {
		return result, ErrUnavailable
	}
	if active != 0 {
		return result, ErrConflict
	}
	job, e := s.enqueue(ctx, tx, source, actor.ID, request, hash, raw, now.Unix())
	if e != nil {
		return result, e
	}
	if e = audit(ctx, tx, actor.ID, "source.sync", id, request, "", "", "queued", now.Unix()); e != nil {
		return result, ErrUnavailable
	}
	return job, tx.Commit()
}
func (s *Store) enqueue(ctx context.Context, tx *sql.Tx, source Source, actor, request, hash string, raw []byte, now int64) (Job, error) {
	id, e := random()
	if e != nil {
		return Job{}, e
	}
	kind := source.Mode
	if kind == "server" {
		kind = "fetch"
	}
	var payload []byte
	if len(raw) > 0 {
		payload, e = s.seal(raw, "catalog-job/v1/"+id)
		if e != nil {
			return Job{}, e
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO catalog_jobs(id,source_id,source_revision,kind,request_id,actor,body_hash,phase,not_before,deadline,payload,created_at,updated_at,base_snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,'queued',$8,$9,$10,$8,$8,$11)`, id, source.ID, source.Revision, kind, request, actor, hash, now, now+900, payload, source.ActiveSnapshot)
	if e != nil {
		return Job{}, ErrUnavailable
	}
	return Job{ID: id, SourceID: source.ID, SourceRevision: source.Revision, Kind: kind, Phase: "queued", Deadline: now + 900, BaseSnapshot: source.ActiveSnapshot}, nil
}

// Schedule's source row locks and the unique active-job index prevent replica
// duplication. It schedules work, never performs provider I/O in a transaction.
func (s *Store) Schedule(ctx context.Context, now time.Time) (int, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return 0, ErrUnavailable
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT id FROM catalog_sources s WHERE enabled AND valid_until>$1 AND next_sync<=$1 AND mode IN('server','resource') AND NOT EXISTS(SELECT 1 FROM catalog_jobs j WHERE j.source_id=s.id AND j.phase IN('queued','running')) ORDER BY next_sync,id LIMIT 16 FOR UPDATE SKIP LOCKED`, now.Unix())
	if e != nil {
		return 0, ErrUnavailable
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return 0, ErrUnavailable
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, ErrUnavailable
	}
	for _, id := range ids {
		source, e := s.readSource(ctx, tx, id, false)
		if e != nil {
			return 0, e
		}
		request, e := random()
		if e != nil {
			return 0, e
		}
		if _, e = s.enqueue(ctx, tx, source, "source-scheduler", request, "scheduled", nil, now.Unix()); e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE catalog_sources SET next_sync=$2 WHERE id=$1`, id, now.Unix()+source.RefreshSeconds); e != nil {
			return 0, ErrUnavailable
		}
	}
	return len(ids), tx.Commit()
}
func (s *Store) Claim(ctx context.Context, now time.Time) (Job, error) {
	var job Job
	lease, e := random()
	if e != nil {
		return job, e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return job, ErrUnavailable
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('catalog/claim-budget/v1',0))`); e != nil {
		return job, ErrUnavailable
	}
	// Crash/expiry transitions remain durable and visible rather than vanishing.
	if _, e = tx.ExecContext(ctx, `UPDATE catalog_jobs SET phase='dead_letter',reason='deadline_or_retry_limit',updated_at=$1 WHERE phase IN('queued','running') AND (deadline<=$1 OR attempts>=8 AND lease_until<=$1)`, now.Unix()); e != nil {
		return job, ErrUnavailable
	}
	var running int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM catalog_jobs WHERE phase='running' AND lease_until>$1`, now.Unix()).Scan(&running); e != nil {
		return job, ErrUnavailable
	}
	if running >= 8 {
		return job, tx.Commit()
	}
	e = tx.QueryRowContext(ctx, `SELECT id,source_id,source_revision,kind,phase,attempts,deadline,COALESCE(base_snapshot,'') FROM catalog_jobs WHERE (phase='queued' OR phase='running' AND lease_until<=$1) AND not_before<=$1 AND deadline>$1 AND attempts<8 ORDER BY not_before,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, now.Unix()).Scan(&job.ID, &job.SourceID, &job.SourceRevision, &job.Kind, &job.Phase, &job.Attempts, &job.Deadline, &job.BaseSnapshot)
	if e == sql.ErrNoRows {
		return Job{}, tx.Commit()
	}
	if e != nil {
		return Job{}, ErrUnavailable
	}
	job.Phase = "running"
	job.Attempts++
	job.Lease = lease
	job.LeaseUntil = min(now.Unix()+60, job.Deadline)
	_, e = tx.ExecContext(ctx, `UPDATE catalog_jobs SET phase='running',attempts=$2,lease=$3,lease_until=$4,updated_at=$5 WHERE id=$1`, job.ID, job.Attempts, lease, job.LeaseUntil, now.Unix())
	if e != nil {
		return Job{}, ErrUnavailable
	}
	return job, tx.Commit()
}
func jobCurrent(ctx context.Context, tx *sql.Tx, job Job, now int64) error {
	var phase, lease, sourceID, kind, base string
	var until, deadline, revision int64
	var attempts int
	e := tx.QueryRowContext(ctx, `SELECT phase,lease,lease_until,deadline,source_revision,source_id,kind,attempts,COALESCE(base_snapshot,'') FROM catalog_jobs WHERE id=$1 FOR UPDATE`, job.ID).Scan(&phase, &lease, &until, &deadline, &revision, &sourceID, &kind, &attempts, &base)
	if e != nil {
		return ErrUnavailable
	}
	if phase != "running" || lease != job.Lease || lease == "" || until <= now || deadline <= now || revision != job.SourceRevision || sourceID != job.SourceID || kind != job.Kind || attempts != job.Attempts || job.Attempts < 1 || job.Attempts > 8 || base != job.BaseSnapshot {
		return ErrStale
	}
	return nil
}
func (s *Store) JobInput(ctx context.Context, job Job, now time.Time) (Source, []byte, []byte, []byte, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Source{}, nil, nil, nil, ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, job.SourceID, true)
	if e != nil {
		return Source{}, nil, nil, nil, e
	}
	if source.Revision != job.SourceRevision || source.ActiveSnapshot != job.BaseSnapshot || !source.Enabled || source.ValidUntil <= now.Unix() {
		return Source{}, nil, nil, nil, ErrStale
	}
	if e = jobCurrent(ctx, tx, job, now.Unix()); e != nil {
		return Source{}, nil, nil, nil, e
	}
	var salt, secret, payload []byte
	if e = tx.QueryRowContext(ctx, `SELECT salt,secrets FROM catalog_sources WHERE id=$1`, source.ID).Scan(&salt, &secret); e != nil {
		return Source{}, nil, nil, nil, ErrUnavailable
	}
	if len(secret) > 0 {
		secret, e = s.open(secret, aad("source-secret", source.ID, source.Revision))
		if e != nil {
			return Source{}, nil, nil, nil, e
		}
	}
	if e = tx.QueryRowContext(ctx, `SELECT payload FROM catalog_jobs WHERE id=$1`, job.ID).Scan(&payload); e != nil {
		return Source{}, nil, nil, nil, ErrUnavailable
	}
	if len(payload) > 0 {
		payload, e = s.open(payload, "catalog-job/v1/"+job.ID)
		if e != nil {
			return Source{}, nil, nil, nil, e
		}
	}
	return source, salt, secret, payload, tx.Commit()
}
func (s *Store) Cancel(ctx context.Context, actor Actor, id, request string, now time.Time) error {
	if !identifier.MatchString(id) || !identifier.MatchString(request) {
		return ErrInvalid
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	var sourceID string
	if e = tx.QueryRowContext(ctx, `SELECT source_id FROM catalog_jobs WHERE id=$1`, id).Scan(&sourceID); e != nil {
		return ErrDenied
	}
	source, e := s.readSource(ctx, tx, sourceID, true)
	if e != nil {
		return e
	}
	if e = authorize(ctx, tx, actor, "sources.sync", "user", source.Owner, now.Unix(), false); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE catalog_jobs SET phase='cancelled',reason='cancelled_by_actor',updated_at=$2 WHERE id=$1 AND phase IN('queued','running')`, id, now.Unix())
	if e != nil {
		return ErrUnavailable
	}
	if e = audit(ctx, tx, actor.ID, "job.cancel", id, request, "", "", "cancelled", now.Unix()); e != nil {
		return ErrUnavailable
	}
	return tx.Commit()
}
func (s *Store) Fail(ctx context.Context, job Job, reason string, permanent bool, now time.Time) error {
	allowed := map[string]bool{"subscription_fetch_unavailable": true, "subscription_tls_failed": true, "subscription_access_denied": true, "subscription_access_revoked": true, "subscription_expired": true, "subscription_empty_response": true, "subscription_size_limit": true, "subscription_invalid": true, "subscription_unsupported": true, "subscription_ambiguous": true, "resource_unavailable": true, "resource_denied": true}
	if !allowed[reason] {
		reason = "subscription_fetch_unavailable"
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, job.SourceID, true)
	if e != nil {
		return e
	}
	if source.Revision != job.SourceRevision {
		return ErrStale
	}
	if e = jobCurrent(ctx, tx, job, now.Unix()); e != nil {
		return e
	}
	phase := "queued"
	delay := int64(5) << min(job.Attempts-1, 8)
	if delay > 3600 {
		delay = 3600
	}
	if permanent {
		phase = "failed"
	}
	state := "refresh_error"
	if reason == "subscription_access_revoked" || reason == "resource_denied" {
		state = "revoked"
	}
	if reason == "subscription_expired" {
		state = "expired"
	}
	if reason == "subscription_empty_response" || reason == "subscription_invalid" || reason == "subscription_unsupported" || reason == "subscription_ambiguous" || reason == "subscription_size_limit" {
		state = "quarantined"
	}
	_, e = tx.ExecContext(ctx, `UPDATE catalog_jobs SET phase=$2,reason=$3,lease='',lease_until=0,not_before=$4,updated_at=$5 WHERE id=$1`, job.ID, phase, reason, now.Unix()+delay, now.Unix())
	if e != nil {
		return ErrUnavailable
	}
	_, e = tx.ExecContext(ctx, `UPDATE catalog_sources SET state=$2,last_sync=$3,next_sync=$4 WHERE id=$1`, source.ID, state, now.Unix(), now.Unix()+source.RefreshSeconds)
	if e != nil {
		return ErrUnavailable
	}
	if e = audit(ctx, tx, "", "source.sync", source.ID, job.ID, "", "", reason, now.Unix()); e != nil {
		return ErrUnavailable
	}
	return tx.Commit()
}
