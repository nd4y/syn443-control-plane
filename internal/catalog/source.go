package catalog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"time"
)

func (s *Store) readSource(ctx context.Context, tx *sql.Tx, id string, lock bool) (Source, error) {
	var source Source
	var raw []byte
	var revision int64
	var active, candidate, resource sql.NullString
	var state, owner, mode, access, fetchDevice string
	var enabled bool
	var last, next, valid, refresh, stale, lastResource int64
	query := `SELECT spec,revision,active_snapshot,candidate_snapshot,state,last_sync,next_sync,owner,mode,resource_id,enabled,valid_until,refresh_seconds,max_stale_seconds,last_resource_revision,access_state,fetch_device_id FROM catalog_sources WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	e := tx.QueryRowContext(ctx, query, id).Scan(&raw, &revision, &active, &candidate, &state, &last, &next, &owner, &mode, &resource, &enabled, &valid, &refresh, &stale, &lastResource, &access, &fetchDevice)
	if e == sql.ErrNoRows {
		return source, ErrDenied
	}
	if e != nil {
		return source, ErrUnavailable
	}
	raw, e = s.open(raw, aad("source", id, revision))
	if e != nil || json.Unmarshal(raw, &source) != nil || source.ID != id || source.Revision != revision || source.Owner != owner || source.Mode != mode || source.ResourceID != resource.String || source.Enabled != enabled || source.ValidUntil != valid || source.RefreshSeconds != refresh || source.MaxStaleSeconds != stale || source.FetchDeviceID != fetchDevice {
		return Source{}, ErrUnavailable
	}
	source.ActiveSnapshot = active.String
	source.CandidateSnapshot = candidate.String
	source.State = state
	source.LastSync = last
	source.NextSync = next
	source.LastResourceRevision = lastResource
	source.AccessState = access
	return source, nil
}
func (s *Store) GetSource(ctx context.Context, actor Actor, id string, now time.Time) (Source, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Source{}, ErrUnavailable
	}
	defer tx.Rollback()
	source, e := s.readSource(ctx, tx, id, false)
	if e != nil {
		return Source{}, e
	}
	if e = authorize(ctx, tx, actor, "sources.read", "user", source.Owner, now.Unix(), false); e != nil {
		return Source{}, e
	}
	source, e = sourceStatus(ctx, tx, source, now)
	if e != nil {
		return Source{}, e
	}
	return source, tx.Commit()
}
func sourceStatus(ctx context.Context, tx *sql.Tx, source Source, now time.Time) (Source, error) {
	var e error
	if !source.Enabled {
		source.State = "disabled"
	} else if source.AccessState == "revoked" || source.AccessState == "expired" || source.AccessState == "quota_exhausted" {
		source.State = source.AccessState
	} else if source.ValidUntil <= now.Unix() {
		source.State = "expired"
	} else if source.ActiveSnapshot != "" {
		var until int64
		var quotaRaw []byte
		if e = tx.QueryRowContext(ctx, `SELECT valid_until,quota FROM catalog_snapshots WHERE source_id=$1 AND id=$2`, source.ID, source.ActiveSnapshot).Scan(&until, &quotaRaw); e != nil {
			return Source{}, ErrUnavailable
		}
		var quota struct {
			ExpiresAt int64 `json:"expiresAt"`
		}
		if json.Unmarshal(quotaRaw, &quota) != nil {
			return Source{}, ErrUnavailable
		}
		if quota.ExpiresAt > 0 && quota.ExpiresAt <= now.Unix() {
			source.State = "expired"
		} else if until <= now.Unix() {
			source.State = "stale"
		}
	}
	if source.Mode == "resource" && source.Enabled {
		var enabled bool
		var revision int64
		if e = tx.QueryRowContext(ctx, `SELECT enabled,revision FROM catalog_resources WHERE id=$1`, source.ResourceID).Scan(&enabled, &revision); e != nil {
			return Source{}, ErrUnavailable
		}
		if !enabled && source.State != "revoked" && source.State != "expired" && source.State != "quota_exhausted" {
			source.State = "resource_disabled"
		} else if revision != source.LastResourceRevision && source.State == "active" {
			source.State = "refresh_pending"
		}
	}
	return source, nil
}

// PutSource uses expected revision, live authority and one immutable operation
// identity. Neither an endpoint change nor a failed fetch extends an old lease.
func (s *Store) PutSource(ctx context.Context, actor Actor, source Source, secret SecretPatch, request string, now time.Time) (Source, error) {
	if source.Validate(now) != nil || !identifier.MatchString(request) || source.State != "" || source.ActiveSnapshot != "" || source.CandidateSnapshot != "" || source.LastSync != 0 || source.NextSync != 0 || source.LastResourceRevision != 0 || source.AccessState != "" {
		return Source{}, ErrInvalid
	}
	body, _ := json.Marshal(struct {
		Source Source
		Secret SecretPatch
	}{source, secret})
	hash := s.hash(body)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Source{}, ErrUnavailable
	}
	defer tx.Rollback()
	if e = authorize(ctx, tx, actor, "sources.write", "user", source.Owner, now.Unix(), secret.Operation != "keep"); e != nil {
		return Source{}, e
	}
	if source.Mode == "device" {
		if e = authorize(ctx, tx, actor, "sources.receive", "device", source.FetchDeviceID, now.Unix(), false); e != nil {
			return Source{}, e
		}
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "catalog-owner/"+source.Owner); e != nil {
		return Source{}, ErrUnavailable
	}
	// Serialize same actor/request before observing a lost-reply receipt.
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, actor.ID+"/"+request); e != nil {
		return Source{}, ErrUnavailable
	}
	prior, e := s.priorOperation(ctx, tx, actor.ID, request, "source.put", source.ID, hash, now.Unix())
	if e != nil {
		return Source{}, e
	}
	if prior != nil {
		var value Source
		if json.Unmarshal(prior, &value) != nil {
			return Source{}, ErrUnavailable
		}
		return value, tx.Commit()
	}
	old, e := s.readSource(ctx, tx, source.ID, true)
	exists := e == nil
	if e != nil && e != ErrDenied {
		return Source{}, e
	}
	var previousSecret, sourceSalt []byte
	if exists {
		if old.Owner != source.Owner || old.Mode != source.Mode || old.ResourceID != source.ResourceID || old.ExternalUserID != source.ExternalUserID || old.Revision != source.Revision || old.FetchDeviceID != "" && old.FetchDeviceID != source.FetchDeviceID {
			return Source{}, ErrConflict
		}
		if (source.ValidUntil > old.ValidUntil || source.MaxStaleSeconds > old.MaxStaleSeconds) && actor.MFAUntil <= now.Unix() {
			return Source{}, ErrDenied
		}
		var protected []byte
		if e = tx.QueryRowContext(ctx, `SELECT secrets,salt FROM catalog_sources WHERE id=$1`, source.ID).Scan(&protected, &sourceSalt); e != nil {
			return Source{}, ErrUnavailable
		}
		if len(protected) > 0 {
			previousSecret, e = s.open(protected, aad("source-secret", source.ID, old.Revision))
			if e != nil {
				return Source{}, e
			}
		}
	} else {
		if source.Revision != 0 {
			return Source{}, ErrConflict
		}
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM catalog_sources WHERE owner=$1`, source.Owner).Scan(&count); e != nil {
			return Source{}, ErrUnavailable
		}
		if count >= 32 {
			return Source{}, ErrQuota
		}
		sourceSalt = make([]byte, 32)
		if _, e = rand.Read(sourceSalt); e != nil {
			return Source{}, ErrUnavailable
		}
	}
	if source.Mode == "resource" {
		if e = authorize(ctx, tx, actor, "resources.bind", "resource", source.ResourceID, now.Unix(), false); e != nil {
			return Source{}, e
		}
		var enabled bool
		var kind string
		if e = tx.QueryRowContext(ctx, `SELECT enabled,provider_type FROM catalog_resources WHERE id=$1 FOR SHARE`, source.ResourceID).Scan(&enabled, &kind); e != nil || !enabled || kind != "panel.remnawave" {
			return Source{}, ErrDenied
		}
	}
	nextSecret, e := secret.Apply(previousSecret)
	if e != nil {
		return Source{}, e
	}
	if source.Mode == "server" || source.Mode == "device" {
		if len(nextSecret) == 0 {
			return Source{}, ErrInvalid
		}
	}
	if source.Mode == "manual" || source.Mode == "resource" {
		if len(nextSecret) > 0 {
			return Source{}, ErrInvalid
		}
	} else {
		if _, e = ReadFetchCredential(nextSecret); e != nil {
			return Source{}, e
		}
	}
	source.Revision++
	source.State = "pending"
	source.ActiveSnapshot = old.ActiveSnapshot
	if source.Mode == "device" && old.FetchDeviceID == "" {
		source.ActiveSnapshot = ""
	}
	source.NextSync = now.Unix()
	source.LastSync = old.LastSync
	source.LastResourceRevision = old.LastResourceRevision
	if !source.Enabled {
		source.State = "disabled"
	}
	raw, _ := json.Marshal(source)
	protected, e := s.seal(raw, aad("source", source.ID, source.Revision))
	if e != nil {
		return Source{}, e
	}
	var protectedSecret []byte
	if len(nextSecret) > 0 {
		protectedSecret, e = s.seal(nextSecret, aad("source-secret", source.ID, source.Revision))
		if e != nil {
			return Source{}, e
		}
	}
	var resource any
	if source.ResourceID != "" {
		resource = source.ResourceID
	}
	fetchModes, _ := json.Marshal(source.NetworkModes)
	if exists {
		_, e = tx.ExecContext(ctx, `UPDATE catalog_sources SET revision=$2,spec=$3,secrets=$4,enabled=$5,valid_until=$6,refresh_seconds=$7,max_stale_seconds=$8,candidate_snapshot=NULL,fetch_cache=NULL,state=$9,next_sync=$10,fetch_device_id=$11,active_snapshot=NULLIF($12,''),fetch_modes=$13::jsonb WHERE id=$1`, source.ID, source.Revision, protected, protectedSecret, source.Enabled, source.ValidUntil, source.RefreshSeconds, source.MaxStaleSeconds, source.State, source.NextSync, source.FetchDeviceID, source.ActiveSnapshot, string(fetchModes))
		if e == nil {
			_, e = tx.ExecContext(ctx, `UPDATE catalog_jobs SET phase='cancelled',reason='source_changed',updated_at=$2 WHERE source_id=$1 AND phase IN('queued','running')`, source.ID, now.Unix())
		}
	} else {
		_, e = tx.ExecContext(ctx, `INSERT INTO catalog_sources(id,owner,revision,spec,secrets,salt,mode,resource_id,enabled,valid_until,refresh_seconds,max_stale_seconds,state,next_sync,fetch_device_id,fetch_modes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb)`, source.ID, source.Owner, source.Revision, protected, protectedSecret, sourceSalt, source.Mode, resource, source.Enabled, source.ValidUntil, source.RefreshSeconds, source.MaxStaleSeconds, source.State, source.NextSync, source.FetchDeviceID, string(fetchModes))
	}
	if e != nil {
		return Source{}, ErrUnavailable
	}
	if e = s.recordOperation(ctx, tx, actor.ID, request, "source.put", source.ID, hash, source, now.Unix()); e != nil {
		return Source{}, ErrUnavailable
	}
	if e = audit(ctx, tx, actor.ID, "source.put", source.ID, request, "", s.hash(protected), "saved", now.Unix()); e != nil {
		return Source{}, ErrUnavailable
	}
	return source, tx.Commit()
}
