package catalog

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"slices"
	"time"
)

// DeviceFetchScope must be supplied by the authenticated device session, never
// decoded from request JSON. The transaction must hold that session's fence.
type DeviceFetchScope struct{ Owner, Device string }

func (DeviceFetchScope) String() string   { return "DeviceFetchScope([redacted])" }
func (DeviceFetchScope) GoString() string { return "DeviceFetchScope([redacted])" }

type DeviceFetchLease struct {
	JobID        string          `json:"jobId"`
	Lease        string          `json:"lease"`
	Until        int64           `json:"until"`
	NetworkModes []string        `json:"networkModes"`
	Credential   FetchCredential `json:"credential"`
}

const MaxDeviceFetchBytes = 10 * 1024 * 1024

func (s *Store) DeviceFetchRole(ctx context.Context) error {
	var scoped bool
	err := s.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'public.catalog_device_fetch_sources','SELECT')
 AND has_table_privilege(current_user,'public.catalog_device_fetch_jobs','SELECT')
 AND has_column_privilege(current_user,'public.catalog_device_fetch_sources','selection_guard','UPDATE')
 AND has_column_privilege(current_user,'public.catalog_device_fetch_jobs','payload','UPDATE')
 AND NOT has_column_privilege(current_user,'public.catalog_device_fetch_jobs','phase','UPDATE')
 AND NOT has_any_column_privilege(current_user,'public.catalog_sources','SELECT')
 AND NOT has_any_column_privilege(current_user,'public.catalog_jobs','SELECT')`).Scan(&scoped)
	if err != nil || !scoped {
		return ErrDenied
	}
	return nil
}

func (DeviceFetchLease) String() string   { return "DeviceFetchLease([redacted])" }
func (DeviceFetchLease) GoString() string { return "DeviceFetchLease([redacted])" }

func (s *Store) readDeviceFetchSource(ctx context.Context, tx *sql.Tx, id string, scope DeviceFetchScope) (Source, error) {
	var source Source
	var sealed, encodedModes []byte
	var revision, validUntil int64
	var enabled bool
	var active string
	if err := tx.QueryRowContext(ctx, `SELECT spec,revision,valid_until,enabled,COALESCE(active_snapshot,''),fetch_modes FROM catalog_device_fetch_sources
 WHERE id=$1 AND owner=$2 AND fetch_device_id=$3`, id, scope.Owner, scope.Device).Scan(&sealed, &revision, &validUntil, &enabled, &active, &encodedModes); err != nil {
		return source, ErrUnavailable
	}
	raw, err := s.open(sealed, aad("source", id, revision))
	var modes []string
	if err != nil || json.Unmarshal(raw, &source) != nil || source.ID != id || source.Mode != "device" ||
		source.Owner != scope.Owner || source.FetchDeviceID != scope.Device || source.Revision != revision ||
		source.Enabled != enabled || source.ValidUntil != validUntil || json.Unmarshal(encodedModes, &modes) != nil || !slices.Equal(modes, source.NetworkModes) {
		return Source{}, ErrUnavailable
	}
	source.ActiveSnapshot = active
	return source, nil
}

func (s *Store) ClaimDeviceFetch(ctx context.Context, tx *sql.Tx, scope DeviceFetchScope, now time.Time) (DeviceFetchLease, error) {
	var result DeviceFetchLease
	if !identifier.MatchString(scope.Owner) || !identifier.MatchString(scope.Device) {
		return result, ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "catalog/device-fetch/"+scope.Owner+"/"+scope.Device); err != nil {
		return result, ErrUnavailable
	}
	second := now.Unix()
	var id string
	err := tx.QueryRowContext(ctx, `SELECT s.id FROM catalog_device_fetch_sources s JOIN catalog_device_fetch_jobs j ON j.source_id=s.id
 WHERE s.owner=$1 AND s.fetch_device_id=$2 AND s.mode='device' AND s.enabled AND s.valid_until>$3 AND s.fetch_modes ? 'wifi'
 AND j.kind='device' AND j.phase='queued' AND j.payload IS NULL AND j.deadline>$3 AND j.not_before<=$3
 AND (j.lease_until>$3 OR j.device_attempts<8) AND j.source_revision=s.revision
 AND COALESCE(j.base_snapshot,'')=COALESCE(s.active_snapshot,'')
 ORDER BY (j.lease_until>$3) DESC,j.created_at,j.id LIMIT 1 FOR UPDATE OF s SKIP LOCKED`, scope.Owner, scope.Device, second).Scan(&id)
	if err == sql.ErrNoRows {
		return result, nil
	}
	if err != nil {
		return result, ErrUnavailable
	}
	source, err := s.readDeviceFetchSource(ctx, tx, id, scope)
	if err != nil {
		return result, err
	}
	var deadline int64
	err = tx.QueryRowContext(ctx, `SELECT id,lease,lease_until,deadline FROM catalog_device_fetch_jobs WHERE source_id=$1 AND kind='device' AND phase='queued'
 AND source_revision=$2 AND payload IS NULL AND deadline>$3 AND not_before<=$3 AND (lease_until>$3 OR device_attempts<8)
 AND COALESCE(base_snapshot,'')=$4 FOR UPDATE`, id, source.Revision, second, source.ActiveSnapshot).Scan(&result.JobID, &result.Lease, &result.Until, &deadline)
	if err == sql.ErrNoRows {
		return DeviceFetchLease{}, nil
	}
	if err != nil {
		return DeviceFetchLease{}, ErrUnavailable
	}
	var sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT secrets FROM catalog_device_fetch_sources WHERE id=$1`, id).Scan(&sealed); err != nil {
		return DeviceFetchLease{}, ErrUnavailable
	}
	cleartext, err := s.open(sealed, aad("source-secret", id, source.Revision))
	if err != nil {
		return DeviceFetchLease{}, err
	}
	defer clear(cleartext)
	result.Credential, err = ReadFetchCredential(cleartext)
	if err != nil {
		return DeviceFetchLease{}, err
	}
	result.NetworkModes = source.NetworkModes
	if result.Until > second {
		return result, nil
	}
	result.Lease, err = random()
	if err != nil {
		return DeviceFetchLease{}, err
	}
	result.Until = min(second+60, deadline, source.ValidUntil)
	if _, err = tx.ExecContext(ctx, `UPDATE catalog_device_fetch_jobs SET lease=$2,lease_until=$3,device_attempts=device_attempts+1,updated_at=$4 WHERE id=$1`, result.JobID, result.Lease, result.Until, second); err != nil {
		return DeviceFetchLease{}, ErrUnavailable
	}
	return result, nil
}

// AcceptDeviceFetch keeps the uploaded provider bytes in the existing encrypted
// job input. Only the source worker can normalize them into a candidate.
func (s *Store) AcceptDeviceFetch(ctx context.Context, tx *sql.Tx, scope DeviceFetchScope, jobID, lease string, raw []byte, now time.Time) error {
	if !identifier.MatchString(scope.Owner) || !identifier.MatchString(scope.Device) ||
		!identifier.MatchString(jobID) || !identifier.MatchString(lease) || len(raw) == 0 || len(raw) > MaxDeviceFetchBytes {
		return ErrInvalid
	}
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT s.id FROM catalog_device_fetch_sources s JOIN catalog_device_fetch_jobs j ON j.source_id=s.id
 WHERE j.id=$1 AND j.kind='device' AND s.mode='device' AND s.owner=$2 AND s.fetch_device_id=$3 FOR UPDATE OF s`, jobID, scope.Owner, scope.Device).Scan(&id); err == sql.ErrNoRows {
		return ErrDenied
	} else if err != nil {
		return ErrUnavailable
	}
	source, err := s.readDeviceFetchSource(ctx, tx, id, scope)
	if err != nil {
		return err
	}
	var phase, expected, receipt, base string
	var revision, until, deadline int64
	if err = tx.QueryRowContext(ctx, `SELECT phase,lease,lease_until,deadline,source_revision,COALESCE(base_snapshot,''),device_result_hash
 FROM catalog_device_fetch_jobs WHERE id=$1 FOR UPDATE`, jobID).Scan(&phase, &expected, &until, &deadline, &revision, &base, &receipt); err != nil {
		return ErrUnavailable
	}
	second := now.Unix()
	if !source.Enabled || source.ValidUntil <= second || source.Revision != revision {
		return ErrStale
	}
	digest := s.hash([]byte("device-fetch/"+jobID+"/"+lease+"\x00"), raw)
	if receipt != "" {
		if subtle.ConstantTimeCompare([]byte(receipt), []byte(digest)) == 1 {
			return nil
		}
		return ErrConflict
	}
	if phase != "queued" || until <= second || deadline <= second || source.ActiveSnapshot != base ||
		subtle.ConstantTimeCompare([]byte(expected), []byte(lease)) != 1 {
		return ErrStale
	}
	payload, err := s.seal(raw, "catalog-job/v1/"+jobID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE catalog_device_fetch_jobs SET payload=$2,device_result_hash=$3,lease='',lease_until=0,updated_at=$4 WHERE id=$1`, jobID, payload, digest, second); err != nil {
		return ErrUnavailable
	}
	return nil
}
