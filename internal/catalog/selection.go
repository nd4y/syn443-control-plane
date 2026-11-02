package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

// SelectionTarget comes from the independently authenticated device/assignment,
// never an unverified device-supplied owner, group list or administrative flag.
// Group grants are not consumed until verified group membership is available.
type SelectionTarget struct{ Owner, Device string }
type ProfileReference struct {
	SourceID  string `json:"sourceId"`
	ProfileID string `json:"profileId"`
}
type SelectionDependency struct {
	SourceID         string `json:"sourceId"`
	SourceRevision   int64  `json:"sourceRevision"`
	SnapshotID       string `json:"snapshotId"`
	SnapshotHash     string `json:"snapshotHash"`
	ShareRevision    int64  `json:"shareRevision"`
	ResourceRevision int64  `json:"resourceRevision"`
	ValidUntil       int64  `json:"validUntil"`
}

// PreparedSelection has no signing authority. The signer must repeat Lock in
// its final publication transaction, after its account/config authority fence.
// Credentials remain process-private and never enter ordinary inventory/diff.
type PreparedSelection struct {
	store        *Store
	target       SelectionTarget
	mode         string
	refs         []ProfileReference
	dependencies []SelectionDependency
	profiles     map[ProfileReference]subscriptions.Profile
	until        int64
}

func (SelectionTarget) String() string      { return "SelectionTarget([redacted])" }
func (SelectionTarget) GoString() string    { return "SelectionTarget([redacted])" }
func (*PreparedSelection) String() string   { return "PreparedSourceSelection([redacted])" }
func (*PreparedSelection) GoString() string { return "PreparedSourceSelection([redacted])" }
func (p *PreparedSelection) Dependencies() []SelectionDependency {
	return append([]SelectionDependency{}, p.dependencies...)
}
func (p *PreparedSelection) ValidUntil() int64 { return p.until }
func (p *PreparedSelection) Profile(ref ProfileReference) (subscriptions.Profile, bool) {
	value, ok := p.profiles[ref]
	value.Outbound = append(json.RawMessage(nil), value.Outbound...)
	return value, ok
}
func (s *Store) PublicationRole(ctx context.Context) error {
	var current, session string
	var unsafe bool
	var memberships int
	e := s.DB.QueryRowContext(ctx, `SELECT current_user,session_user,rolsuper OR rolbypassrls OR rolinherit OR rolcreatedb OR rolcreaterole,(SELECT count(*) FROM pg_auth_members WHERE member=r.oid) FROM pg_roles r WHERE rolname=current_user`).Scan(&current, &session, &unsafe, &memberships)
	if e != nil || current != "syn443_identity_publisher" || session != current || unsafe || memberships != 0 {
		return ErrDenied
	}
	return nil
}
func sourceSelectionValid(source Source, snapshot Snapshot, mode string, now time.Time) (int64, error) {
	if !source.Enabled || source.ActiveSnapshot == "" || source.AccessState != "allowed" || snapshot.ID != source.ActiveSnapshot || snapshot.SourceID != source.ID || snapshot.State != "active" || snapshot.SourceRevision > source.Revision || snapshot.ObservedAt > now.Unix()+30 {
		return 0, ErrDenied
	}
	admitted := false
	for _, value := range source.NetworkModes {
		admitted = admitted || value == mode
	}
	if !admitted {
		return 0, ErrDenied
	}
	until := min(source.ValidUntil, snapshot.ValidUntil, snapshot.ObservedAt+source.MaxStaleSeconds)
	if snapshot.Quota.Known && snapshot.Quota.Limit > 0 && snapshot.Quota.Used >= snapshot.Quota.Limit {
		return 0, ErrDenied
	}
	if snapshot.Quota.ExpiresAt > 0 {
		until = min(until, snapshot.Quota.ExpiresAt)
	}
	if until <= now.Unix() {
		return 0, ErrDenied
	}
	return until, nil
}
func (s *Store) selectionSource(ctx context.Context, tx *sql.Tx, target SelectionTarget, id, mode string, now time.Time) (SelectionDependency, error) {
	// All sharing/source/snapshot mutations serialize on this parent row.
	var locked string
	e := tx.QueryRowContext(ctx, `SELECT id FROM catalog_sources WHERE id=$1 FOR SHARE`, id).Scan(&locked)
	if e == sql.ErrNoRows {
		return SelectionDependency{}, ErrDenied
	}
	if e != nil {
		return SelectionDependency{}, ErrUnavailable
	}
	source, e := s.readSource(ctx, tx, id, false)
	if e != nil {
		return SelectionDependency{}, e
	}
	if source.Mode == "device" && source.Owner != target.Owner {
		return SelectionDependency{}, ErrDenied
	}
	if source.Owner != target.Owner {
		var granted bool
		e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_source_grants WHERE source_id=$1 AND ((target_kind='user' AND target_id=$2) OR (target_kind='device' AND target_id=$3)))`, source.ID, target.Owner, target.Device).Scan(&granted)
		if e != nil {
			return SelectionDependency{}, ErrUnavailable
		}
		if !granted {
			return SelectionDependency{}, ErrDenied
		}
	}
	var shares int64
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM catalog_share_heads WHERE source_id=$1),0)`, id).Scan(&shares); e != nil {
		return SelectionDependency{}, ErrUnavailable
	}
	var snapshot Snapshot
	var quota []byte
	e = tx.QueryRowContext(ctx, `SELECT id,source_id,source_revision,content_hash,observed_at,valid_until,state,quota,resource_revision FROM catalog_snapshots WHERE source_id=$1 AND id=$2`, id, source.ActiveSnapshot).Scan(&snapshot.ID, &snapshot.SourceID, &snapshot.SourceRevision, &snapshot.Hash, &snapshot.ObservedAt, &snapshot.ValidUntil, &snapshot.State, &quota, &snapshot.ResourceRevision)
	if e == sql.ErrNoRows {
		return SelectionDependency{}, ErrDenied
	}
	if e != nil || len(quota) > 4096 || json.Unmarshal(quota, &snapshot.Quota) != nil {
		return SelectionDependency{}, ErrUnavailable
	}
	until, e := sourceSelectionValid(source, snapshot, mode, now)
	if e != nil {
		return SelectionDependency{}, e
	}
	if e = resourceCurrent(ctx, tx, Job{ResourceRevision: snapshot.ResourceRevision}, source); e != nil {
		return SelectionDependency{}, e
	}
	return SelectionDependency{id, source.Revision, snapshot.ID, snapshot.Hash, shares, snapshot.ResourceRevision, until}, nil
}
func validSelection(target SelectionTarget, refs []ProfileReference, mode string, until int64, now time.Time) error {
	if !identifier.MatchString(target.Owner) || !identifier.MatchString(target.Device) || len(refs) < 1 || len(refs) > 64 || until <= now.Unix() || until > now.Unix()+604800 {
		return ErrInvalid
	}
	if mode != "home_wifi" && mode != "wifi" && mode != "cellular_restricted" && mode != "cellular" {
		return ErrInvalid
	}
	seen := map[ProfileReference]bool{}
	sources := map[string]bool{}
	for _, ref := range refs {
		if !sourceIdentifier.MatchString(ref.SourceID) || !identifier.MatchString(ref.ProfileID) || seen[ref] {
			return ErrInvalid
		}
		seen[ref] = true
		sources[ref.SourceID] = true
	}
	if len(sources) > 32 {
		return ErrQuota
	}
	return nil
}
func (s *Store) PrepareSelection(ctx context.Context, target SelectionTarget, refs []ProfileReference, mode string, until int64, now time.Time) (*PreparedSelection, error) {
	if e := validSelection(target, refs, mode, until, now); e != nil {
		return nil, e
	}
	p := &PreparedSelection{store: s, target: target, mode: mode, refs: append([]ProfileReference{}, refs...), until: until, profiles: map[ProfileReference]subscriptions.Profile{}}
	bySource := map[string][]ProfileReference{}
	for _, ref := range refs {
		bySource[ref.SourceID] = append(bySource[ref.SourceID], ref)
	}
	sources := make([]string, 0, len(bySource))
	for source := range bySource {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer tx.Rollback()
	remaining := 16 * 1024 * 1024
	for _, source := range sources {
		dependency, e := s.selectionSource(ctx, tx, target, source, mode, now)
		if e != nil {
			return nil, e
		}
		var size int
		if e = tx.QueryRowContext(ctx, `SELECT octet_length(profiles) FROM catalog_snapshots WHERE source_id=$1 AND id=$2`, source, dependency.SnapshotID).Scan(&size); e != nil {
			return nil, ErrUnavailable
		}
		if size < 1 || size > remaining {
			return nil, ErrQuota
		}
		remaining -= size
		var salt []byte
		if e = tx.QueryRowContext(ctx, `SELECT salt FROM catalog_sources WHERE id=$1`, source).Scan(&salt); e != nil || len(salt) != 32 {
			return nil, ErrUnavailable
		}
		snapshot, profiles, e := s.readSnapshot(ctx, tx, source, dependency.SnapshotID)
		if e != nil {
			return nil, e
		}
		if snapshot.Hash != dependency.SnapshotHash {
			return nil, ErrConflict
		}
		wanted := map[string]bool{}
		for _, ref := range bySource[source] {
			wanted[ref.ProfileID] = true
		}
		for _, profile := range profiles {
			if !wanted[profile.ID] {
				continue
			}
			// Ciphertext integrity is not a substitute for current parser/schema
			// validity when old snapshots meet a newer compiler.
			value, e := subscriptions.DecodeJSON(profile.Outbound)
			object, ok := value.(map[string]any)
			if e != nil || !ok || object["tag"] != profile.ID || object["type"] != profile.Kind || subscriptions.ValidateOutbound(object) != nil {
				return nil, ErrInvalid
			}
			if verifyProfileIDs(source, salt, []subscriptions.Profile{profile}) != nil {
				return nil, ErrInvalid
			}
			ref := ProfileReference{source, profile.ID}
			p.profiles[ref] = profile
		}
		for _, ref := range bySource[source] {
			if _, ok := p.profiles[ref]; !ok {
				return nil, ErrDenied
			}
		}
		p.dependencies = append(p.dependencies, dependency)
		p.until = min(p.until, dependency.ValidUntil)
	}
	if e = tx.Commit(); e != nil {
		return nil, ErrUnavailable
	}
	return p, nil
}
func (p *PreparedSelection) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil || p.store == nil || tx == nil || p.until <= now.Unix() {
		return ErrDenied
	}
	for _, old := range p.dependencies {
		current, e := p.store.selectionSource(ctx, tx, p.target, old.SourceID, p.mode, now)
		if e != nil {
			return e
		}
		if current != old {
			return ErrConflict
		}
	}
	return nil
}
