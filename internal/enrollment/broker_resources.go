package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// BrokerResourceCatalog has a separate encryption key and SQL namespace. It
// cannot authorize an identity or sign policies. Existing broker scopes pin
// exact immutable versions, including the version needed for safe cleanup.
type BrokerResourceCatalog struct {
	store   *Store
	fixture bool
}

func (*BrokerResourceCatalog) String() string   { return "OverlayResourceCatalog([redacted])" }
func (*BrokerResourceCatalog) GoString() string { return "OverlayResourceCatalog([redacted])" }
func NewBrokerResourceCatalog(db *sql.DB, key []byte, fixture bool) (*BrokerResourceCatalog, error) {
	if db == nil {
		return nil, identity.ErrInvalid
	}
	s, e := NewStore(db, key)
	if e != nil {
		return nil, e
	}
	return &BrokerResourceCatalog{store: s, fixture: fixture}, nil
}
func brokerResourceAAD(id string, revision int64) string {
	return "overlay-resource/v1/" + id + "/" + strconv.FormatInt(revision, 10)
}

func brokerResourceOwner(ctx context.Context, tx *sql.Tx) error {
	var current, session, owner string
	e := tx.QueryRowContext(ctx, `SELECT current_user,session_user,pg_get_userbyid(relowner) FROM pg_class WHERE oid='identity_overlay_resource_versions'::regclass`).Scan(&current, &session, &owner)
	if e != nil || current != owner || session != owner {
		return ErrDenied
	}
	return nil
}

// Put is deliberately owner-only until a separately authenticated control
// resource editor is wired. An immutable version is its own replay receipt.
func (c *BrokerResourceCatalog) Put(ctx context.Context, resource BrokerResource, previous int64, now time.Time) error {
	if c == nil || c.store == nil || ctx == nil || now.UnixMilli() <= 0 || previous < 0 || previous >= 9007199254740991 || resource.Revision != previous+1 {
		return identity.ErrInvalid
	}
	if _, e := NewBrokerResources([]BrokerResource{resource}, c.fixture); e != nil {
		return e
	}
	raw, e := json.Marshal(resource)
	if e != nil || len(raw) > 65536 {
		return identity.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, e := c.store.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	if e = brokerResourceOwner(ctx, tx); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "overlay-resource/"+resource.ResourceID); e != nil {
		return ErrUnavailable
	}
	var saved string
	var retired int64
	e = tx.QueryRowContext(ctx, `SELECT body_hash,retired_ms FROM identity_overlay_resource_versions WHERE resource=$1 AND revision=$2`, resource.ResourceID, resource.Revision).Scan(&saved, &retired)
	if e == nil {
		if saved != identity.Hash(raw) || retired != 0 {
			return ErrConflict
		}
		if tx.Commit() != nil {
			return ErrUnavailable
		}
		return nil
	}
	if e != sql.ErrNoRows {
		return ErrUnavailable
	}
	var head int64
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(revision),0) FROM identity_overlay_resource_versions WHERE resource=$1`, resource.ResourceID).Scan(&head); e != nil {
		return ErrUnavailable
	}
	if head != previous {
		return ErrConflict
	}
	protected := c.store.Seal(raw, brokerResourceAAD(resource.ResourceID, resource.Revision))
	if _, e = tx.ExecContext(ctx, `INSERT INTO identity_overlay_resource_versions(resource,revision,body_hash,body,created_ms) VALUES($1,$2,$3,$4,$5)`, resource.ResourceID, resource.Revision, identity.Hash(raw), protected, now.UnixMilli()); e != nil {
		return ErrUnavailable
	}
	if tx.Commit() != nil {
		return ErrUnavailable
	}
	return nil
}

// RetireBrokerResourceVersion removes an obsolete ciphertext while retaining its
// immutable identity and retirement timestamp. The database also fences every
// new reservation against the retirement, regardless of publisher version.
func RetireBrokerResourceVersion(ctx context.Context, db *sql.DB, resource string, revision, expectedHead int64, now time.Time) error {
	if ctx == nil || db == nil || !brokerIdentifier.MatchString(resource) || revision < 1 || expectedHead <= revision || expectedHead > 9007199254740991 || now.UnixMilli() <= 0 {
		return identity.ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	if e = brokerResourceOwner(ctx, tx); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "overlay-resource/"+resource); e != nil {
		return ErrUnavailable
	}
	var created, retired int64
	e = tx.QueryRowContext(ctx, `SELECT created_ms,retired_ms FROM identity_overlay_resource_versions WHERE resource=$1 AND revision=$2`, resource, revision).Scan(&created, &retired)
	if e == sql.ErrNoRows {
		return ErrDenied
	}
	if e != nil {
		return ErrUnavailable
	}
	if retired != 0 {
		// A lost reply can be reconciled even after a later rotation.
		if tx.Commit() != nil {
			return ErrUnavailable
		}
		return nil
	}
	var head int64
	if e = tx.QueryRowContext(ctx, `SELECT max(revision) FROM identity_overlay_resource_versions WHERE resource=$1`, resource).Scan(&head); e != nil {
		return ErrUnavailable
	}
	if head != expectedHead || now.UnixMilli() <= created {
		return ErrConflict
	}
	result, e := tx.ExecContext(ctx, `UPDATE identity_overlay_resource_versions SET body=NULL,retired_ms=$3 WHERE resource=$1 AND revision=$2 AND retired_ms=0`, resource, revision, now.UnixMilli())
	if e != nil {
		var constraint *pgconn.PgError
		if errors.As(e, &constraint) && constraint.Code == "23514" {
			return ErrConflict
		}
		return ErrUnavailable
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	if tx.Commit() != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *BrokerResourceCatalog) RuntimeRole(ctx context.Context) error {
	if c == nil || c.store == nil || ctx == nil {
		return ErrDenied
	}
	if e := c.store.BrokerRuntimeRole(ctx); e != nil {
		return e
	}
	var read, insert, update, remove bool
	e := c.store.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'identity_overlay_resource_versions','SELECT'),has_any_column_privilege(current_user,'identity_overlay_resource_versions','INSERT'),has_any_column_privilege(current_user,'identity_overlay_resource_versions','UPDATE'),has_table_privilege(current_user,'identity_overlay_resource_versions','DELETE') OR has_table_privilege(current_user,'identity_overlay_resource_versions','TRUNCATE') OR has_table_privilege(current_user,'identity_overlay_resource_versions','TRIGGER')`).Scan(&read, &insert, &update, &remove)
	if e != nil || !read || insert || update || remove {
		return ErrDenied
	}
	return nil
}

func (c *BrokerResourceCatalog) Resolve(ctx context.Context, scope BrokerScope) (BrokerProvider, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if e := c.RuntimeRole(ctx); e != nil {
		return nil, nil, e
	}
	var hash string
	var protected []byte
	e := c.store.DB.QueryRowContext(ctx, `SELECT body_hash,body FROM identity_overlay_resource_versions WHERE resource=$1 AND revision=$2 AND retired_ms=0`, scope.Binding.Address.ResourceID, scope.ResourceRevision).Scan(&hash, &protected)
	if e == sql.ErrNoRows {
		return nil, nil, ErrDenied
	}
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	raw, e := c.store.Open(protected, brokerResourceAAD(scope.Binding.Address.ResourceID, scope.ResourceRevision))
	var resource BrokerResource
	if e != nil || identity.Hash(raw) != hash || identity.DecodeOperatorDocument(raw, &resource) != nil || resource.ResourceID != scope.Binding.Address.ResourceID || resource.Revision != scope.ResourceRevision {
		return nil, nil, ErrUnavailable
	}
	resources, e := NewBrokerResources([]BrokerResource{resource}, c.fixture)
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	return resources.Resolve(ctx, scope)
}
