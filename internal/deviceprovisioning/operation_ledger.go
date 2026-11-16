package deviceprovisioning

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

// These bounds are owner-policy constants, never caller supplied. SQL enforces
// the same limits atomically, including normal and checked-backfill separation.
const (
	operationNormalActorDay    = 512
	operationNormalGlobalDay   = 32768
	operationNormalTotal       = 1048576
	operationBackfillActorDay  = 128
	operationBackfillGlobalDay = 8192
	operationBackfillTotal     = 65536
)

type configurationOperation struct {
	Actor, Request, Action, Hash, Kind, Target string
	Version                                    int
	Disposition, EffectID                      string
	EffectRevision, RecordedMS                 int64
	Backfill                                   bool
}

func (configurationOperation) String() string   { return "ConfigurationOperation([redacted])" }
func (configurationOperation) GoString() string { return "ConfigurationOperation([redacted])" }

func operationFamily(action string) string {
	switch action {
	case "configuration.layers.draft.put", "configuration.layers.draft.discard":
		return "draft"
	case "configuration.preview.request", "configuration.publish":
		return "job"
	default:
		return ""
	}
}

// Version two is deliberately restricted to four mutations. An old strict
// version-one server rejects it before any configuration business effect.
func configurationVersion(version int, action string) bool {
	return version == 1 || version == 2 && operationFamily(action) != ""
}

func operationLock(ctx context.Context, tx *sql.Tx, actor, family string) error {
	prefix := "configuration-private-drafts/"
	if family == "job" {
		prefix = "configuration-requests/"
	} else if family != "draft" {
		return enrollment.ErrDenied
	}
	if _, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, prefix+actor); e != nil {
		return enrollment.ErrUnavailable
	}
	return nil
}

func operationRead(ctx context.Context, tx *sql.Tx, actor, family, request string) (*configurationOperation, error) {
	o := &configurationOperation{Actor: actor, Request: request}
	e := tx.QueryRowContext(ctx, `SELECT action,body_hash,protocol_version,target_kind,target_id,disposition,effect_id,effect_revision,recorded_ms,backfill FROM managed_configuration_operations WHERE actor=$1 AND family=$2 AND request_id=$3`, actor, family, request).Scan(&o.Action, &o.Hash, &o.Version, &o.Kind, &o.Target, &o.Disposition, &o.EffectID, &o.EffectRevision, &o.RecordedMS, &o.Backfill)
	if e == sql.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, enrollment.ErrUnavailable
	}
	return o, nil
}

func operationSame(have, want configurationOperation) bool {
	return have.Actor == want.Actor && have.Request == want.Request && have.Action == want.Action && have.Hash == want.Hash && have.Version == want.Version && have.Kind == want.Kind && have.Target == want.Target
}

// Call only under the existing family/actor lock. A new RECORDED row precedes
// its effect in this same transaction; deferred SQL verifies the effect at COMMIT.
func operationInsert(ctx context.Context, tx *sql.Tx, o configurationOperation, now time.Time) error {
	if !configurationRequestID.MatchString(o.Actor) || !configurationRequestID.MatchString(o.Request) || !configurationBodyHash.MatchString(o.Hash) || operationFamily(o.Action) == "" || !configurationTargetShape(o.Kind, o.Target) || !configurationVersion(o.Version, o.Action) || o.Disposition != "recorded" && o.Disposition != "no_effect" || o.Disposition == "no_effect" && o.Version != 2 {
		return enrollment.ErrDenied
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO managed_configuration_operations(actor,family,request_id,action,body_hash,protocol_version,target_kind,target_id,disposition,effect_id,effect_revision,recorded_ms,backfill) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, o.Actor, operationFamily(o.Action), o.Request, o.Action, o.Hash, o.Version, o.Kind, o.Target, o.Disposition, o.EffectID, o.EffectRevision, now.UnixMilli(), o.Backfill)
	if e != nil {
		// SQL errors are never returned as diagnostics or interpreted as absence.
		var state interface{ SQLState() string }
		if errors.As(e, &state) && state.SQLState() == "P0042" {
			return catalog.ErrQuota
		}
		return enrollment.ErrUnavailable
	}
	return nil
}

func operationAdmission(ctx context.Context, tx *sql.Tx, want configurationOperation) (*configurationOperation, error) {
	have, e := operationRead(ctx, tx, want.Actor, operationFamily(want.Action), want.Request)
	if e != nil || have == nil {
		return have, e
	}
	if !operationSame(*have, want) || have.Disposition != "recorded" {
		return nil, enrollment.ErrConflict
	}
	return have, nil
}
