package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

const configurationReconcilePath = "/v1/control/configuration/reconcile"

type configurationReconcileInput struct {
	Version        int    `json:"version"`
	RequestID      string `json:"requestId"`
	Intent         string `json:"intent"`
	OriginalBody64 string `json:"originalBody64"`
}

func (configurationReconcileInput) String() string { return "ConfigurationReconcileInput([redacted])" }
func (configurationReconcileInput) GoString() string {
	return "ConfigurationReconcileInput([redacted])"
}

type ConfigurationOperationOutcome struct {
	Version        int                       `json:"version"`
	Actor          string                    `json:"actor"`
	Action         string                    `json:"action"`
	RequestID      string                    `json:"requestId"`
	BodyHash       string                    `json:"bodyHash"`
	TargetKind     string                    `json:"targetKind"`
	TargetID       string                    `json:"targetId"`
	Outcome        string                    `json:"outcome"`
	RecordedAtMS   int64                     `json:"recordedAtMs"`
	EffectKind     string                    `json:"effectKind"`
	EffectID       string                    `json:"effectId"`
	EffectRevision int64                     `json:"effectRevision"`
	Job            *ConfigurationRequestView `json:"job,omitempty"`
}

func (ConfigurationOperationOutcome) String() string {
	return "ConfigurationOperationOutcome([redacted])"
}
func (ConfigurationOperationOutcome) GoString() string {
	return "ConfigurationOperationOutcome([redacted])"
}

func decodeReconcile(raw []byte) (configurationReconcileInput, invitation.Envelope, []byte, error) {
	var in configurationReconcileInput
	var original invitation.Envelope
	if len(raw) < 1 || len(raw) > 524288 || identity.DecodeConfiguration(raw, &in) != nil || in.Version != 1 || !configurationRequestID.MatchString(in.RequestID) || in.Intent != "lookup" && in.Intent != "seal_if_absent" || len(in.OriginalBody64) < 1 || len(in.OriginalBody64) > 349526 {
		return in, original, nil, enrollment.ErrDenied
	}
	owned, e := base64.RawURLEncoding.DecodeString(in.OriginalBody64)
	if e != nil || len(owned) < 1 || len(owned) > 262144 || base64.RawURLEncoding.EncodeToString(owned) != in.OriginalBody64 || identity.DecodeConfiguration(owned, &original) != nil || !configurationRequestID.MatchString(original.RequestID) || operationFamily(original.Action) == "" || !configurationVersion(original.Version, original.Action) {
		for i := range owned {
			owned[i] = 0
		}
		return in, original, nil, enrollment.ErrDenied
	}
	return in, original, owned, nil
}

func operationACL(action string) string {
	switch action {
	case "configuration.layers.draft.put", "configuration.layers.draft.discard":
		return "configuration.drafts.write"
	case "configuration.preview.request":
		return "configuration.preview"
	case "configuration.publish":
		return "configuration.publish"
	default:
		return ""
	}
}

// Structural target recovery never reruns publication/compilation, renews an
// old ticket or reuses an old bearer. Recorded publish rows retain their own
// immutable target even if the original preview is no longer recoverable.
func (c *ConfigurationControl) operationTarget(ctx context.Context, tx *sql.Tx, actor string, original invitation.Envelope) (string, string, error) {
	switch original.Action {
	case "configuration.layers.draft.put":
		var in struct {
			Draft ConfigurationDraft `json:"draft"`
		}
		if identity.DecodeConfiguration(original.Payload, &in) != nil || in.Draft.ID != in.Draft.Proposal.DraftID || in.Draft.Revision < 0 || in.Draft.Revision >= 9007199254740991 || in.Draft.Proposal.DraftRevision != in.Draft.Revision+1 || in.Draft.SavedAtMs != 0 {
			return "", "", enrollment.ErrDenied
		}
		return in.Draft.Proposal.TargetKind, in.Draft.Proposal.TargetID, nil
	case "configuration.layers.draft.discard":
		var in ConfigurationDraftDiscard
		if identity.DecodeConfiguration(original.Payload, &in) != nil || !configurationObjectID.MatchString(in.ID) || in.Revision < 1 || in.Revision > 9007199254740991 {
			return "", "", enrollment.ErrDenied
		}
		return in.TargetKind, in.TargetID, nil
	case "configuration.preview.request":
		var in configurationPreviewInput
		if identity.DecodeConfiguration(original.Payload, &in) != nil {
			return "", "", enrollment.ErrDenied
		}
		return in.Proposal.TargetKind, in.Proposal.TargetID, nil
	case "configuration.publish":
		var in configurationPublishInput
		if identity.DecodeConfiguration(original.Payload, &in) != nil || !configurationRequestID.MatchString(in.PreviewID) || len(in.Ticket) < 128 || len(in.Ticket) > 90000 {
			return "", "", enrollment.ErrDenied
		}
		var protected []byte
		var ticket string
		if e := tx.QueryRowContext(ctx, `SELECT body,ticket FROM managed_configuration_previews WHERE id=$1 AND actor=$2`, in.PreviewID, actor).Scan(&protected, &ticket); e != nil || ticket != in.Ticket {
			return "", "", enrollment.ErrDenied
		}
		plain, e := c.Store.Open(protected, layerProposalAAD(in.PreviewID))
		var p LayerProposal
		if e != nil || identity.DecodeConfiguration(plain, &p) != nil {
			return "", "", enrollment.ErrUnavailable
		}
		return p.TargetKind, p.TargetID, nil
	}
	return "", "", enrollment.ErrDenied
}

// Reading retained native history is checked evidence, not proof of absence.
// It never charges quota. A seal request may explicitly backfill it afterwards.
func (c *ConfigurationControl) legacyOperation(ctx context.Context, tx *sql.Tx, want configurationOperation) (*configurationOperation, error) {
	o := want
	o.Disposition = "recorded"
	o.Backfill = true
	if operationFamily(want.Action) == "job" {
		var hash, action string
		e := tx.QueryRowContext(ctx, `SELECT id,action,body_hash,target_kind,target_id,created_ms FROM managed_configuration_requests WHERE actor=$1 AND request_id=$2`, want.Actor, want.Request).Scan(&o.EffectID, &action, &hash, &o.Kind, &o.Target, &o.RecordedMS)
		if e == sql.ErrNoRows {
			return nil, nil
		}
		if e != nil {
			return nil, enrollment.ErrUnavailable
		}
		if hash != want.Hash || action != want.Action {
			return nil, enrollment.ErrConflict
		}
		return &o, nil
	}
	var hash string
	var protected []byte
	var expiry int64
	e := tx.QueryRowContext(ctx, `SELECT body_hash,response,expires_ms FROM managed_configuration_draft_ops WHERE actor=$1 AND request_id=$2`, want.Actor, want.Request).Scan(&hash, &protected, &expiry)
	if e == sql.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, enrollment.ErrUnavailable
	}
	if hash != want.Hash {
		return nil, enrollment.ErrConflict
	}
	plain, e := c.Store.Open(protected, configurationDraftOpAAD(want.Actor, want.Request))
	if e != nil {
		return nil, enrollment.ErrUnavailable
	}
	if want.Action == "configuration.layers.draft.put" {
		var saved ConfigurationDraft
		if identity.DecodeConfiguration(plain, &saved) != nil || !configurationObjectID.MatchString(saved.ID) || saved.Revision < 1 {
			return nil, enrollment.ErrUnavailable
		}
		o.EffectID = saved.ID
		o.EffectRevision = saved.Revision
		o.RecordedMS = saved.SavedAtMs
		o.Kind = saved.Proposal.TargetKind
		o.Target = saved.Proposal.TargetID
	} else {
		var saved ConfigurationDraftDiscarded
		if identity.DecodeConfiguration(plain, &saved) != nil || !saved.Discarded || !configurationObjectID.MatchString(saved.ID) || saved.Revision < 1 {
			return nil, enrollment.ErrUnavailable
		}
		o.EffectID = saved.ID
		o.EffectRevision = saved.Revision
		o.RecordedMS = expiry - (24 * time.Hour).Milliseconds()
	}
	return &o, nil
}

func (c *ConfigurationControl) operationOutcome(ctx context.Context, tx *sql.Tx, o configurationOperation) (ConfigurationOperationOutcome, error) {
	r := ConfigurationOperationOutcome{Version: 1, Actor: o.Actor, Action: o.Action, RequestID: o.Request, BodyHash: o.Hash, TargetKind: o.Kind, TargetID: o.Target, RecordedAtMS: o.RecordedMS, EffectKind: operationFamily(o.Action), EffectID: o.EffectID, EffectRevision: o.EffectRevision, Outcome: "RECORDED"}
	if o.Disposition == "no_effect" {
		r.Outcome = "NO_EFFECT"
		r.EffectKind = ""
		return r, nil
	}
	if operationFamily(o.Action) == "job" {
		job := &ConfigurationRequestView{ID: o.EffectID}
		var body []byte
		var hash, action, kind, target string
		e := tx.QueryRowContext(ctx, `SELECT body_hash,action,target_kind,target_id,state,error_code,result FROM managed_configuration_requests WHERE id=$1 AND actor=$2 AND request_id=$3`, o.EffectID, o.Actor, o.Request).Scan(&hash, &action, &kind, &target, &job.State, &job.Error, &body)
		if e == sql.ErrNoRows {
			r.Outcome = "RECORDED_RESULT_UNAVAILABLE"
			return r, nil
		}
		if e != nil || hash != o.Hash || action != o.Action || kind != o.Kind || target != o.Target || len(body) > 100000 || len(body) > 0 && !json.Valid(body) {
			return r, enrollment.ErrUnavailable
		}
		job.Result = append(json.RawMessage(nil), body...)
		r.Job = job
		return r, nil
	}
	// Do not duplicate a proposal in this reply. Its checked reference/hash binds
	// the caller's own pending bytes; a pruned response remains explicitly missing.
	var hash string
	var protected []byte
	e := tx.QueryRowContext(ctx, `SELECT body_hash,response FROM managed_configuration_draft_ops WHERE actor=$1 AND request_id=$2`, o.Actor, o.Request).Scan(&hash, &protected)
	if e == sql.ErrNoRows {
		r.Outcome = "RECORDED_RESULT_UNAVAILABLE"
		return r, nil
	}
	if e != nil || hash != o.Hash {
		return r, enrollment.ErrUnavailable
	}
	plain, e := c.Store.Open(protected, configurationDraftOpAAD(o.Actor, o.Request))
	if e != nil {
		return r, enrollment.ErrUnavailable
	}
	if o.Action == "configuration.layers.draft.put" {
		var saved ConfigurationDraft
		if identity.DecodeConfiguration(plain, &saved) != nil || saved.ID != o.EffectID || saved.Revision != o.EffectRevision || saved.Proposal.TargetKind != o.Kind || saved.Proposal.TargetID != o.Target {
			return r, enrollment.ErrUnavailable
		}
	} else {
		var saved ConfigurationDraftDiscarded
		if identity.DecodeConfiguration(plain, &saved) != nil || !saved.Discarded || saved.ID != o.EffectID || saved.Revision != o.EffectRevision {
			return r, enrollment.ErrUnavailable
		}
	}
	return r, nil
}

func (c *ConfigurationControl) ReconcileAction(ctx context.Context, token, proof string, raw []byte, now time.Time) (any, error) {
	value, e := c.reconcile(ctx, token, proof, raw, now)
	if e == nil {
		return value, nil
	}
	if e == catalog.ErrQuota {
		return nil, catalog.ErrQuota
	}
	if e == errConfigurationReauthentication {
		return nil, catalog.ErrReauthentication
	}
	if e == enrollment.ErrConflict {
		return nil, catalog.ErrConflict
	}
	if e == enrollment.ErrDenied {
		return nil, catalog.ErrDenied
	}
	return nil, catalog.ErrUnavailable
}

func (c *ConfigurationControl) reconcile(ctx context.Context, token, proof string, raw []byte, now time.Time) (ConfigurationOperationOutcome, error) {
	var result ConfigurationOperationOutcome
	if c == nil || c.Store == nil || c.Verifier == nil || ctx == nil {
		return result, enrollment.ErrDenied
	}
	in, original, body, e := decodeReconcile(raw)
	if e != nil {
		return result, e
	}
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()
	if e = ConfigurationRuntimeRole(ctx, c.Store.DB, false); e != nil {
		return result, e
	}
	p, e := c.Verifier.Verify(ctx, token, now)
	if e != nil || !p.HasScope("syn443.control") || p.Expires <= now.Unix() {
		return result, enrollment.ErrDenied
	}
	verified, e := identity.VerifyProof(proof, identity.ProofContext{Method: "POST", URI: c.Origin + configurationReconcilePath, Token: token, BodyHash: identity.Hash(raw), Now: now})
	if e != nil || verified.Thumbprint != p.Thumbprint {
		return result, enrollment.ErrDenied
	}
	want := configurationOperation{Actor: identity.Hash([]byte(p.Issuer + "\x00" + p.Subject)), Request: original.RequestID, Action: original.Action, Hash: configurationHash(body), Version: original.Version}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	if e = operationLock(ctx, tx, want.Actor, operationFamily(want.Action)); e != nil {
		return result, e
	}
	have, e := operationRead(ctx, tx, want.Actor, operationFamily(want.Action), want.Request)
	if e != nil {
		return result, e
	}
	if have != nil {
		if have.Action != want.Action || have.Hash != want.Hash || have.Version != want.Version {
			return result, enrollment.ErrConflict
		}
		want.Kind = have.Kind
		want.Target = have.Target
	} else {
		// A retained job already has immutable actor-derived target metadata.
		if operationFamily(want.Action) == "job" {
			have, e = c.legacyOperation(ctx, tx, want)
			if e != nil {
				return result, e
			}
		}
		if have != nil {
			want.Kind = have.Kind
			want.Target = have.Target
		} else {
			want.Kind, want.Target, e = c.operationTarget(ctx, tx, want.Actor, original)
			if e != nil {
				return result, e
			}
		}
	}
	if !configurationTargetShape(want.Kind, want.Target) {
		return result, enrollment.ErrDenied
	}
	if e = layerACL(ctx, tx, want.Actor, operationACL(want.Action), want.Kind, want.Target, current().Unix()); e != nil {
		return result, e
	}
	mfaUntil := p.MFAUntil(c.AssuranceACR, current())
	if mfaUntil <= current().Unix() {
		return result, errConfigurationReauthentication
	}
	until := min(p.Expires, mfaUntil, now.Unix()+180)
	if have == nil {
		have, e = c.legacyOperation(ctx, tx, want)
		if e != nil {
			return result, e
		}
		if have != nil && (have.Kind != want.Kind || have.Target != want.Target) {
			return result, enrollment.ErrConflict
		}
	}
	if have != nil {
		if have.Backfill && in.Intent == "seal_if_absent" {
			// Existing ordinary lookups do not burn entry quota. An explicit
			// checked import consumes only the separate bounded backfill reserve.
			if existing, err := operationRead(ctx, tx, want.Actor, operationFamily(want.Action), want.Request); err != nil {
				return result, err
			} else if existing == nil {
				at := current()
				if e = operationInsert(ctx, tx, *have, at); e != nil {
					return result, e
				}
				have.RecordedMS = at.UnixMilli()
			}
		}
		result, e = c.operationOutcome(ctx, tx, *have)
		if e != nil {
			return result, e
		}
	} else if original.Version == 2 && in.Intent == "seal_if_absent" {
		want.Disposition = "no_effect"
		want.RecordedMS = current().UnixMilli()
		if e = operationInsert(ctx, tx, want, time.UnixMilli(want.RecordedMS)); e != nil {
			return result, e
		}
		result, e = c.operationOutcome(ctx, tx, want)
		if e != nil {
			return result, e
		}
	} else {
		result = ConfigurationOperationOutcome{Version: 1, Actor: want.Actor, Action: want.Action, RequestID: want.Request, BodyHash: want.Hash, TargetKind: want.Kind, TargetID: want.Target, Outcome: "UNKNOWN"}
	}
	if e = layerACL(ctx, tx, want.Actor, operationACL(want.Action), want.Kind, want.Target, current().Unix()); e != nil {
		return result, e
	}
	if current().Unix() >= until || ctx.Err() != nil {
		return result, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return result, enrollment.ErrUnavailable
	}
	return result, nil
}
