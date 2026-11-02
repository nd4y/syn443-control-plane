package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

var configurationObjectID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var configurationRequestID = regexp.MustCompile(`^[A-Za-z0-9_-]{24,128}$`)
var configurationBodyHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validateProposalShape(ctx context.Context, p LayerProposal, now time.Time) error {
	if !configurationObjectID.MatchString(p.DraftID) || p.DraftRevision < 1 || p.DraftRevision > 9007199254740991 || p.ApprovalUntilMs <= now.UnixMilli() || p.ApprovalUntilMs-now.UnixMilli() > 366*24*time.Hour.Milliseconds() {
		return enrollment.ErrDenied
	}
	for _, b := range p.Bundles {
		if !configurationObjectID.MatchString(b.Device) || b.BaseRevision < 0 || b.BaseRevision > 9007199254740991 || b.BaseRevision == 0 && b.BaseHash != "" || b.BaseRevision > 0 && !configurationBodyHash.MatchString(b.BaseHash) {
			return enrollment.ErrDenied
		}
	}
	_, e := effectiveProposalHash(ctx, p)
	return e
}

// Original signed administrative input is independently reverified by the
// publisher. Larger portable proposals use the bounded configuration decoder;
// this does not widen the invitation or ordinary identity wire protocol.
func verifyConfigurationReceipt(ctx context.Context, verifier invitation.Verifier, receipt invitation.Receipt, origin, acr string, now time.Time) (string, invitation.Envelope, int64, error) {
	var envelope invitation.Envelope
	if ctx == nil || verifier == nil || len(receipt.Body) > 262144 || receipt.URI != origin+"/v1/control/action" || receipt.AcceptedAt > now.Unix() || receipt.AcceptedAt < now.Unix()-180 || len(receipt.Token) < 24 || len(receipt.Token) > 16384 || identity.DecodeConfiguration(receipt.Body, &envelope) != nil || envelope.Version != 1 || !configurationRequestID.MatchString(envelope.RequestID) {
		return "", envelope, 0, enrollment.ErrDenied
	}
	switch envelope.Action {
	case "configuration.preview.request", "configuration.publish", "configuration.request.get":
	default:
		return "", envelope, 0, enrollment.ErrDenied
	}
	p, e := verifier.Verify(ctx, receipt.Token, now)
	if e != nil || !p.HasScope("syn443.control") || p.Expires <= now.Unix() || p.MFAUntil(acr, now) <= now.Unix() {
		return "", envelope, 0, enrollment.ErrDenied
	}
	proof, e := identity.VerifyProof(receipt.Proof, identity.ProofContext{Method: "POST", URI: receipt.URI, Token: receipt.Token, BodyHash: identity.Hash(receipt.Body), Now: time.Unix(receipt.AcceptedAt, 0)})
	if e != nil || proof.Thumbprint != p.Thumbprint {
		return "", envelope, 0, enrollment.ErrDenied
	}
	return identity.Hash([]byte(p.Issuer + "\x00" + p.Subject)), envelope, min(p.Expires, p.MFAUntil(acr, now), receipt.AcceptedAt+180), nil
}

type ConfigurationRequestView struct {
	ID     string          `json:"id"`
	State  string          `json:"state"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

func (ConfigurationRequestView) String() string   { return "ConfigurationRequest([redacted])" }
func (ConfigurationRequestView) GoString() string { return "ConfigurationRequest([redacted])" }

// ConfigurationControl queues original receipts only. It has no signing key or
// head mutation method. A response describes queue state, never VPN activation.
type ConfigurationControl struct {
	Store                *enrollment.Store
	Verifier             invitation.Verifier
	Origin, AssuranceACR string
}

func (*ConfigurationControl) String() string   { return "ConfigurationControl([redacted])" }
func (*ConfigurationControl) GoString() string { return "ConfigurationControl([redacted])" }

// Adapter for the catalog HTTP boundary. Internal receipt/SQL details never
// become response text, and no unknown action gains a generic callback route.
func (c *ConfigurationControl) ControlAction(ctx context.Context, token, proof string, raw []byte, now time.Time) (any, error) {
	v, e := c.Dispatch(ctx, token, proof, raw, now)
	switch {
	case e == nil:
		return v, nil
	case errors.Is(e, enrollment.ErrDenied):
		return nil, catalog.ErrDenied
	case errors.Is(e, enrollment.ErrConflict):
		return nil, catalog.ErrConflict
	default:
		return nil, catalog.ErrUnavailable
	}
}

type configurationPublishInput struct {
	PreviewID string `json:"previewId"`
	Ticket    string `json:"ticket"`
}
type configurationPreviewInput struct {
	Proposal LayerProposal `json:"proposal"`
}

func configurationRequestAAD(id string) string { return "configuration-request/v1/" + id }

func (c *ConfigurationControl) Dispatch(ctx context.Context, token, proof string, raw []byte, now time.Time) (any, error) {
	if c == nil || c.Store == nil {
		return nil, enrollment.ErrDenied
	}
	if e := ConfigurationRuntimeRole(ctx, c.Store.DB, false); e != nil {
		return nil, e
	}
	receipt := invitation.Receipt{Token: token, Proof: proof, URI: c.Origin + "/v1/control/action", Body: append([]byte(nil), raw...), AcceptedAt: now.Unix()}
	actor, envelope, authorityUntil, e := verifyConfigurationReceipt(ctx, c.Verifier, receipt, c.Origin, c.AssuranceACR, now)
	if e != nil {
		return nil, e
	}
	if envelope.Action == "configuration.request.get" {
		var input struct {
			ID string `json:"id"`
		}
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil || !configurationRequestID.MatchString(input.ID) {
			return nil, enrollment.ErrDenied
		}
		return c.get(ctx, actor, input.ID, authorityUntil, now)
	}
	kind, id := "", ""
	if envelope.Action == "configuration.preview.request" {
		var input configurationPreviewInput
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil {
			return nil, enrollment.ErrDenied
		}
		if e = validateProposalShape(ctx, input.Proposal, now); e != nil {
			return nil, e
		}
		kind, id = input.Proposal.TargetKind, input.Proposal.TargetID
	} else {
		var input configurationPublishInput
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil || !configurationRequestID.MatchString(input.PreviewID) || len(input.Ticket) > 90000 {
			return nil, enrollment.ErrDenied
		}
		var protected []byte
		var ticket string
		if e = c.Store.DB.QueryRowContext(ctx, `SELECT body,ticket FROM managed_configuration_previews WHERE id=$1 AND actor=$2`, input.PreviewID, actor).Scan(&protected, &ticket); e != nil || input.Ticket != ticket {
			return nil, enrollment.ErrDenied
		}
		body, e := c.Store.Open(protected, layerProposalAAD(input.PreviewID))
		var proposal LayerProposal
		if e != nil || identity.DecodeConfiguration(body, &proposal) != nil {
			return nil, enrollment.ErrUnavailable
		}
		kind, id = proposal.TargetKind, proposal.TargetID
	}
	switch kind {
	case "template", "group", "user", "device":
	default:
		return nil, enrollment.ErrDenied
	}
	if !configurationObjectID.MatchString(id) {
		return nil, enrollment.ErrDenied
	}
	return c.queue(ctx, actor, kind, id, envelope, receipt, authorityUntil, now)
}

func (c *ConfigurationControl) queue(ctx context.Context, actor, kind, target string, envelope invitation.Envelope, receipt invitation.Receipt, authorityUntil int64, now time.Time) (ConfigurationRequestView, error) {
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	result := ConfigurationRequestView{ID: identity.Hash([]byte(actor + "\x00" + envelope.RequestID))}
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return result, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	action := "configuration.preview"
	if envelope.Action == "configuration.publish" {
		action = "configuration.publish"
	}
	if e = layerACL(ctx, tx, actor, action, kind, target, current().Unix()); e != nil {
		return result, e
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "configuration-requests/"+actor); e != nil {
		return result, enrollment.ErrUnavailable
	}
	hash := configurationHash(receipt.Body)
	var previous string
	var priorResult []byte
	e = tx.QueryRowContext(ctx, `SELECT body_hash,state,error_code,result FROM managed_configuration_requests WHERE id=$1 AND actor=$2`, result.ID, actor).Scan(&previous, &result.State, &result.Error, &priorResult)
	if e == nil {
		result.Result = append(json.RawMessage(nil), priorResult...)
		if previous != hash {
			return result, enrollment.ErrConflict
		}
		if current().Unix() >= authorityUntil {
			return result, enrollment.ErrDenied
		}
		if e = layerACL(ctx, tx, actor, action, kind, target, current().Unix()); e != nil {
			return result, e
		}
		if current().Unix() >= authorityUntil {
			return result, enrollment.ErrDenied
		}
		if e = tx.Commit(); e != nil {
			return result, enrollment.ErrUnavailable
		}
		return result, nil
	}
	if e != sql.ErrNoRows {
		return result, enrollment.ErrUnavailable
	}
	var total, pending int
	if e = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state IN('queued','running')) FROM managed_configuration_requests WHERE actor=$1`, actor).Scan(&total, &pending); e != nil {
		return result, enrollment.ErrUnavailable
	}
	if total >= 256 || pending >= 64 {
		return result, enrollment.ErrDenied
	}
	protected, e := json.Marshal(receipt)
	if e != nil || len(protected) > 524288 {
		return result, enrollment.ErrDenied
	}
	deadline := time.Unix(receipt.AcceptedAt+180, 0).UnixMilli()
	if current().UnixMilli() >= deadline || current().Unix() >= authorityUntil {
		return result, enrollment.ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO managed_configuration_requests(id,actor,request_id,action,target_kind,target_id,created_ms,deadline_ms,body_hash,receipt) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, result.ID, actor, envelope.RequestID, envelope.Action, kind, target, now.UnixMilli(), deadline, hash, c.Store.Seal(protected, configurationRequestAAD(result.ID))); e != nil {
		return result, enrollment.ErrUnavailable
	}
	if e = layerACL(ctx, tx, actor, action, kind, target, current().Unix()); e != nil {
		return result, e
	}
	if current().Unix() >= authorityUntil {
		return result, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return result, enrollment.ErrUnavailable
	}
	result.State = "queued"
	return result, nil
}

func (c *ConfigurationControl) get(ctx context.Context, actor, id string, authorityUntil int64, now time.Time) (ConfigurationRequestView, error) {
	started := time.Now()
	tx, e := c.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return ConfigurationRequestView{}, enrollment.ErrUnavailable
	}
	defer tx.Rollback()
	r := ConfigurationRequestView{ID: id}
	var kind, target string
	var rawResult []byte
	if e = tx.QueryRowContext(ctx, `SELECT target_kind,target_id,state,error_code,result FROM managed_configuration_requests WHERE id=$1 AND actor=$2`, id, actor).Scan(&kind, &target, &r.State, &r.Error, &rawResult); e != nil {
		return r, enrollment.ErrDenied
	}
	r.Result = append(json.RawMessage(nil), rawResult...)
	if e = layerACL(ctx, tx, actor, "configuration.requests.read", kind, target, now.Add(time.Since(started)).Unix()); e != nil {
		return r, e
	}
	if now.Add(time.Since(started)).Unix() >= authorityUntil {
		return r, enrollment.ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return r, enrollment.ErrUnavailable
	}
	return r, nil
}
