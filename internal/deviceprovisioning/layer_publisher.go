package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

// ConfigurationPublisher is an independent consumer of original administrative
// receipts. The API cannot supply a compiled profile or an approval result.
// Publication advances desired configuration heads; it is not a device ACK.
type ConfigurationPublisher struct {
	Store                       *enrollment.Store
	Sources                     *catalog.Store
	Verifier                    invitation.Verifier
	Origin, AssuranceACR, KeyID string
	Key                         *ecdsa.PrivateKey
	Roots                       map[string]*ecdsa.PublicKey
}

func (*ConfigurationPublisher) String() string   { return "ConfigurationPublisher([redacted])" }
func (*ConfigurationPublisher) GoString() string { return "ConfigurationPublisher([redacted])" }

type proposedNetworkLayers struct{ snapshot *configurationLayerSnapshot }

func (p proposedNetworkLayers) PrepareLayers(ctx context.Context, target enrollment.ConfigurationTarget, now time.Time) (*ApprovedNetworkLayers, error) {
	if ctx == nil || p.snapshot == nil {
		return nil, enrollment.ErrDenied
	}
	for i, t := range p.snapshot.Targets {
		if sameNetworkTarget(t, target) {
			return &ApprovedNetworkLayers{Target: t, Layers: p.snapshot.proposal.Bundles[i].Layers,
				Mode: p.snapshot.proposal.Mode, UntilMs: min(p.snapshot.proposal.ApprovalUntilMs, now.Add(7*24*time.Hour).UnixMilli()), Fence: p.snapshot}, nil
		}
	}
	return nil, enrollment.ErrDenied
}

type compiledLayerProposal struct {
	snapshot                                 *configurationLayerSnapshot
	fences                                   []*networkFence
	dependencyHash, effectiveHash, draftHash string
	until                                    int64
}

func (p *ConfigurationPublisher) compile(ctx context.Context, actor, action string, proposal LayerProposal, now time.Time) (*compiledLayerProposal, error) {
	snapshot, e := prepareConfigurationLayers(ctx, p.Store, actor, action, proposal, now)
	if e != nil {
		return nil, e
	}
	proposal = snapshot.proposal
	authority := NetworkAuthority{Layers: proposedNetworkLayers{snapshot}, Sources: p.Sources}
	type dependency struct {
		Device, EngineHash, ActivationHash string
		Capabilities                       []string
		Sources                            []catalog.SelectionDependency
	}
	dependencies := []dependency{}
	c := &compiledLayerProposal{snapshot: snapshot, until: proposal.ApprovalUntilMs}
	for _, target := range snapshot.Targets {
		prepared, e := authority.Prepare(ctx, target, now)
		if e != nil {
			return nil, e
		}
		for _, capability := range prepared.RequiredCapabilities {
			if !slices.Contains(target.Capabilities, capability) {
				return nil, enrollment.ErrDenied
			}
		}
		f, ok := prepared.Fence.(*networkFence)
		if !ok || f == nil {
			return nil, enrollment.ErrDenied
		}
		activation, e := json.Marshal(prepared.Activation)
		if e != nil {
			return nil, enrollment.ErrDenied
		}
		d := dependency{Device: target.Device, EngineHash: configurationHash(prepared.EngineConfig), ActivationHash: configurationHash(activation), Capabilities: prepared.RequiredCapabilities, Sources: []catalog.SelectionDependency{}}
		if f.sources != nil {
			d.Sources = f.sources.Dependencies()
		}
		dependencies = append(dependencies, d)
		c.fences = append(c.fences, f)
		c.until = min(c.until, prepared.UntilMs)
	}
	raw, e := json.Marshal(struct {
		Layers       string
		Dependencies []dependency
	}{snapshot.Hash, dependencies})
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	c.dependencyHash = configurationHash(raw)
	c.effectiveHash, e = effectiveProposalHash(ctx, proposal)
	if e != nil {
		return nil, e
	}
	raw, e = json.Marshal(proposal)
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	c.draftHash = configurationHash(raw)
	return c, nil
}

// Repeat actual recipient/layer authority once, then each immutable source
// fence. These locks remain held through every affected head and queue receipt.
func (c *compiledLayerProposal) lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if now.UnixMilli() >= c.until {
		return enrollment.ErrDenied
	}
	if e := c.snapshot.Lock(ctx, tx, now); e != nil {
		return e
	}
	for _, f := range c.fences {
		if now.UnixMilli() >= f.untilMs {
			return enrollment.ErrDenied
		}
		if f.sources != nil {
			if e := f.sources.Lock(ctx, tx, now); e != nil {
				return e
			}
		}
	}
	return nil
}

type ConfigurationPreviewResult struct {
	PreviewID string                `json:"previewId"`
	Ticket    string                `json:"ticket"`
	Preview   configuration.Preview `json:"preview"`
}

func (ConfigurationPreviewResult) String() string   { return "ConfigurationPreviewResult([redacted])" }
func (ConfigurationPreviewResult) GoString() string { return "ConfigurationPreviewResult([redacted])" }

func (p *ConfigurationPublisher) RunOnce(ctx context.Context, now time.Time) error {
	if ctx == nil || now.IsZero() || p == nil || p.Store == nil || p.Sources == nil || p.Verifier == nil || p.Key == nil || p.KeyID == "" {
		return enrollment.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	started := time.Now()
	current := func() time.Time { return now.Add(time.Since(started)) }
	s := &configurationWorkStore{Store: p.Store, Verifier: p.Verifier, Origin: p.Origin, AssuranceACR: p.AssuranceACR}
	w, e := s.claim(ctx, current())
	if e != nil || w.id == "" {
		return e
	}
	e = p.process(ctx, s, w, current)
	// Deterministic denial/conflict is terminal. Transient failure/cancellation
	// retains the bounded lease/retry path; neither path produces approval.
	if errors.Is(e, enrollment.ErrDenied) || errors.Is(e, enrollment.ErrConflict) || errors.Is(e, configuration.ErrInvalid) || errors.Is(e, catalog.ErrDenied) || errors.Is(e, catalog.ErrInvalid) || errors.Is(e, catalog.ErrConflict) || errors.Is(e, catalog.ErrStale) || errors.Is(e, catalog.ErrQuota) {
		code := "configuration_denied"
		if errors.Is(e, enrollment.ErrConflict) || errors.Is(e, catalog.ErrConflict) || errors.Is(e, catalog.ErrStale) {
			code = "configuration_conflict"
		}
		if rejected := s.reject(ctx, w, current(), code); rejected != nil {
			return rejected
		}
	}
	return e
}

func (p *ConfigurationPublisher) process(ctx context.Context, s *configurationWorkStore, w configurationWork, current func() time.Time) error {
	envelope, authorityUntil, e := s.verify(ctx, w, current())
	if e != nil {
		return e
	}
	if envelope.Action == "configuration.preview.request" {
		var input configurationPreviewInput
		if identity.DecodeConfiguration(envelope.Payload, &input) != nil {
			return enrollment.ErrDenied
		}
		c, e := p.compile(ctx, w.actor, "configuration.preview", input.Proposal, current())
		if e != nil {
			return e
		}
		now := current()
		proposal := c.snapshot.proposal
		preview := configuration.Preview{SchemaVersion: 1, Origin: p.Origin, Actor: w.actor, RequestID: w.request,
			DraftID: proposal.DraftID, DraftRevision: proposal.DraftRevision, DraftHash: c.draftHash, TargetKind: proposal.TargetKind, TargetID: proposal.TargetID, Mode: proposal.Mode,
			DependencyHash: c.dependencyHash, EffectiveHash: c.effectiveHash, Recipients: c.snapshot.Recipients,
			IssuedAtMs: now.UnixMilli(), ExpiresAtMs: min(now.Add(180*time.Second).UnixMilli(), authorityUntil*1000, w.deadline, c.until)}
		ticket, e := configuration.SignPreview(ctx, preview, p.KeyID, p.Key, now)
		if e != nil {
			return enrollment.ErrDenied
		}
		// The configured public history must authenticate our output too. A key
		// rotation misconfiguration cannot create unreadable active artifacts.
		if _, e = configuration.VerifyPreview(ctx, ticket, p.Roots, p.Origin, w.actor, now); e != nil {
			return enrollment.ErrDenied
		}
		raw, e := json.Marshal(proposal)
		if e != nil {
			return enrollment.ErrDenied
		}
		protected := p.Store.Seal(raw, layerProposalAAD(w.id))
		return s.commitGuarded(ctx, w, current(), preview.ExpiresAtMs, func(ctx context.Context, tx *sql.Tx, at time.Time, _ invitation.Envelope) (json.RawMessage, error) {
			if e := c.lock(ctx, tx, at); e != nil {
				return nil, e
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO managed_configuration_previews(id,actor,request_id,body_hash,body,ticket,issued_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, w.id, w.actor, w.request, c.draftHash, protected, ticket, preview.IssuedAtMs, preview.ExpiresAtMs); e != nil {
				return nil, enrollment.ErrUnavailable
			}
			return json.Marshal(ConfigurationPreviewResult{w.id, ticket, preview})
		})
	}
	var input configurationPublishInput
	if identity.DecodeConfiguration(envelope.Payload, &input) != nil || !configurationRequestID.MatchString(input.PreviewID) || len(input.Ticket) > 90000 {
		return enrollment.ErrDenied
	}
	var body []byte
	var ticket, hash string
	var issued, expires int64
	if e = p.Store.DB.QueryRowContext(ctx, `SELECT body,ticket,body_hash,issued_at_ms,expires_at_ms FROM managed_configuration_previews WHERE id=$1 AND actor=$2`, input.PreviewID, w.actor).Scan(&body, &ticket, &hash, &issued, &expires); e != nil || input.Ticket != ticket {
		return enrollment.ErrDenied
	}
	preview, e := configuration.VerifyPreview(ctx, ticket, p.Roots, p.Origin, w.actor, current())
	if e != nil || preview.IssuedAtMs != issued || preview.ExpiresAtMs != expires || preview.DraftHash != hash {
		return enrollment.ErrDenied
	}
	raw, e := p.Store.Open(body, layerProposalAAD(input.PreviewID))
	var proposal LayerProposal
	if e != nil || configurationHash(raw) != hash || identity.DecodeConfiguration(raw, &proposal) != nil || proposal.TargetKind != w.kind || proposal.TargetID != w.target {
		return enrollment.ErrDenied
	}
	c, e := p.compile(ctx, w.actor, "configuration.publish", proposal, current())
	if e != nil {
		return e
	}
	if c.draftHash != preview.DraftHash || c.effectiveHash != preview.EffectiveHash || c.dependencyHash != preview.DependencyHash || proposal.DraftID != preview.DraftID || proposal.DraftRevision != preview.DraftRevision || proposal.Mode != preview.Mode || proposal.TargetKind != preview.TargetKind || proposal.TargetID != preview.TargetID || !slices.Equal(c.snapshot.Recipients, preview.Recipients) {
		return enrollment.ErrConflict
	}
	return s.commitGuarded(ctx, w, current(), min(expires, c.until), func(ctx context.Context, tx *sql.Tx, at time.Time, _ invitation.Envelope) (json.RawMessage, error) {
		if e := c.lock(ctx, tx, at); e != nil {
			return nil, e
		}
		return c.snapshot.publish(ctx, tx, w, input.PreviewID, hash, at)
	})
}
