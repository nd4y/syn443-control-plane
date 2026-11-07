package enrollment

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

// Grant is operator-owned immutable input. API has only its hash, never the signing key.
type Grant struct {
	OverlayGroups map[string][]string `json:"overlayGroups,omitempty"`
	Issuer        string              `json:"issuer"`
	Subject       string              `json:"subject"`
	DeviceLimit   int                 `json:"deviceLimit"`
	Until         int64               `json:"until"`
	Template      policy.Payload      `json:"template"`
}

func (g Grant) Hash() string { raw, _ := json.Marshal(g); return identity.Hash(raw) }
func (g Grant) Validate(now time.Time) error {
	if len(g.OverlayGroups) > 16 {
		return identity.ErrInvalid
	}
	for resource, groups := range g.OverlayGroups {
		if !brokerIdentifier.MatchString(resource) || len(groups) < 1 || len(groups) > 16 {
			return identity.ErrInvalid
		}
		seen := map[string]bool{}
		for _, group := range groups {
			if !brokerIdentifier.MatchString(group) || seen[group] {
				return identity.ErrInvalid
			}
			seen[group] = true
		}
	}
	if g.Template.KeyThumbprint != "" || g.Template.Operation != "configure" || (g.Template.SchemaVersion != 1 && g.Template.SchemaVersion != 2) {
		return identity.ErrInvalid
	}
	// These capabilities require the approved per-device configuration.
	// A shared grant cannot bypass rollout selection or exit-check approval.
	if hasCapability(g.Template.RequiredCapabilities, policy.ReserveProbeCooldown) || hasCapability(g.Template.RequiredCapabilities, policy.RouteExitIP) ||
		hasCapability(g.Template.RequiredCapabilities, policy.RouteDecision) {
		return identity.ErrInvalid
	}
	if g.Issuer == "" || g.Subject == "" || g.DeviceLimit < 1 || g.DeviceLimit > 16 || g.Until <= now.Unix() || g.Until > now.Unix()+604800 {
		return identity.ErrInvalid
	}
	p := g.Template
	p.RequiredCapabilities = append([]string(nil), g.Template.RequiredCapabilities...)
	p.SchemaVersion = 2
	p.KeyThumbprint = identity.Hash([]byte("synthetic-validation-key"))
	if !hasCapability(p.RequiredCapabilities, "policy.keybound.v2") {
		p.RequiredCapabilities = append(p.RequiredCapabilities, "policy.keybound.v2")
	}
	p.TargetDevice = "synthetic-device"
	p.Revision = 1
	p.IssuedAtMs = now.UnixMilli()
	p.NotBeforeMs = p.IssuedAtMs
	p.RefreshAfterMs = p.IssuedAtMs + 30000
	p.OfflineUntilMs = min(p.IssuedAtMs+3600000, g.Until*1000)
	return p.Validate(now)
}
func hasCapability(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func Authorize(ctx context.Context, db *sql.DB, grant Grant, now time.Time) error {
	if e := grant.Validate(now); e != nil {
		return e
	}
	_, e := db.ExecContext(ctx, `INSERT INTO identity_accounts(owner,issuer,subject,enabled,device_limit,valid_until,grant_hash) VALUES($1,$2,$3,true,$4,$5,$6) ON CONFLICT(owner) DO UPDATE SET enabled=true,device_limit=excluded.device_limit,valid_until=excluded.valid_until,grant_hash=excluded.grant_hash`, Owner(grant.Issuer, grant.Subject), grant.Issuer, grant.Subject, grant.DeviceLimit, grant.Until, grant.Hash())
	return e
}

type Publisher struct {
	Brokers            *BrokerPolicies
	Store              *Store
	Verifier           Verifier
	Grants             map[string]Grant
	KeyID              string
	Key                *ecdsa.PrivateKey
	Origin             string
	InvitationApproval ExternalApproval
	Configurations     ConfigurationAuthority
}

type ApprovalInput struct {
	Device, Owner, Thumbprint, GrantHash, InvitationID string
	Request                                            []byte
}
type ApprovalFence interface {
	Lock(context.Context, *sql.Tx, time.Time) error
}
type ExternalApproval interface {
	Verify(context.Context, ApprovalInput, time.Time) (ApprovalFence, error)
}
type snapshot struct {
	Device, Owner, Jkt, Grant string
	Raw, Receipt              []byte
	Approved                  bool
	Revision                  int64
}

func (p *Publisher) RunOnce(ctx context.Context, now time.Time) error {
	if e := p.Store.RuntimeRole(ctx, true); e != nil {
		return e
	}
	capabilityContext, capabilityCancel := context.WithTimeout(ctx, 3*time.Second)
	capabilityError := p.ApproveCapabilitiesOnce(capabilityContext, now)
	capabilityCancel()
	rows, e := p.Store.DB.QueryContext(ctx, `SELECT id,revision FROM identity_devices WHERE active AND retry_after<=$1 AND (NOT approved OR refresh_after<=$1) ORDER BY refresh_after,id LIMIT 16`, now.Unix())
	if e != nil {
		return e
	}
	type work struct {
		id       string
		revision int64
	}
	var ids []work
	for rows.Next() {
		var id work
		if e = rows.Scan(&id.id, &id.revision); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = p.publish(ctx, id.id, now); e != nil {
			code := "temporarily_unavailable"
			if errors.Is(e, identity.ErrInvalid) {
				code = "reauthentication_required"
			} else if errors.Is(e, ErrConfigurationUnassigned) {
				code = "configuration_pending"
			}
			// Retry is per device; existing permitted publication is retained.
			if _, e = p.Store.DB.ExecContext(ctx, `UPDATE identity_devices SET publication_error=$2,retry_after=$3 WHERE id=$1 AND revision=$4 AND active`, id.id, code, now.Unix()+30, id.revision); e != nil {
				return e
			}
		}
	}
	if capabilityError != nil && !errors.Is(capabilityError, ErrDenied) && !errors.Is(capabilityError, ErrConflict) && !errors.Is(capabilityError, identity.ErrInvalid) {
		return capabilityError
	}
	return nil
}
func (p *Publisher) publish(ctx context.Context, id string, now time.Time) error {
	started := time.Now()
	var s snapshot
	s.Device = id
	var active, enabled bool
	var until int64
	e := p.Store.DB.QueryRowContext(ctx, `SELECT d.owner,d.jkt,d.request_body,d.receipt,d.approved,d.revision,d.active,a.grant_hash,a.enabled,a.valid_until FROM identity_devices d JOIN identity_accounts a ON a.owner=d.owner WHERE d.id=$1`, id).Scan(&s.Owner, &s.Jkt, &s.Raw, &s.Receipt, &s.Approved, &s.Revision, &active, &s.Grant, &enabled, &until)
	if e != nil {
		return e
	}
	g, exists := p.Grants[s.Owner]
	if !exists || !active || !enabled || until <= now.Unix() || g.Hash() != s.Grant || g.Validate(now) != nil {
		return ErrDenied
	}
	var request Request
	if identity.Decode(s.Raw, &request, true) != nil {
		return identity.ErrInvalid
	}
	thumb, e := request.Key.Thumbprint()
	if e != nil || thumb != s.Jkt {
		return identity.ErrInvalid
	}
	var approvalFence ApprovalFence
	var admissionUntil int64
	if !s.Approved {
		raw, e := p.Store.Open(s.Receipt, "receipt/v1/"+id)
		if e != nil {
			return e
		}
		var receipt Receipt
		if identity.Decode(raw, &receipt, true) != nil {
			return identity.ErrInvalid
		}
		admissionUntil = receipt.AcceptedAt + 180
		switch receipt.Kind {
		case "invite-v1":
			if p.InvitationApproval == nil || !idPattern.MatchString(receipt.InvitationID) {
				return identity.ErrInvalid
			}
			approvalFence, e = p.InvitationApproval.Verify(ctx, ApprovalInput{Device: id, Owner: s.Owner, Thumbprint: s.Jkt, GrantHash: s.Grant, InvitationID: receipt.InvitationID, Request: append([]byte(nil), s.Raw...)}, now)
			if e != nil || approvalFence == nil {
				return identity.ErrInvalid
			}
		case "":
			if receipt.InvitationID != "" || receipt.URI != p.Origin+"/v1/devices/enroll" || receipt.AcceptedAt > now.Unix() || receipt.AcceptedAt < now.Unix()-180 {
				return identity.ErrInvalid
			}
			principal, e := p.Verifier.Verify(ctx, receipt.Token, now)
			if e != nil {
				return identity.ErrInvalid
			}
			admissionUntil = min(admissionUntil, principal.Expires)
			proof, e := identity.RequestProof(receipt.Proof, identity.ProofContext{Method: "POST", URI: receipt.URI, Token: receipt.Token, BodyHash: identity.Hash(s.Raw), Now: now})
			if e != nil || proof.Claims.Nonce == "" || proof.Thumbprint != s.Jkt || principal.Thumbprint != s.Jkt || principal.Issuer != g.Issuer || principal.Subject != g.Subject {
				return identity.ErrInvalid
			}
		default:
			return identity.ErrInvalid
		}
	}
	if s.Approved {
		available, e := EffectiveCapabilities(ctx, p.Store.DB, id, request.Capabilities)
		if e != nil {
			return e
		}
		request.Capabilities = available.Capabilities
	}
	caps := map[string]bool{}
	for _, v := range request.Capabilities {
		caps[v] = true
	}
	for _, v := range g.Template.RequiredCapabilities {
		if !caps[v] {
			return ErrDenied
		}
	}
	if !caps["policy.keybound.v2"] {
		return ErrDenied
	}
	payload := g.Template
	payload.RequiredCapabilities = append([]string(nil), g.Template.RequiredCapabilities...)
	payload.SchemaVersion = 2
	payload.KeyThumbprint = s.Jkt
	if !hasCapability(payload.RequiredCapabilities, "policy.keybound.v2") {
		payload.RequiredCapabilities = append(payload.RequiredCapabilities, "policy.keybound.v2")
	}
	payload.TargetDevice = id
	payload.Revision = s.Revision + 1
	payload.IssuedAtMs = now.UnixMilli()
	payload.NotBeforeMs = payload.IssuedAtMs
	payload.OfflineUntilMs = min(payload.IssuedAtMs+3600000, g.Until*1000)
	payload.RefreshAfterMs = min(payload.IssuedAtMs+300000, payload.OfflineUntilMs-1000)
	var configurationFence ApprovalFence
	var configurationSource ConfigurationSource
	if p.Configurations != nil {
		prepared, prepareErr := p.Configurations.Prepare(ctx, ConfigurationTarget{Device: id, Owner: s.Owner, Thumbprint: s.Jkt, GrantHash: s.Grant, CurrentRevision: s.Revision, Capabilities: append([]string(nil), request.Capabilities...)}, now)
		if prepareErr != nil {
			if !s.Approved && errors.Is(prepareErr, ErrConfigurationUnassigned) {
				return p.admitIdentity(ctx, s, g, approvalFence, admissionUntil, now.Add(time.Since(started)))
			}
			return prepareErr
		}
		if prepared != nil && hasCapability(prepared.RequiredCapabilities, "overlay.credentials.v1") && p.Brokers == nil {
			return ErrDenied
		}
		if err := applyPreparedConfiguration(&payload, prepared, request.Capabilities, now); err != nil {
			return err
		}
		configurationFence = prepared.Fence
		configurationSource = prepared.Source
	}
	var brokerFence ApprovalFence
	if p.Brokers != nil {
		brokerFence, e = p.Brokers.Prepare(ctx, ConfigurationTarget{Device: id, Owner: s.Owner, Thumbprint: s.Jkt, GrantHash: s.Grant, CurrentRevision: s.Revision, Capabilities: request.Capabilities}, g, &payload, now)
		if e != nil {
			return e
		}
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	bundle, e := policy.Sign(raw, p.KeyID, p.Key, id, payload.Revision, now)
	if e != nil {
		return e
	}
	tx, e := p.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := lockAccount(ctx, tx, s.Owner, now.Unix())
	if e != nil {
		return e
	}
	if a.Grant != s.Grant {
		return ErrConflict
	}
	if approvalFence != nil {
		if e = approvalFence.Lock(ctx, tx, now); e != nil {
			return e
		}
	}
	if configurationFence != nil {
		if e = configurationFence.Lock(ctx, tx, now); e != nil {
			return e
		}
	}
	var current int64
	var owner, jkt string
	var body []byte
	e = tx.QueryRowContext(ctx, `SELECT revision,owner,jkt,request_body,active FROM identity_devices WHERE id=$1 FOR UPDATE`, id).Scan(&current, &owner, &jkt, &body, &active)
	if e != nil {
		return e
	}
	if !active || current != s.Revision || owner != s.Owner || jkt != s.Jkt || identity.Hash(body) != identity.Hash(s.Raw) {
		return ErrConflict
	}
	if brokerFence != nil {
		if e = brokerFence.Lock(ctx, tx, now); e != nil {
			return e
		}
	}
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE owner=$1 AND active`, s.Owner).Scan(&count); e != nil {
		return e
	}
	if count > g.DeviceLimit {
		return ErrDenied
	}
	// Network/key work and row-lock waits cannot extend the original permit or
	// the fresh administrator approval. Repeat the final fence at commit time.
	commitNow := now.Add(time.Since(started))
	if a.Until <= commitNow.Unix() || payload.OfflineUntilMs <= commitNow.UnixMilli() {
		return ErrDenied
	}
	if approvalFence != nil {
		if e = approvalFence.Lock(ctx, tx, commitNow); e != nil {
			return e
		}
	}
	if configurationFence != nil {
		if payload.OfflineUntilMs <= commitNow.UnixMilli() {
			return ErrDenied
		}
		if e = configurationFence.Lock(ctx, tx, commitNow); e != nil {
			return e
		}
	}
	if brokerFence != nil {
		if e = brokerFence.Lock(ctx, tx, commitNow); e != nil {
			return e
		}
	}
	encrypted := p.Store.Seal([]byte(bundle), "publication/v1/"+id+"/"+formatInt(payload.Revision))
	var sourcePolicyRevision int64
	if configurationSource.Revision > 0 {
		sourcePolicyRevision = payload.Revision
	}
	_, e = tx.ExecContext(ctx, `UPDATE identity_devices SET approved=true,publication=$2,revision=$3,refresh_after=$4,offline_until=$5,publication_error='',retry_after=0,publication_grant_hash=$6,publication_source_policy_revision=$7,publication_source_revision=$8,publication_source_hash=$9 WHERE id=$1`,
		id, encrypted, payload.Revision, payload.RefreshAfterMs/1000, payload.OfflineUntilMs/1000, s.Grant,
		sourcePolicyRevision, configurationSource.Revision, configurationSource.Hash)
	if e != nil {
		return e
	}
	return tx.Commit()
}
