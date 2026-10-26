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
	Issuer      string         `json:"issuer"`
	Subject     string         `json:"subject"`
	DeviceLimit int            `json:"deviceLimit"`
	Until       int64          `json:"until"`
	Template    policy.Payload `json:"template"`
}

func (g Grant) Hash() string { raw, _ := json.Marshal(g); return identity.Hash(raw) }
func (g Grant) Validate(now time.Time) error {
	if g.Template.KeyThumbprint != "" || g.Template.Operation != "configure" || (g.Template.SchemaVersion != 1 && g.Template.SchemaVersion != 2) {
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
	Store    *Store
	Verifier Verifier
	Grants   map[string]Grant
	KeyID    string
	Key      *ecdsa.PrivateKey
	Origin   string
}
type snapshot struct {
	Device, Owner, Jkt, Grant string
	Raw, Receipt              []byte
	Approved                  bool
	Revision                  int64
}

func (p *Publisher) RunOnce(ctx context.Context, now time.Time) error {
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
			}
			// Retry is per device; existing permitted publication is retained.
			if _, e = p.Store.DB.ExecContext(ctx, `UPDATE identity_devices SET publication_error=$2,retry_after=$3 WHERE id=$1 AND revision=$4 AND active`, id.id, code, now.Unix()+30, id.revision); e != nil {
				return e
			}
		}
	}
	return nil
}
func (p *Publisher) publish(ctx context.Context, id string, now time.Time) error {
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
	if !s.Approved {
		raw, e := p.Store.Open(s.Receipt, "receipt/v1/"+id)
		if e != nil {
			return e
		}
		var receipt Receipt
		if identity.Decode(raw, &receipt, true) != nil || receipt.URI != p.Origin+"/v1/devices/enroll" || receipt.AcceptedAt > now.Unix() || receipt.AcceptedAt < now.Unix()-180 {
			return identity.ErrInvalid
		}
		principal, e := p.Verifier.Verify(ctx, receipt.Token, now)
		if e != nil {
			return identity.ErrInvalid
		}
		proof, e := identity.RequestProof(receipt.Proof, identity.ProofContext{Method: "POST", URI: receipt.URI, Token: receipt.Token, BodyHash: identity.Hash(s.Raw), Now: now})
		if e != nil || proof.Claims.Nonce == "" || proof.Thumbprint != s.Jkt || principal.Thumbprint != s.Jkt || principal.Issuer != g.Issuer || principal.Subject != g.Subject {
			return identity.ErrInvalid
		}
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
	payload.RefreshAfterMs = min(payload.IssuedAtMs+1800000, payload.OfflineUntilMs-1000)
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
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_devices WHERE owner=$1 AND active`, s.Owner).Scan(&count); e != nil {
		return e
	}
	if count > g.DeviceLimit {
		return ErrDenied
	}
	encrypted := p.Store.Seal([]byte(bundle), "publication/v1/"+id+"/"+formatInt(payload.Revision))
	_, e = tx.ExecContext(ctx, `UPDATE identity_devices SET approved=true,publication=$2,revision=$3,refresh_after=$4,offline_until=$5,publication_error='',retry_after=0 WHERE id=$1`, id, encrypted, payload.Revision, payload.RefreshAfterMs/1000, payload.OfflineUntilMs/1000)
	if e != nil {
		return e
	}
	return tx.Commit()
}
