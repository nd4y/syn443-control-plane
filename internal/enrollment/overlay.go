package enrollment

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

// ManagedOverlayReference appears only inside an independently signed engine
// configuration. It contains no setup key or imported SDK state path.
type ManagedOverlayReference struct {
	OverlayID      string `json:"overlayId"`
	ResourceID     string `json:"resourceId"`
	NetworkID      string `json:"networkId"`
	IdentityEpoch  int64  `json:"identityEpoch"`
	SetupReference string `json:"setupReference"`
	SetupVersion   int64  `json:"setupVersion"`
}

func (ManagedOverlayReference) String() string   { return "ManagedOverlayReference([redacted])" }
func (ManagedOverlayReference) GoString() string { return "ManagedOverlayReference([redacted])" }

type OverlayRequest struct {
	OperationID string `json:"operationId"`
	Namespace   string `json:"namespace"`
	Reference   string `json:"reference"`
	Version     int64  `json:"version"`
}

func (OverlayRequest) String() string   { return "OverlayRequest([redacted])" }
func (OverlayRequest) GoString() string { return "OverlayRequest([redacted])" }

type OverlayReply struct {
	Envelope string `json:"envelope,omitempty"`
	Consumed bool   `json:"consumed"`
}

func (OverlayReply) String() string   { return "OverlayReply([redacted])" }
func (OverlayReply) GoString() string { return "OverlayReply([redacted])" }

func overlayDigest(raw string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == raw
}
func overlayOwner(service, issuer, subject string) string {
	raw, _ := json.Marshal(map[string]string{"service": service, "issuer": issuer, "subject": subject})
	raw, _ = policy.Canonical(raw)
	return identity.Hash(raw)
}

// Only the current approved, key-bound policy authorizes delivery. SQL ready
// flags or request-supplied identity fields are never enough.
func (s *Store) overlayPermission(ctx context.Context, tx *sql.Tx, a DeviceAuthority, service string, roots map[string]*ecdsa.PublicKey, r OverlayRequest, cleanup bool, now time.Time) (overlay.CredentialBinding, error) {
	var b overlay.CredentialBinding
	var raw []byte
	var revision int64
	var approved bool
	var grantHash string
	e := tx.QueryRowContext(ctx, `SELECT publication,revision,approved,publication_grant_hash FROM identity_devices WHERE id=$1`, a.Binding.Device).Scan(&raw, &revision, &approved, &grantHash)
	if e != nil {
		return b, e
	}
	if !approved || raw == nil || grantHash != a.GrantHash {
		return b, ErrDenied
	}
	raw, e = s.Open(raw, "publication/v1/"+a.Binding.Device+"/"+formatInt(revision))
	if e != nil {
		return b, ErrUnavailable
	}
	p, e := policy.VerifyBound(string(raw), roots, a.Binding.Device, a.Binding.Jkt, now)
	if e != nil {
		return b, ErrUnavailable
	}
	if p.Operation != "configure" || p.Revision != revision {
		return b, ErrDenied
	}
	capable := false
	for _, c := range p.RequiredCapabilities {
		if c == "overlay.credentials.v1" {
			capable = true
		}
	}
	if !capable {
		return b, ErrDenied
	}
	engine, e := base64.RawURLEncoding.Strict().DecodeString(p.EngineConfigB64)
	if e != nil {
		return b, ErrUnavailable
	}
	var document map[string]json.RawMessage
	if identity.DecodeConfiguration(engine, &document) != nil || document == nil {
		return b, ErrUnavailable
	}
	var outbounds []map[string]json.RawMessage
	if identity.DecodeConfiguration(document["outbounds"], &outbounds) != nil || len(outbounds) > 64 {
		return b, ErrUnavailable
	}
	found := false
	for _, outbound := range outbounds {
		if _, ok := outbound["managed"]; !ok {
			continue
		}
		var kind, management string
		var m ManagedOverlayReference
		if identity.Decode(outbound["type"], &kind, true) != nil || kind != "netbird" || identity.Decode(outbound["management_url"], &management, true) != nil || identity.Decode(outbound["managed"], &m, true) != nil || string(outbound["managed"]) == "null" {
			return b, ErrUnavailable
		}
		if _, ok := outbound["setup_key"]; ok {
			return b, ErrUnavailable
		}
		if _, ok := outbound["state_directory"]; ok {
			return b, ErrUnavailable
		}
		address := overlay.Address{ServiceID: service, OwnerTag: overlayOwner(service, a.Issuer, a.Subject), DeviceID: a.Binding.Device, OverlayID: m.OverlayID, Provider: "netbird", ResourceID: m.ResourceID, NetworkID: m.NetworkID, IdentityEpoch: m.IdentityEpoch, ManagementURL: management}
		namespace, e := overlay.Namespace(address)
		if e != nil || !overlayDigest(m.SetupReference) || m.SetupVersion < 1 || m.SetupVersion > 9007199254740991 {
			return b, ErrUnavailable
		}
		if namespace == r.Namespace && (cleanup || m.SetupReference == r.Reference && m.SetupVersion == r.Version) {
			if found {
				return b, ErrUnavailable
			}
			found = true
			b = overlay.CredentialBinding{Address: address, KeyThumbprint: a.Binding.Jkt, Reference: r.Reference, Version: r.Version, SecurityEpoch: p.SecurityEpoch, OfflineUntilMs: min(p.OfflineUntilMs, a.AccountUntilMs)}
		}
	}
	if !found {
		return b, ErrDenied
	}
	return b, nil
}

func overlayAAD(device, reference string, version int64) string {
	return "overlay/v1/" + device + "/" + reference + "/" + formatInt(version)
}

// InstallOverlayGrant is called by the independent publication authority in
// its final account/device/assignment-fenced transaction, never by the API.
// It verifies the addressed signature again and cannot overwrite a reference.
func (s *Store) InstallOverlayGrant(ctx context.Context, tx *sql.Tx, owner string, b overlay.CredentialBinding, envelope string, roots map[string]*ecdsa.PublicKey, now time.Time) error {
	c, e := overlay.VerifyCredential(envelope, roots, b, now)
	if e != nil {
		return identity.ErrInvalid
	}
	namespace, e := overlay.Namespace(b.Address)
	if e != nil {
		return identity.ErrInvalid
	}
	if owner == "" {
		return identity.ErrInvalid
	}
	if _, e = lockAccount(ctx, tx, owner, now.Unix()); e != nil {
		return e
	}
	var deviceOwner, jkt, issuer, subject string
	var active bool
	if e = tx.QueryRowContext(ctx, `SELECT owner,jkt,active FROM identity_devices WHERE id=$1 FOR UPDATE`, b.Address.DeviceID).Scan(&deviceOwner, &jkt, &active); e != nil {
		return e
	}
	if !active || deviceOwner != owner || jkt != b.KeyThumbprint {
		return ErrDenied
	}
	if e = tx.QueryRowContext(ctx, `SELECT issuer,subject FROM identity_accounts WHERE owner=$1`, owner).Scan(&issuer, &subject); e != nil {
		return e
	}
	if b.Address.OwnerTag != overlayOwner(b.Address.ServiceID, issuer, subject) {
		return ErrDenied
	}
	protected := s.Seal([]byte(envelope), overlayAAD(b.Address.DeviceID, b.Reference, b.Version))
	_, e = tx.ExecContext(ctx, `INSERT INTO identity_overlay_grants(device,reference,version,owner,jkt,namespace,security_epoch,expires_ms,envelope_hash,envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, b.Address.DeviceID, b.Reference, b.Version, owner, b.KeyThumbprint, namespace, b.SecurityEpoch, c.ExpiresMs, identity.Hash([]byte(envelope)), protected)
	return e
}

func (s *Store) OverlayCredential(ctx context.Context, b Binding, token string, proof identity.Proof, raw []byte, consume bool, service string, roots map[string]*ecdsa.PublicKey, now time.Time) (OverlayReply, error) {
	started := time.Now()
	var reply OverlayReply
	var request OverlayRequest
	if proof.Claims.RequestHash != identity.Hash(raw) || identity.Decode(raw, &request, true) != nil || !idPattern.MatchString(request.OperationID) || !overlayDigest(request.Reference) || request.Version < 1 || request.Version > 9007199254740991 || !strings.HasPrefix(request.Namespace, "managed-netbird/") || !overlayDigest(strings.TrimPrefix(request.Namespace, "managed-netbird/")) {
		return reply, identity.ErrInvalid
	}
	value, e := s.WithDeviceSession(ctx, b, token, proof, now, func(ctx context.Context, tx *sql.Tx, a DeviceAuthority) (DeviceResult, error) {
		current := now.Add(time.Since(started))
		permit, e := s.overlayPermission(ctx, tx, a, service, roots, request, consume, current)
		if e != nil {
			return DeviceResult{}, e
		}
		var owner, jkt, namespace, hash string
		var epoch, expires int64
		var protected []byte
		var revoked bool
		e = tx.QueryRowContext(ctx, `SELECT owner,jkt,namespace,security_epoch,expires_ms,envelope_hash,envelope,revoked FROM identity_overlay_grants WHERE device=$1 AND reference=$2 AND version=$3 FOR UPDATE`, b.Device, request.Reference, request.Version).Scan(&owner, &jkt, &namespace, &epoch, &expires, &hash, &protected, &revoked)
		if errors.Is(e, sql.ErrNoRows) {
			if !consume {
				return DeviceResult{}, s.overlayBrokerPending(ctx, tx, a, permit, request, current)
			}
			return DeviceResult{}, ErrDenied
		}
		if e != nil {
			return DeviceResult{}, e
		}
		if owner != a.Binding.Owner || jkt != a.Binding.Jkt || namespace != request.Namespace || epoch > permit.SecurityEpoch {
			return DeviceResult{}, ErrDenied
		}
		if !consume && (epoch != permit.SecurityEpoch || revoked || expires <= current.UnixMilli()) {
			if s.OverlayBrokerPending {
				e := s.overlayBrokerPending(ctx, tx, a, permit, request, current)
				if errors.Is(e, ErrPending) {
					e = ErrConflict
				}
				return DeviceResult{}, e
			}
			return DeviceResult{}, ErrDenied
		}
		var operation, bodyHash string
		var consumed sql.NullInt64
		e = tx.QueryRowContext(ctx, `SELECT operation_id,body_hash,consumed_ms FROM identity_overlay_deliveries WHERE device=$1 AND reference=$2 AND version=$3 FOR UPDATE`, b.Device, request.Reference, request.Version).Scan(&operation, &bodyHash, &consumed)
		if errors.Is(e, sql.ErrNoRows) {
			var other bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_overlay_deliveries WHERE device=$1 AND operation_id=$2)`, b.Device, request.OperationID).Scan(&other); e != nil {
				return DeviceResult{}, e
			}
			if other {
				return DeviceResult{}, ErrConflict
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO identity_overlay_deliveries(device,reference,version,operation_id,body_hash) VALUES($1,$2,$3,$4,$5)`, b.Device, request.Reference, request.Version, request.OperationID, identity.Hash(raw))
			if e != nil {
				return DeviceResult{}, e
			}
		} else if e != nil {
			return DeviceResult{}, e
		} else if operation != request.OperationID || bodyHash != identity.Hash(raw) {
			return DeviceResult{}, ErrConflict
		}
		until := min(permit.OfflineUntilMs, expires)
		// Consumption also abandons a never-fetched grant after a controller
		// crash before dispatch. The locked addressed grant must still belong to
		// this current authorized device/key/namespace. Persist its operation and
		// irreversible erasure together: a late fetch cannot resurrect it. An
		// existing delivery always requires its exact immutable operation/body.
		// Its secret is never returned or reused. Current permission for the same
		// namespace can therefore acknowledge it after key expiry/reference or
		// security-epoch refresh; fetch retains every exact version/time fence.
		if consume {
			until = permit.OfflineUntilMs
		}
		if consumed.Valid {
			if !consume {
				return DeviceResult{}, ErrDenied
			}
			return DeviceResult{OverlayReply{Consumed: true}, until}, nil
		}
		if consume {
			if _, e = tx.ExecContext(ctx, `UPDATE identity_overlay_deliveries SET consumed_ms=$4 WHERE device=$1 AND reference=$2 AND version=$3`, b.Device, request.Reference, request.Version, current.UnixMilli()); e != nil {
				return DeviceResult{}, e
			}
			if _, e = tx.ExecContext(ctx, `UPDATE identity_overlay_grants SET envelope=NULL WHERE device=$1 AND reference=$2 AND version=$3`, b.Device, request.Reference, request.Version); e != nil {
				return DeviceResult{}, e
			}
			return DeviceResult{OverlayReply{Consumed: true}, until}, nil
		}
		if protected == nil {
			return DeviceResult{}, ErrDenied
		}
		envelope, e := s.Open(protected, overlayAAD(b.Device, request.Reference, request.Version))
		if e != nil || identity.Hash(envelope) != hash {
			return DeviceResult{}, ErrUnavailable
		}
		if _, e = overlay.VerifyCredential(string(envelope), roots, permit, now.Add(time.Since(started))); e != nil {
			return DeviceResult{}, ErrUnavailable
		}
		return DeviceResult{OverlayReply{Envelope: string(envelope)}, until}, nil
	})
	if e != nil {
		return reply, e
	}
	reply, ok := value.(OverlayReply)
	if !ok {
		return OverlayReply{}, ErrUnavailable
	}
	return reply, nil
}
