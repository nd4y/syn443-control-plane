package enrollment

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/netbirdapi"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
)

// BrokerScope is publisher-owned immutable authority. Provider values and PATs
// never occur here. Resource/account/group approval is supplied by a fence owned
// by the independent publisher, not a caller-supplied 'ready' flag.
type BrokerScope struct {
	Binding          overlay.CredentialBinding `json:"binding"`
	Owner            string                    `json:"owner"`
	GrantHash        string                    `json:"grantHash"`
	ResourceRevision int64                     `json:"resourceRevision"`
	Account          string                    `json:"account"`
	Groups           []string                  `json:"groups"`
	DeadlineMs       int64                     `json:"deadlineMs"`
}

var brokerIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (BrokerScope) String() string   { return "OverlayBrokerScope([redacted])" }
func (BrokerScope) GoString() string { return "OverlayBrokerScope([redacted])" }

func brokerAAD(device, ref string, version int64, kind string) string {
	return "overlay-broker/v1/" + device + "/" + ref + "/" + formatInt(version) + "/" + kind
}
func (b BrokerScope) validate(now time.Time) error {
	if _, e := overlay.Namespace(b.Binding.Address); e != nil {
		return identity.ErrInvalid
	}
	if b.Binding.Address.Provider != "netbird" || !overlayDigest(b.Binding.Reference) || !overlayDigest(b.Binding.KeyThumbprint) || !overlayDigest(b.GrantHash) || b.Binding.Version < 1 || b.Binding.Version > 9007199254740991 || b.Binding.SecurityEpoch < 0 || b.Binding.SecurityEpoch > 9007199254740991 || b.ResourceRevision < 1 || b.ResourceRevision > 9007199254740991 || !overlayDigest(b.Owner) || !brokerIdentifier.MatchString(b.Account) || b.DeadlineMs <= now.UnixMilli() || b.DeadlineMs > now.Add(30*time.Minute).UnixMilli() || b.DeadlineMs > b.Binding.OfflineUntilMs || len(b.Groups) < 1 || len(b.Groups) > 16 {
		return identity.ErrInvalid
	}
	seen := map[string]bool{}
	for _, group := range b.Groups {
		if !brokerIdentifier.MatchString(group) || seen[group] {
			return identity.ErrInvalid
		}
		seen[group] = true
	}
	return nil
}

// ReserveOverlayBroker must execute in the publisher's final transaction. It
// derives account/device ownership from locked SQL rows and rechecks the external
// resource/approval fence. Duplicate requests preserve the original operation.
func (s *Store) ReserveOverlayBroker(ctx context.Context, tx *sql.Tx, b BrokerScope, fence ApprovalFence, now time.Time) error {
	if tx == nil || fence == nil || b.validate(now) != nil {
		return identity.ErrInvalid
	}
	var role string
	if e := tx.QueryRowContext(ctx, `SELECT current_user`).Scan(&role); e != nil || role != "syn443_identity_publisher" {
		return ErrDenied
	}
	a, e := lockAccount(ctx, tx, b.Owner, now.Unix())
	if e != nil {
		return e
	}
	if a.Grant != b.GrantHash || a.Until*1000 < b.DeadlineMs {
		return ErrDenied
	}
	var owner, jkt, issuer, subject string
	var active bool
	e = tx.QueryRowContext(ctx, `SELECT owner,jkt,active FROM identity_devices WHERE id=$1 FOR UPDATE`, b.Binding.Address.DeviceID).Scan(&owner, &jkt, &active)
	if e != nil {
		return e
	}
	if !active || owner != b.Owner || jkt != b.Binding.KeyThumbprint {
		return ErrDenied
	}
	if e = tx.QueryRowContext(ctx, `SELECT issuer,subject FROM identity_accounts WHERE owner=$1`, owner).Scan(&issuer, &subject); e != nil {
		return e
	}
	if b.Binding.Address.OwnerTag != overlayOwner(b.Binding.Address.ServiceID, issuer, subject) {
		return ErrDenied
	}
	if e = fence.Lock(ctx, tx, now); e != nil {
		return e
	}
	raw, e := json.Marshal(b)
	if e != nil {
		return identity.ErrInvalid
	}
	hash := identity.Hash(raw)
	namespace, _ := overlay.Namespace(b.Binding.Address)
	var existing string
	e = tx.QueryRowContext(ctx, `SELECT scope_hash FROM identity_overlay_broker WHERE device=$1 AND reference=$2 AND version=$3`, b.Binding.Address.DeviceID, b.Binding.Reference, b.Binding.Version).Scan(&existing)
	if e == nil {
		if existing != hash {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_overlay_broker WHERE device=$1 AND state<>'retired'`, b.Binding.Address.DeviceID).Scan(&count); e != nil {
		return e
	}
	if count >= 16 {
		return ErrUnavailable
	}
	protected := s.Seal(raw, brokerAAD(b.Binding.Address.DeviceID, b.Binding.Reference, b.Binding.Version, "scope"))
	_, e = tx.ExecContext(ctx, `INSERT INTO identity_overlay_broker(device,reference,version,owner,jkt,namespace,resource,resource_revision,scope_hash,scope,operation,deadline_ms,created_ms,next_ms,security_epoch,grant_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15)`, b.Binding.Address.DeviceID, b.Binding.Reference, b.Binding.Version, owner, jkt, namespace, b.Binding.Address.ResourceID, b.ResourceRevision, hash, protected, random(), b.DeadlineMs, now.UnixMilli(), b.Binding.SecurityEpoch, b.GrantHash)
	return e
}

// RetireOverlayBroker records cleanup intent; it never destroys the provider
// mapping/credentials needed by the worker to finish a delayed revocation.
func (s *Store) RetireOverlayBroker(ctx context.Context, tx *sql.Tx, device, namespace string) error {
	var role string
	if tx == nil {
		return identity.ErrInvalid
	}
	if e := tx.QueryRowContext(ctx, `SELECT current_user`).Scan(&role); e != nil || role != "syn443_identity_publisher" {
		return ErrDenied
	}
	_, e := tx.ExecContext(ctx, `UPDATE identity_overlay_broker SET retire=true WHERE device=$1 AND namespace=$2`, device, namespace)
	return e
}

// The publisher propagates actual account/device withdrawal to durable cleanup;
// provider workers have no access to those identity tables. A changed ordinary
// config/grant hash alone does not retire an established overlay identity.
func (s *Store) RetireWithdrawnOverlayBrokers(ctx context.Context, now time.Time) error {
	if e := s.RuntimeRole(ctx, true); e != nil {
		return e
	}
	_, e := s.DB.ExecContext(ctx, `UPDATE identity_overlay_broker b SET retire=true FROM identity_devices d,identity_accounts a WHERE b.device=d.id AND b.owner=d.owner AND b.owner=a.owner AND NOT b.retire AND (NOT d.active OR NOT a.enabled OR a.valid_until<=$1)`, now.Unix())
	return e
}

// BrokerProvider is pinned to the scope's resource/account by the resolver.
// No callback has device-publication or SQL account/session authority.
type BrokerProvider interface {
	Authority() (string, string)
	CreateOneOff(context.Context, string, []string, time.Time) (netbirdapi.SetupKey, error)
	FindOperation(context.Context, string) ([]netbirdapi.SetupKey, error)
	InspectOwned(context.Context, string, string) (netbirdapi.SetupKey, error)
	DisableOwned(context.Context, string, string) (netbirdapi.SetupKey, error)
	RevokeOwned(context.Context, string, string) error
	FindOwnedPeer(context.Context, string, string, time.Time, time.Time) (netbirdapi.PeerOwnership, error)
	RevokeVerifiedPeer(context.Context, netbirdapi.PeerOwnership) error
}
type BrokerResolver interface {
	Resolve(context.Context, BrokerScope) (BrokerProvider, func(), error)
}

type brokerJob struct {
	device, ref, operation, state, lease, providerID, namespace   string
	version, deadline, dispatched, providerExpires, used, created int64
	retire                                                        bool
	scope                                                         BrokerScope
	secret, peer                                                  []byte
}

func (*brokerJob) String() string   { return "OverlayBrokerJob([redacted])" }
func (*brokerJob) GoString() string { return "OverlayBrokerJob([redacted])" }

// The strict protocol decoder treats structs as JSON objects, so time.Time's
// custom string representation is deliberately not used as a storage DTO. Keep
// RFC3339Nano text explicitly and parse after the ordinary exact-shape guards;
// nanoseconds matter when checking a provider's current creation identity.
type brokerPeerReceipt struct {
	ResourceID, AccountID, PeerID, SetupKeyID, OperationName, EventID string
	RegisteredAt, CreatedAt                                           string
}

func marshalBrokerPeer(p netbirdapi.PeerOwnership) ([]byte, error) {
	return json.Marshal(brokerPeerReceipt{p.ResourceID, p.AccountID, p.PeerID, p.SetupKeyID, p.OperationName, p.EventID, p.RegisteredAt.UTC().Format(time.RFC3339Nano), p.CreatedAt.UTC().Format(time.RFC3339Nano)})
}
func unmarshalBrokerPeer(raw []byte) (netbirdapi.PeerOwnership, error) {
	var r brokerPeerReceipt
	if len(raw) > 4096 || identity.Decode(raw, &r, true) != nil {
		return netbirdapi.PeerOwnership{}, ErrUnavailable
	}
	registered, e := time.Parse(time.RFC3339Nano, r.RegisteredAt)
	if e != nil {
		return netbirdapi.PeerOwnership{}, ErrUnavailable
	}
	created, e := time.Parse(time.RFC3339Nano, r.CreatedAt)
	if e != nil {
		return netbirdapi.PeerOwnership{}, ErrUnavailable
	}
	return netbirdapi.PeerOwnership{ResourceID: r.ResourceID, AccountID: r.AccountID, PeerID: r.PeerID, SetupKeyID: r.SetupKeyID, OperationName: r.OperationName, EventID: r.EventID, RegisteredAt: registered, CreatedAt: created}, nil
}

func (s *Store) BrokerRuntimeRole(ctx context.Context) error {
	var current, session string
	var unsafe bool
	e := s.DB.QueryRowContext(ctx, `SELECT current_user,session_user,rolsuper OR rolcreaterole OR rolcreatedb OR rolinherit OR rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) OR has_schema_privilege(current_user,'public','CREATE') OR has_table_privilege(current_user,'identity_devices','SELECT') OR has_table_privilege(current_user,'identity_sessions','SELECT') OR has_table_privilege(current_user,'identity_overlay_grants','INSERT') OR has_table_privilege(current_user,'identity_overlay_broker','INSERT') OR has_column_privilege(current_user,'identity_overlay_broker','scope','UPDATE') OR has_column_privilege(current_user,'identity_overlay_broker','retire','UPDATE') FROM pg_roles WHERE rolname=current_user`).Scan(&current, &session, &unsafe)
	if e != nil || unsafe || current != "syn443_overlay_worker" || session != current {
		return ErrDenied
	}
	if e = s.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'identity_overlay_reference_heads','INSERT') OR has_column_privilege(current_user,'identity_overlay_reference_heads','reference','UPDATE') OR has_column_privilege(current_user,'identity_overlay_reference_heads','retired','UPDATE')`).Scan(&unsafe); e != nil || unsafe {
		return ErrDenied
	}
	return nil
}

// Claim preserves queued authority while resolving the resource. RunOnce commits
// a separate dispatched marker immediately before the first mutation attempt.
func (s *Store) claimBroker(ctx context.Context, now time.Time) (*brokerJob, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	j := &brokerJob{}
	var protected []byte
	var hash string
	e = tx.QueryRowContext(ctx, `SELECT device,reference,version,operation,state,provider_id,deadline_ms,dispatched_ms,provider_expires_ms,provider_used,retire,scope,scope_hash,secret,peer_evidence,namespace,created_ms FROM identity_overlay_broker WHERE lease_until_ms<=$1 AND next_ms<=$1 AND attempts<10000 AND state NOT IN ('retired','blocked') AND (state NOT IN ('established','cleared') OR retire) ORDER BY next_ms,created_ms,device LIMIT 1 FOR UPDATE SKIP LOCKED`, now.UnixMilli()).Scan(&j.device, &j.ref, &j.version, &j.operation, &j.state, &j.providerID, &j.deadline, &j.dispatched, &j.providerExpires, &j.used, &j.retire, &protected, &hash, &j.secret, &j.peer, &j.namespace, &j.created)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	raw, e := s.Open(protected, brokerAAD(j.device, j.ref, j.version, "scope"))
	if e != nil || identity.Hash(raw) != hash || identity.Decode(raw, &j.scope, true) != nil {
		return nil, ErrUnavailable
	}
	namespace, e := overlay.Namespace(j.scope.Binding.Address)
	if e != nil || j.scope.validate(time.UnixMilli(j.created)) != nil || j.scope.Binding.Address.DeviceID != j.device || j.scope.Binding.Reference != j.ref || j.scope.Binding.Version != j.version || namespace != j.namespace || j.scope.DeadlineMs != j.deadline {
		return nil, ErrUnavailable
	}
	j.lease = random()
	state := j.state
	dispatch := j.dispatched
	if state == "queued" && (j.retire || j.deadline <= now.UnixMilli()) {
		state = "retired"
	}
	_, e = tx.ExecContext(ctx, `UPDATE identity_overlay_broker SET lease=$4,lease_until_ms=$5,state=$6,dispatched_ms=$7,attempts=attempts+1 WHERE device=$1 AND reference=$2 AND version=$3`, j.device, j.ref, j.version, j.lease, now.Add(45*time.Second).UnixMilli(), state, dispatch)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	if state == "retired" {
		return nil, nil
	}
	j.dispatched = dispatch
	return j, nil
}

func (s *Store) finishBroker(ctx context.Context, j *brokerJob, state string, key netbirdapi.SetupKey, peer []byte, code string, now time.Time) error {
	// A callback arriving after its lease cannot overwrite a newer worker. It
	// does not revoke on its own: the durable dispatched operation is reconciled.
	id := j.providerID
	expires := j.providerExpires
	used := j.used
	if key.ID != "" {
		if !validBrokerKey(j, key) {
			return ErrUnavailable
		}
		id = key.ID
		expires = key.Expires.UnixMilli()
		used = max(used, key.UsedTimes)
	}
	var secret []byte
	if state == "issued" && key.Secret != "" {
		secret = s.Seal([]byte(key.Secret), brokerAAD(j.device, j.ref, j.version, "secret"))
	} else if state == "issued" {
		secret = j.secret
	}
	if peer == nil {
		peer = j.peer
	}
	result, e := s.DB.ExecContext(ctx, `UPDATE identity_overlay_broker SET state=$5,provider_id=$6,provider_expires_ms=$7,provider_used=$8,secret=$9,peer_evidence=$10,error_code=$11,lease='',lease_until_ms=0,next_ms=$12 WHERE device=$1 AND reference=$2 AND version=$3 AND lease=$4 AND lease_until_ms>$13`, j.device, j.ref, j.version, j.lease, state, id, expires, used, secret, peer, code, now.Add(5*time.Second).UnixMilli(), now.UnixMilli())
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func validBrokerKey(j *brokerJob, k netbirdapi.SetupKey) bool {
	if !brokerIdentifier.MatchString(k.ID) || k.Name != "syn443-"+j.operation || k.Type != "one-off" || k.UsageLimit != 1 || k.UsedTimes < j.used || k.UsedTimes > 1 || k.Expires.IsZero() || j.providerID != "" && k.ID != j.providerID || j.providerExpires != 0 && k.Expires.UnixMilli() != j.providerExpires {
		return false
	}
	expected := append([]string(nil), j.scope.Groups...)
	actual := append([]string(nil), k.Groups...)
	slices.Sort(expected)
	slices.Sort(actual)
	return slices.Equal(expected, actual)
}

func providerCode(e error) string {
	var p *netbirdapi.Error
	if errors.As(e, &p) {
		switch p.Code {
		case "not_found":
			return "provider_absent"
		case "ownership_ambiguous", "ownership_mismatch", "peer_identity_mismatch":
			return "provider_ownership"
		case "cancelled":
			return "cancelled"
		}
	}
	return "provider_unavailable"
}

// RunOverlayBrokerOnce handles one bounded job and requires a restricted worker
// connection. It holds no SQL transaction during HTTP. An unknown POST is never
// retried, including after a crash immediately following the dispatch commit.
func (s *Store) RunOverlayBrokerOnce(ctx context.Context, resolver BrokerResolver, now time.Time) error {
	if resolver == nil {
		return identity.ErrInvalid
	}
	if e := s.BrokerRuntimeRole(ctx); e != nil {
		return e
	}
	started := time.Now()
	j, e := s.claimBroker(ctx, now)
	if e != nil || j == nil {
		return e
	}
	current := func() time.Time { return now.Add(time.Since(started)) }
	provider, close, e := resolver.Resolve(ctx, j.scope)
	if e != nil || provider == nil {
		if close != nil {
			close()
		}
		return s.finishBroker(ctx, j, brokerRetryState(j), netbirdapi.SetupKey{}, nil, "resource_unavailable", current())
	}
	if close != nil {
		defer close()
	}
	resource, account := provider.Authority()
	if resource != j.scope.Binding.Address.ResourceID || account != j.scope.Account {
		return s.finishBroker(ctx, j, brokerRetryState(j), netbirdapi.SetupKey{}, nil, "resource_mismatch", current())
	}
	if j.state == "cleared" && j.retire {
		return s.finishBroker(ctx, j, "retired", netbirdapi.SetupKey{}, nil, "", current())
	}
	if (j.state == "registered" || j.state == "established") && j.retire {
		raw, err := s.Open(j.peer, brokerAAD(j.device, j.ref, j.version, "peer"))
		if err != nil {
			return ErrUnavailable
		}
		proof, err := unmarshalBrokerPeer(raw)
		if err != nil || proof.ResourceID != resource || proof.AccountID != account || proof.SetupKeyID != j.providerID || proof.OperationName != "syn443-"+j.operation {
			return ErrUnavailable
		}
		if err = provider.RevokeVerifiedPeer(ctx, proof); err != nil {
			return s.finishBroker(ctx, j, j.state, netbirdapi.SetupKey{}, nil, providerCode(err), current())
		}
		if err = provider.RevokeOwned(ctx, j.operation, j.providerID); err != nil {
			return s.finishBroker(ctx, j, j.state, netbirdapi.SetupKey{}, nil, providerCode(err), current())
		}
		return s.finishBroker(ctx, j, "retired", netbirdapi.SetupKey{}, nil, "", current())
	}
	if j.state == "registered" || j.state == "unused" {
		if err := provider.RevokeOwned(ctx, j.operation, j.providerID); err != nil {
			return s.finishBroker(ctx, j, j.state, netbirdapi.SetupKey{}, nil, providerCode(err), current())
		}
		state := "cleared"
		if j.state == "registered" {
			state = "established"
		}
		if j.retire {
			state = "retired"
		}
		return s.finishBroker(ctx, j, state, netbirdapi.SetupKey{}, nil, "", current())
	}
	if j.state == "queued" {
		// Commit dispatch only after resolving the pinned resource. Authority
		// withdrawal or expiry while resolving prevents the HTTP mutation.
		at := current()
		result, err := s.DB.ExecContext(ctx, `UPDATE identity_overlay_broker SET state='dispatched',dispatched_ms=$5 WHERE device=$1 AND reference=$2 AND version=$3 AND lease=$4 AND lease_until_ms>$5 AND state='queued' AND NOT retire AND deadline_ms>$5`, j.device, j.ref, j.version, j.lease, at.UnixMilli())
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrConflict
		}
		j.dispatched = at.UnixMilli()
		key, err := provider.CreateOneOff(ctx, j.operation, j.scope.Groups, current())
		if err != nil {
			return s.finishBroker(ctx, j, "uncertain", netbirdapi.SetupKey{}, nil, providerCode(err), current())
		}
		return s.finishBroker(ctx, j, "issued", key, nil, "", current())
	}
	if j.state == "dispatched" || j.state == "uncertain" {
		keys, err := provider.FindOperation(ctx, j.operation)
		if err != nil || len(keys) != 1 {
			if current().After(time.UnixMilli(j.dispatched).Add(26 * time.Hour)) {
				return s.finishBroker(ctx, j, "blocked", netbirdapi.SetupKey{}, nil, "creation_unresolved", current())
			}
			return s.finishBroker(ctx, j, "uncertain", netbirdapi.SetupKey{}, nil, providerCode(err), current())
		}
		key := keys[0]
		// A recovered metadata-only key cannot be delivered; disable before any
		// explicit new-reference renewal, preserving whether registration occurred.
		j.providerID = key.ID
		j.providerExpires = key.Expires.UnixMilli()
		j.used = max(j.used, key.UsedTimes)
		return s.finishBroker(ctx, j, "disabled", key, nil, "recovered_without_value", current())
	}
	if j.state == "issued" && j.deadline > current().UnixMilli() && !j.retire {
		key, err := provider.InspectOwned(ctx, j.operation, j.providerID)
		if err != nil {
			return s.finishBroker(ctx, j, "issued", netbirdapi.SetupKey{}, nil, providerCode(err), current())
		}
		if key.UsedTimes == 0 && key.Valid && !key.Revoked {
			return s.finishBroker(ctx, j, "issued", key, nil, "", current())
		}
	}
	// disabled is a cleanup phase, not proof that the provider accepted a PUT.
	key, err := provider.DisableOwned(ctx, j.operation, j.providerID)
	if err != nil {
		return s.finishBroker(ctx, j, "disabled", netbirdapi.SetupKey{}, nil, providerCode(err), current())
	}
	if key.UsedTimes == 0 {
		return s.finishBroker(ctx, j, "unused", key, nil, "", current())
	}
	proof, err := provider.FindOwnedPeer(ctx, j.operation, j.providerID, time.UnixMilli(j.dispatched), time.UnixMilli(j.dispatched).Add(26*time.Hour))
	if err != nil {
		return s.finishBroker(ctx, j, "disabled", key, nil, providerCode(err), current())
	}
	if proof.ResourceID != resource || proof.AccountID != account || proof.SetupKeyID != j.providerID || proof.OperationName != "syn443-"+j.operation {
		return ErrUnavailable
	}
	raw, err := marshalBrokerPeer(proof)
	if err != nil {
		return ErrUnavailable
	}
	protected := s.Seal(raw, brokerAAD(j.device, j.ref, j.version, "peer"))
	// Persist ownership before deleting setup-key metadata. Peer retirement is a
	// separate phase; it must consume this immutable evidence, never a hostname.
	return s.finishBroker(ctx, j, "registered", key, protected, "", current())
}
func brokerRetryState(j *brokerJob) string {
	if j.state == "dispatched" {
		return "uncertain"
	}
	return j.state
}

// Called only after current signed policy/session verification. The API has
// column-level metadata access, never scope/secret/provider mutation authority.
// A currently addressed but no-longer-deliverable key is a credential conflict,
// not proof that the ordinary device session/base policy has been revoked.
func (s *Store) overlayBrokerPending(ctx context.Context, tx *sql.Tx, a DeviceAuthority, permit overlay.CredentialBinding, r OverlayRequest, now time.Time) error {
	if !s.OverlayBrokerPending {
		return ErrDenied
	}
	var owner, jkt, namespace, grant, state string
	var epoch, deadline int64
	var retire bool
	e := tx.QueryRowContext(ctx, `SELECT owner,jkt,namespace,security_epoch,grant_hash,deadline_ms,state,retire FROM identity_overlay_broker WHERE device=$1 AND reference=$2 AND version=$3`, a.Binding.Device, r.Reference, r.Version).Scan(&owner, &jkt, &namespace, &epoch, &grant, &deadline, &state, &retire)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return ErrUnavailable
	}
	if owner != a.Binding.Owner || jkt != a.Binding.Jkt || namespace != r.Namespace || epoch != permit.SecurityEpoch || grant != a.GrantHash {
		return ErrDenied
	}
	if retire || deadline <= now.UnixMilli() || state != "queued" && state != "dispatched" && state != "uncertain" && state != "issued" {
		return ErrConflict
	}
	return ErrPending
}

// InstallReadyOverlayBroker wraps a worker-produced value only in the
// independently signed current policy's exact namespace/reference and live SQL
// account/device/resource authority. A short worker poll is independent of the
// policy refresh interval; this method never changes that policy or its lease.
func (s *Store) InstallReadyOverlayBroker(ctx context.Context, device, ref string, version int64, service, kid string, key *ecdsa.PrivateKey, roots map[string]*ecdsa.PublicKey, fence ApprovalFence, now time.Time) error {
	started := time.Now()
	if fence == nil || key == nil || service == "" || kid == "" {
		return identity.ErrInvalid
	}
	if e := s.RuntimeRole(ctx, true); e != nil {
		return e
	}
	// Ownership is immutable; acquire locks in account -> device -> broker order
	// used by enrollment/revocation rather than blocking those paths in reverse.
	var owner string
	if e := s.DB.QueryRowContext(ctx, `SELECT owner FROM identity_overlay_broker WHERE device=$1 AND reference=$2 AND version=$3`, device, ref, version).Scan(&owner); e != nil {
		return e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := lockAccount(ctx, tx, owner, now.Unix())
	if e != nil {
		return e
	}
	var deviceOwner, jkt, issuer, subject string
	var active bool
	if e = tx.QueryRowContext(ctx, `SELECT owner,jkt,active FROM identity_devices WHERE id=$1 FOR UPDATE`, device).Scan(&deviceOwner, &jkt, &active); e != nil {
		return e
	}
	if deviceOwner != owner || !active {
		return ErrDenied
	}
	var state, namespace, storedHash string
	var protected, cipher []byte
	var deadline int64
	var retire bool
	if e = tx.QueryRowContext(ctx, `SELECT state,namespace,scope_hash,scope,secret,deadline_ms,retire FROM identity_overlay_broker WHERE device=$1 AND reference=$2 AND version=$3 FOR UPDATE`, device, ref, version).Scan(&state, &namespace, &storedHash, &protected, &cipher, &deadline, &retire); e != nil {
		return e
	}
	current := func() time.Time { return now.Add(time.Since(started)) }
	if state != "issued" || retire || deadline <= current().UnixMilli() || len(cipher) == 0 {
		return ErrPending
	}
	raw, e := s.Open(protected, brokerAAD(device, ref, version, "scope"))
	var b BrokerScope
	if e != nil || identity.Hash(raw) != storedHash || identity.Decode(raw, &b, true) != nil {
		return ErrUnavailable
	}
	if b.Owner != owner || b.GrantHash != a.Grant || b.Binding.Address.DeviceID != device || b.Binding.Address.ServiceID != service || b.Binding.KeyThumbprint != jkt || b.Binding.Reference != ref || b.Binding.Version != version || b.DeadlineMs != deadline {
		return ErrDenied
	}
	if e = tx.QueryRowContext(ctx, `SELECT issuer,subject FROM identity_accounts WHERE owner=$1`, owner).Scan(&issuer, &subject); e != nil {
		return e
	}
	permit, e := s.overlayPermission(ctx, tx, DeviceAuthority{Binding: Binding{Owner: owner, Device: device, Jkt: jkt}, Issuer: issuer, Subject: subject, GrantHash: a.Grant, AccountUntilMs: a.Until * 1000}, service, roots, OverlayRequest{Namespace: namespace, Reference: ref, Version: version}, false, current())
	if e != nil {
		return e
	}
	if permit.Address != b.Binding.Address || permit.SecurityEpoch != b.Binding.SecurityEpoch {
		return ErrDenied
	}
	if e = fence.Lock(ctx, tx, current()); e != nil {
		return e
	}
	var installed bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_overlay_grants WHERE device=$1 AND reference=$2 AND version=$3)`, device, ref, version).Scan(&installed); e != nil {
		return e
	}
	if installed {
		return nil
	}
	value, e := s.Open(cipher, brokerAAD(device, ref, version, "secret"))
	if e != nil {
		return ErrUnavailable
	}
	at := current()
	expiry := min(deadline, permit.OfflineUntilMs)
	c := overlay.Credential{SchemaVersion: 1, Audience: "syn443-overlay-credential", Address: permit.Address, KeyThumbprint: jkt, Reference: ref, Version: version, SecurityEpoch: permit.SecurityEpoch, Kind: "netbird.setup-key", IssuedAtMs: at.UnixMilli(), NotBeforeMs: at.UnixMilli(), ExpiresMs: expiry, Value: string(value)}
	envelope, e := overlay.SignCredential(c, permit, kid, key, at)
	clear(value)
	if e != nil {
		return e
	}
	if e = s.InstallOverlayGrant(ctx, tx, owner, permit, envelope, roots, current()); e != nil {
		return e
	}
	if e = fence.Lock(ctx, tx, current()); e != nil {
		return e
	}
	if current().UnixMilli() >= expiry {
		return ErrDenied
	}
	return tx.Commit()
}
