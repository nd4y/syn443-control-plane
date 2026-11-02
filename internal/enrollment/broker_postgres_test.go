//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/netbirdapi"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

type brokerResolverFunc func(context.Context, BrokerScope) (BrokerProvider, func(), error)

func (f brokerResolverFunc) Resolve(ctx context.Context, b BrokerScope) (BrokerProvider, func(), error) {
	return f(ctx, b)
}

type brokerProviderFixture struct {
	t                                                  *testing.T
	scope                                              BrokerScope
	key                                                netbirdapi.SetupKey
	create, find, inspect, disable, remove, removePeer int
	createError, removeError, errorAll                 error
	beforeCreate                                       func()
	peerUnavailable                                    bool
}

var _ BrokerProvider = (*netbirdapi.Client)(nil)

func (p *brokerProviderFixture) Authority() (string, string) {
	return p.scope.Binding.Address.ResourceID, p.scope.Account
}
func (p *brokerProviderFixture) CreateOneOff(_ context.Context, tag string, _ []string, now time.Time) (netbirdapi.SetupKey, error) {
	p.create++
	p.key.Name = "syn443-" + tag
	p.key.Expires = now.Add(24 * time.Hour)
	if p.beforeCreate != nil {
		p.beforeCreate()
	}
	if p.createError != nil {
		return netbirdapi.SetupKey{}, p.createError
	}
	return p.key, p.errorAll
}
func (p *brokerProviderFixture) FindOperation(_ context.Context, tag string) ([]netbirdapi.SetupKey, error) {
	p.find++
	if p.errorAll != nil {
		return nil, p.errorAll
	}
	if p.key.ID == "" || p.key.Name != "syn443-"+tag {
		return nil, nil
	}
	k := p.key
	k.Secret = ""
	return []netbirdapi.SetupKey{k}, nil
}
func (p *brokerProviderFixture) InspectOwned(context.Context, string, string) (netbirdapi.SetupKey, error) {
	p.inspect++
	k := p.key
	k.Secret = ""
	return k, p.errorAll
}
func (p *brokerProviderFixture) DisableOwned(context.Context, string, string) (netbirdapi.SetupKey, error) {
	p.disable++
	p.key.Valid = false
	p.key.Revoked = true
	k := p.key
	k.Secret = ""
	return k, p.errorAll
}
func (p *brokerProviderFixture) RevokeOwned(context.Context, string, string) error {
	p.remove++
	if p.removeError != nil {
		return p.removeError
	}
	return p.errorAll
}
func (p *brokerProviderFixture) FindOwnedPeer(_ context.Context, tag, key string, start, end time.Time) (netbirdapi.PeerOwnership, error) {
	if p.peerUnavailable {
		return netbirdapi.PeerOwnership{}, &netbirdapi.Error{Code: "ownership_unavailable"}
	}
	return netbirdapi.PeerOwnership{ResourceID: p.scope.Binding.Address.ResourceID, AccountID: p.scope.Account, PeerID: "peer-owned", SetupKeyID: key, OperationName: "syn443-" + tag, EventID: "event-a", RegisteredAt: start.Add(time.Second), CreatedAt: start}, p.errorAll
}
func (p *brokerProviderFixture) RevokeVerifiedPeer(_ context.Context, proof netbirdapi.PeerOwnership) error {
	p.removePeer++
	if proof.PeerID != "peer-owned" || proof.ResourceID != p.scope.Binding.Address.ResourceID || proof.AccountID != p.scope.Account {
		p.t.Fatal("broker borrowed foreign persisted peer evidence")
	}
	return p.errorAll
}

type brokerFixture struct {
	*overlayFixture
	scope    BrokerScope
	worker   *Store
	provider *brokerProviderFixture
	clock    time.Time
}

func newBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	o := newOverlayFixture(t)
	if _, e := fixtureOwner.Exec(`DELETE FROM identity_overlay_grants`); e != nil {
		t.Fatal(e)
	}
	scope := BrokerScope{Binding: o.binding, Owner: Owner(o.grant.Issuer, o.grant.Subject), GrantHash: o.grant.Hash(), ResourceRevision: 1, Account: "account-a", Groups: []string{"group-a"}, DeadlineMs: o.now.Add(5 * time.Minute).UnixMilli()}
	var value [16]byte
	if _, e := rand.Read(value[:]); e != nil {
		t.Fatal(e)
	}
	v := hex.EncodeToString(value[:])
	v = v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
	worker, e := NewStore(fixtureBroker, o.encryption)
	if e != nil {
		t.Fatal(e)
	}
	return &brokerFixture{o, scope, worker, &brokerProviderFixture{t: t, scope: scope, key: netbirdapi.SetupKey{ID: "key-a", Secret: v, Valid: true, Type: "one-off", UsageLimit: 1, Groups: scope.Groups}}, o.now}
}
func (f *brokerFixture) reserve(t *testing.T) {
	t.Helper()
	tx, e := fixturePublisher.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = f.overlayFixture.worker.ReserveOverlayBroker(context.Background(), tx, f.scope, &fixtureConfigurationFence{}, f.clock); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
}
func (f *brokerFixture) run(t *testing.T) {
	t.Helper()
	e := f.worker.RunOverlayBrokerOnce(context.Background(), brokerResolverFunc(func(_ context.Context, b BrokerScope) (BrokerProvider, func(), error) {
		if b.GrantHash != f.scope.GrantHash {
			t.Fatal("scope changed")
		}
		return f.provider, func() {}, nil
	}), f.clock)
	if e != nil {
		t.Fatal("broker step", e)
	}
	f.clock = f.clock.Add(6 * time.Second)
}
func (f *brokerFixture) state(t *testing.T) string {
	t.Helper()
	var state string
	if e := fixtureOwner.QueryRow(`SELECT state FROM identity_overlay_broker WHERE device=$1`, f.session.DeviceID).Scan(&state); e != nil {
		t.Fatal(e)
	}
	return state
}
func (f *brokerFixture) retire(t *testing.T) {
	t.Helper()
	tx, e := fixturePublisher.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = f.overlayFixture.worker.RetireOverlayBroker(context.Background(), tx, f.session.DeviceID, f.request.Namespace); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
}

func TestSQLBrokerDispatchesOnceAfterCommitAndPublishesOnlyCurrentSignedTarget(t *testing.T) {
	f := newBrokerFixture(t)
	f.reserve(t)
	f.reserve(t)
	f.provider.beforeCreate = func() {
		if f.state(t) != "dispatched" {
			t.Fatal("HTTP before durable dispatch commit")
		}
	}
	f.run(t)
	if f.state(t) != "issued" || f.provider.create != 1 {
		t.Fatal("issuance failed")
	}
	var cipher, scope []byte
	if e := fixtureOwner.QueryRow(`SELECT secret,scope FROM identity_overlay_broker`).Scan(&cipher, &scope); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(cipher, []byte(f.provider.key.Secret)) || bytes.Contains(scope, []byte(f.scope.Account)) {
		t.Fatal("broker stored private plaintext")
	}
	fence := &fixtureConfigurationFence{}
	e := f.overlayFixture.worker.InstallReadyOverlayBroker(context.Background(), f.session.DeviceID, f.request.Reference, 1, f.api.OverlayServiceID, "fixture-root", f.key, f.api.Roots, fence, f.clock)
	if e != nil || fence.calls != 2 {
		t.Fatal("independent addressed installation", e)
	}
	var protected []byte
	if e = fixtureOwner.QueryRow(`SELECT envelope FROM identity_overlay_grants`).Scan(&protected); e != nil {
		t.Fatal(e)
	}
	raw, e := f.overlayFixture.worker.Open(protected, overlayAAD(f.session.DeviceID, f.request.Reference, 1))
	if e != nil {
		t.Fatal(e)
	}
	credential, e := overlay.VerifyCredential(string(raw), f.api.Roots, f.binding, time.UnixMilli(f.scope.DeadlineMs-1))
	if e != nil || credential.Value != f.provider.key.Secret || credential.ExpiresMs != f.scope.DeadlineMs {
		t.Fatal("signed addressed credential or immutable deadline", e)
	}
	if _, e = overlay.VerifyCredential(string(raw), f.api.Roots, f.binding, time.UnixMilli(f.scope.DeadlineMs)); e == nil {
		t.Fatal("broker wrapping extended the original deadline")
	}
	f.run(t)
	if f.provider.create != 1 || f.provider.inspect != 1 {
		t.Fatal("already issued job repeated creation")
	}
}
func TestSQLBrokerLostCreationAndCrashBeforeHTTPOnlyReconcileTheOriginalOperation(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-reply", true: "after-commit-before-http"}[crash], func(t *testing.T) {
			f := newBrokerFixture(t)
			f.reserve(t)
			if crash {
				if _, e := fixtureOwner.Exec(`UPDATE identity_overlay_broker SET state='dispatched',dispatched_ms=$1,next_ms=0`, f.now.UnixMilli()); e != nil {
					t.Fatal(e)
				}
				var tag string
				if e := fixtureOwner.QueryRow(`SELECT operation FROM identity_overlay_broker`).Scan(&tag); e != nil {
					t.Fatal(e)
				}
				f.provider.key.Name = "syn443-" + tag
				f.provider.key.Expires = f.now.Add(24 * time.Hour)
			} else {
				f.provider.createError = &netbirdapi.Error{Code: "transport_unavailable", OutcomeUnknown: true}
				f.run(t)
			}
			f.run(t)
			if f.state(t) != "disabled" || f.provider.create > 1 || f.provider.find != 1 {
				t.Fatal("unknown issuance repeated POST")
			}
			f.run(t)
			if f.state(t) != "unused" || f.provider.remove != 0 {
				t.Fatal("usage evidence not durable before DELETE")
			}
			f.provider.removeError = &netbirdapi.Error{Code: "transport_unavailable", OutcomeUnknown: true}
			f.run(t)
			if f.state(t) != "unused" {
				t.Fatal("unknown key deletion lost disabled evidence")
			}
			f.provider.removeError = nil
			f.run(t)
			if f.state(t) != "cleared" || f.provider.create > 1 {
				t.Fatal("owned deletion retry not reconciled")
			}
		})
	}
}
func TestSQLBrokerPersistsPeerBeforeRemovingKeyAndRetiresAfterAuditRetention(t *testing.T) {
	f := newBrokerFixture(t)
	f.reserve(t)
	f.run(t)
	f.provider.key.UsedTimes = 1
	f.provider.peerUnavailable = true
	f.run(t)
	if f.state(t) != "disabled" || f.provider.remove != 0 {
		t.Fatal("missing peer evidence deleted key")
	}
	f.provider.peerUnavailable = false
	f.run(t)
	if f.state(t) != "registered" || f.provider.remove != 0 {
		t.Fatal("peer mapping not persisted first")
	}
	var protected []byte
	if e := fixtureOwner.QueryRow(`SELECT peer_evidence FROM identity_overlay_broker`).Scan(&protected); e != nil || len(protected) == 0 {
		t.Fatal("peer receipt absent", e)
	}
	f.run(t)
	if f.state(t) != "established" || f.provider.remove != 1 || f.provider.removePeer != 0 {
		t.Fatal("credential cleanup removed registered peer")
	}
	f.provider.peerUnavailable = true
	f.retire(t)
	f.run(t)
	if f.state(t) != "retired" || f.provider.removePeer != 1 {
		t.Fatal("retirement depended on expired audit retention")
	}
}
func TestSQLBrokerExpiryErasesOnlyEnrollmentValueAndLateCallbackCannotOverwriteLease(t *testing.T) {
	f := newBrokerFixture(t)
	f.reserve(t)
	f.run(t)
	f.clock = f.now.Add(6 * time.Minute)
	f.run(t)
	var cipher []byte
	if e := fixtureOwner.QueryRow(`SELECT secret FROM identity_overlay_broker`).Scan(&cipher); e != nil {
		t.Fatal(e)
	}
	if cipher != nil || f.provider.removePeer != 0 || f.state(t) != "unused" {
		t.Fatal("expired grant retained material or removed peer")
	}
	f = newBrokerFixture(t)
	f.reserve(t)
	f.provider.beforeCreate = func() {
		if _, e := fixtureOwner.Exec(`UPDATE identity_overlay_broker SET lease_until_ms=0`); e != nil {
			t.Fatal(e)
		}
	}
	e := f.worker.RunOverlayBrokerOnce(context.Background(), brokerResolverFunc(func(context.Context, BrokerScope) (BrokerProvider, func(), error) { return f.provider, nil, nil }), f.clock)
	if !errors.Is(e, ErrConflict) || f.state(t) != "dispatched" || f.provider.remove != 0 {
		t.Fatal("late callback overwrote/revoked another lease", e)
	}
	f.provider.beforeCreate = nil
	f.clock = f.clock.Add(time.Minute)
	f.run(t)
	if f.provider.create != 1 || f.state(t) != "disabled" {
		t.Fatal("late callback caused new issuance")
	}
}
func TestSQLBrokerRuntimeRolesAndImmutableScopeCannotBeBorrowed(t *testing.T) {
	f := newBrokerFixture(t)
	f.reserve(t)
	if e := f.worker.BrokerRuntimeRole(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, s := range []*Store{f.store, f.overlayFixture.worker} {
		if !errors.Is(s.BrokerRuntimeRole(context.Background()), ErrDenied) {
			t.Fatal("foreign runtime role accepted")
		}
	}
	for _, query := range []string{`SELECT scope FROM identity_overlay_broker`, `INSERT INTO identity_overlay_broker(device) VALUES('unowned')`, `UPDATE identity_overlay_broker SET retire=true`} {
		db := fixtureAPI
		if strings.Contains(query, "retire") {
			db = fixtureBroker
		}
		if _, e := db.Exec(query); e == nil {
			t.Fatal("runtime role acquired unrelated authority")
		}
	}
	for _, query := range []string{`SELECT id FROM identity_sessions`, `SELECT id FROM identity_devices`, `UPDATE identity_overlay_broker SET scope_hash='another'`, `UPDATE identity_overlay_broker SET operation='another'`, `DELETE FROM identity_overlay_broker`} {
		if _, e := fixtureBroker.Exec(query); e == nil {
			t.Fatal("provider worker gained identity/immutable/delete authority")
		}
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_overlay_broker SET deadline_ms=deadline_ms+1`); e == nil {
		t.Fatal("database invariant permitted changed credential deadline")
	}
	raw, e := json.Marshal(f.scope)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), f.provider.key.Secret) {
		t.Fatal("scope contains provider secret")
	}
}
func TestSQLBrokerRevokedReservationAndResourceOutageNeverDispatch(t *testing.T) {
	for _, scenario := range []string{"retired", "expired", "outage", "wrong-resource"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBrokerFixture(t)
			f.reserve(t)
			if scenario == "retired" {
				f.retire(t)
			}
			if scenario == "expired" {
				f.clock = f.clock.Add(6 * time.Minute)
			}
			if scenario == "wrong-resource" {
				f.provider.scope.Account = "foreign"
			}
			resolver := brokerResolverFunc(func(context.Context, BrokerScope) (BrokerProvider, func(), error) {
				if scenario == "outage" {
					return nil, nil, ErrUnavailable
				}
				return f.provider, nil, nil
			})
			if e := f.worker.RunOverlayBrokerOnce(context.Background(), resolver, f.clock); e != nil {
				t.Fatal(e)
			}
			if f.provider.create != 0 {
				t.Fatal("withdrawn/foreign/unavailable authority dispatched")
			}
			if scenario == "outage" {
				if f.state(t) != "queued" {
					t.Fatal("pre-dispatch outage destroyed retry authority")
				}
				f.clock = f.clock.Add(6 * time.Second)
				f.run(t)
				if f.provider.create != 1 {
					t.Fatal("known no-dispatch outage did not recover")
				}
			}
		})
	}
}
func TestSQLBrokerIndependentPublicationRejectsChangedGrantPolicyExpiryAndLateFence(t *testing.T) {
	for _, scenario := range []string{"grant", "policy", "expiry", "fence"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBrokerFixture(t)
			f.reserve(t)
			f.run(t)
			fence := &fixtureConfigurationFence{}
			switch scenario {
			case "grant":
				if _, e := fixtureOwner.Exec(`UPDATE identity_accounts SET grant_hash=$1`, random()); e != nil {
					t.Fatal(e)
				}
			case "policy":
				f.publication(t, func(p *policy.Payload) {
					p.RequiredCapabilities = []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}
				})
			case "expiry":
				f.clock = f.clock.Add(6 * time.Minute)
			case "fence":
				fence.lock = func(context.Context, *sql.Tx, time.Time) error { return ErrDenied }
			}
			e := f.overlayFixture.worker.InstallReadyOverlayBroker(context.Background(), f.session.DeviceID, f.request.Reference, 1, f.api.OverlayServiceID, "fixture-root", f.key, f.api.Roots, fence, f.clock)
			if e == nil {
				t.Fatal("withdrawn scope published")
			}
			var count int
			if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_grants`).Scan(&count); e != nil || count != 0 {
				t.Fatal("rejected grant persisted", e)
			}
		})
	}
}

func TestSQLBrokerReservationRejectsForeignIdentityChangedApprovalAndQuota(t *testing.T) {
	for _, scenario := range []string{"wrong-role", "owner", "jkt", "owner-tag", "grant", "inactive", "fence", "changed-reference", "quota"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBrokerFixture(t)
			scope := f.scope
			fence := &fixtureConfigurationFence{}
			db := fixturePublisher
			switch scenario {
			case "wrong-role":
				db = fixtureAPI
			case "owner":
				scope.Owner = random()
			case "jkt":
				scope.Binding.KeyThumbprint = random()
			case "owner-tag":
				scope.Binding.Address.OwnerTag = random()
			case "grant":
				scope.GrantHash = random()
			case "inactive":
				if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET active=false`); e != nil {
					t.Fatal(e)
				}
			case "fence":
				fence.lock = func(context.Context, *sql.Tx, time.Time) error { return ErrDenied }
			case "changed-reference":
				f.reserve(t)
				scope.Groups = []string{"changed-group"}
			case "quota":
				for i := 0; i < 16; i++ {
					f.scope.Binding.Reference = random()
					f.reserve(t)
				}
				scope.Binding.Reference = random()
			}
			tx, e := db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if e = f.overlayFixture.worker.ReserveOverlayBroker(context.Background(), tx, scope, fence, f.now); e == nil {
				t.Fatal("foreign/unapproved/over-quota reservation accepted")
			}
		})
	}
}

func TestSQLBrokerUnknownCreationNeverUsesMissingOrMultipleRecordsAsFreshAuthority(t *testing.T) {
	f := newBrokerFixture(t)
	f.reserve(t)
	f.provider.createError = &netbirdapi.Error{Code: "transport", OutcomeUnknown: true}
	f.run(t)
	f.provider.key.ID = ""
	f.run(t)
	f.run(t)
	if f.state(t) != "uncertain" || f.provider.create != 1 || f.provider.remove != 0 {
		t.Fatal("absent metadata caused speculative issuance/deletion")
	}
	f.clock = f.now.Add(27 * time.Hour)
	f.run(t)
	if f.state(t) != "blocked" || f.provider.create != 1 {
		t.Fatal("unknown outcome not bounded/dead-lettered")
	}
}

// Keep SQL transaction interfaces concrete: fixture callbacks cannot substitute
// their own device/account grant or return a public ready boolean.
var _ ApprovalFence = (*fixtureConfigurationFence)(nil)

func TestSQLBrokerPendingIsOptInCurrentPolicyOwnedAndDoesNotAcknowledgeConsumption(t *testing.T) {
	f := newBrokerFixture(t)
	expect(t, f.call(t, false), 403)
	f.reserve(t)
	expect(t, f.call(t, false), 403)
	f.store.OverlayBrokerPending = true
	reply := f.call(t, false)
	expect(t, reply, 202)
	if reply.Header().Get("Retry-After") != "2" {
		t.Fatal("pending poll was not bounded")
	}
	expect(t, f.call(t, true), 403)
	original := f.request
	f.request.Reference = random()
	expect(t, f.call(t, false), 403)
	f.request = original
	f.retire(t)
	expect(t, f.call(t, false), 409)
	var delivered int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_deliveries`).Scan(&delivered); e != nil || delivered != 0 {
		t.Fatal("pending/denied request created delivery/consumption evidence", e)
	}
}
func TestSQLBrokerExpiredPendingKeyIsNotADeviceSessionRevocation(t *testing.T) {
	f := newBrokerFixture(t)
	f.reserve(t)
	f.store.OverlayBrokerPending = true
	f.now = f.now.Add(6 * time.Minute)
	f.api.Clock = func() time.Time { return f.now }
	expect(t, f.call(t, false), 409)
	// Ordinary current policy remains independently authorized after the
	// optional overlay credential expires; no secret or registration is invented.
	reply := f.fixture.call(t, f.client, "GET", "/v1/device/policy", f.session.AccessToken, f.session.Nonce, nil)
	expect(t, reply, 200)
}
func TestSQLBrokerAccountWithdrawalQueuesRetirementWithoutConfigRefreshChurn(t *testing.T) {
	f := newBrokerFixture(t)
	f.reserve(t)
	f.run(t)
	f.provider.key.UsedTimes = 1
	f.run(t)
	f.run(t)
	if e := f.overlayFixture.worker.RetireWithdrawnOverlayBrokers(context.Background(), f.clock); e != nil {
		t.Fatal(e)
	}
	var retired bool
	if e := fixtureOwner.QueryRow(`SELECT retire FROM identity_overlay_broker`).Scan(&retired); e != nil || retired {
		t.Fatal("live owner was retired", e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET active=false`); e != nil {
		t.Fatal(e)
	}
	if e := f.overlayFixture.worker.RetireWithdrawnOverlayBrokers(context.Background(), f.clock); e != nil {
		t.Fatal(e)
	}
	f.run(t)
	if f.state(t) != "retired" || f.provider.removePeer != 1 {
		t.Fatal("withdrawal did not reach owned provider cleanup")
	}
}

func TestSQLBrokerOwnClockCannotRollBackOrModifyIdentityClock(t *testing.T) {
	f := newBrokerFixture(t)
	first, e := f.worker.BrokerNow(context.Background(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	second, e := f.worker.BrokerNow(context.Background(), f.now.Add(-time.Hour))
	if e != nil || !first.Equal(second) {
		t.Fatal("broker clock moved backward", e)
	}
	if _, e := fixtureBroker.Exec(`UPDATE identity_clock SET second=0`); e == nil {
		t.Fatal("provider worker modified identity clock")
	}
	if _, e := f.store.BrokerNow(context.Background(), f.now); e == nil {
		t.Fatal("API acquired broker scheduling clock")
	}
}

func TestSQLBrokerStartupRejectsAccidentallyBroadenedApiAndWorkerPrivileges(t *testing.T) {
	f := newBrokerFixture(t)
	if e := f.store.RuntimeRole(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	if e := f.worker.BrokerRuntimeRole(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`GRANT SELECT(secret) ON identity_overlay_broker TO syn443_identity_api`); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if _, e := fixtureOwner.Exec(`REVOKE SELECT(secret) ON identity_overlay_broker FROM syn443_identity_api`); e != nil {
			t.Error(e)
		}
	}()
	if !errors.Is(f.store.RuntimeRole(context.Background(), false), ErrDenied) {
		t.Fatal("API started with provider setup-secret read authority")
	}
	if _, e := fixtureOwner.Exec(`GRANT UPDATE(reference) ON identity_overlay_reference_heads TO syn443_overlay_worker`); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if _, e := fixtureOwner.Exec(`REVOKE UPDATE(reference) ON identity_overlay_reference_heads FROM syn443_overlay_worker`); e != nil {
			t.Error(e)
		}
	}()
	if !errors.Is(f.worker.BrokerRuntimeRole(context.Background()), ErrDenied) {
		t.Fatal("provider worker started with policy reference authority")
	}
}
