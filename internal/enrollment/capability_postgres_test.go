//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type capabilityFixture struct {
	f         *fixture
	key       *ecdsa.PrivateKey
	session   Session
	original  []byte
	publisher *Publisher
}

type capabilityVerifierFunc func(context.Context, string, time.Time) (identity.Principal, error)

func (f capabilityVerifierFunc) Verify(ctx context.Context, token string, now time.Time) (identity.Principal, error) {
	return f(ctx, token, now)
}
func capabilityQueuedWork(t *testing.T, c capabilityFixture) capabilityWork {
	t.Helper()
	var w capabilityWork
	e := fixtureOwner.QueryRow(`SELECT device,request_id,owner,jkt,grant_hash,request_hash,auth_kind,session_id,session_generation,accepted_ms,deadline_ms,body,receipt FROM identity_capability_requests WHERE device=$1 AND state='queued' ORDER BY request_id LIMIT 1`, c.session.DeviceID).Scan(&w.device, &w.request, &w.owner, &w.key, &w.grant, &w.hash, &w.kind, &w.session, &w.generation, &w.accepted, &w.deadline, &w.body, &w.protected)
	if e != nil {
		t.Fatal(e)
	}
	return w
}

func TestCapabilityPublisherVerifiesOidcScopeExpiryAndDistinguishesTransportFailure(t *testing.T) {
	for _, kind := range []string{"invalid-token", "transport", "scope", "expired", "withdrawn-grant"} {
		t.Run(kind, func(t *testing.T) {
			c := newCapabilityFixture(t)
			token := c.f.token(c.key)
			c.f.v.mu.Lock()
			principal := c.f.v.principals[token]
			principal.Scope = "syn443.enroll"
			principal.Expires = c.f.now.Unix() + 300
			c.f.v.principals[token] = principal
			c.f.v.mu.Unlock()
			path := "/v1/devices/capabilities"
			r := c.f.call(t, c.key, "GET", path, token, "", nil)
			expect(t, r, 401)
			nonce := r.Header().Get("DPoP-Nonce")
			r = c.f.call(t, c.key, "GET", path, token, nonce, nil)
			expect(t, r, 200)
			var snapshot CapabilitySnapshot
			json.Unmarshal(r.Body.Bytes(), &snapshot)
			raw := capabilityBody(t, "OIDC final "+kind, snapshot, "overlay.credentials.v1")
			expect(t, c.f.call(t, c.key, "POST", path, token, nonce, raw), 200)
			original := c.publisher.Verifier
			switch kind {
			case "invalid-token":
				c.publisher.Verifier = capabilityVerifierFunc(func(context.Context, string, time.Time) (identity.Principal, error) {
					return identity.Principal{}, identity.ErrInvalid
				})
			case "transport":
				c.publisher.Verifier = capabilityVerifierFunc(func(context.Context, string, time.Time) (identity.Principal, error) {
					return identity.Principal{}, errors.New("synthetic verifier transport")
				})
			case "scope":
				principal.Scope = "syn443.control"
				c.publisher.Verifier = capabilityVerifierFunc(func(context.Context, string, time.Time) (identity.Principal, error) { return principal, nil })
			case "expired":
				principal.Expires = c.f.now.Unix()
				c.publisher.Verifier = capabilityVerifierFunc(func(context.Context, string, time.Time) (identity.Principal, error) { return principal, nil })
			case "withdrawn-grant":
				delete(c.publisher.Grants, Owner(c.f.grant.Issuer, c.f.grant.Subject))
			}
			e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now)
			if kind == "transport" {
				if !errors.Is(e, ErrUnavailable) {
					t.Fatal("verifier outage became terminal", e)
				}
				c.assertNoHead(t)
				c.publisher.Verifier = original
				if e = c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); e != nil {
					t.Fatal("verifier retry lost original receipt", e)
				}
			} else {
				if !errors.Is(e, ErrDenied) {
					t.Fatal("unverified issuer authority accepted", e)
				}
				c.assertNoHead(t)
			}
		})
	}
}

func TestCapabilityLatePreparedDuplicateAndSqlLossDoNotDuplicateApproval(t *testing.T) {
	c := newCapabilityFixture(t)
	c.call(t, "POST", capabilityBody(t, "prepared duplicate", c.snapshot(t), "overlay.credentials.v1"), 200)
	w := capabilityQueuedWork(t, c)
	closed, e := sql.Open("pgx", fixturePublisherDSN)
	if e != nil {
		t.Fatal(e)
	}
	closed.Close()
	store, e := NewStore(closed, c.f.encryption)
	if e != nil {
		t.Fatal(e)
	}
	copy := *c.publisher
	copy.Store = store
	if e = copy.approveCapability(context.Background(), w, func() time.Time { return c.f.now }); !errors.Is(e, ErrUnavailable) {
		t.Fatal("lost SQL after verification approved data", e)
	}
	c.assertNoHead(t)
	if e = c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); e != nil {
		t.Fatal(e)
	}
	if e = c.publisher.approveCapability(context.Background(), w, func() time.Time { return c.f.now }); e != nil {
		t.Fatal("late duplicate not idempotent", e)
	}
	var versions int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_capability_versions`).Scan(&versions); e != nil || versions != 1 {
		t.Fatal("duplicate worker rewrote history", e)
	}
}

func TestCapabilityFinalExpiryRollsBackVersionHeadAndReceiptTogether(t *testing.T) {
	c := newCapabilityFixture(t)
	c.call(t, "POST", capabilityBody(t, "first before expiry", c.snapshot(t), "overlay.credentials.v1"), 200)
	if e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_sessions SET access_until=$2 WHERE access_hash=$1`, identity.Hash([]byte(c.session.AccessToken)), c.f.now.Unix()+1); e != nil {
		t.Fatal(e)
	}
	c.call(t, "POST", capabilityBody(t, "final commit expiry", c.snapshot(t), "configuration.layers.v1"), 200)
	tx, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`SELECT device FROM identity_capability_heads WHERE device=$1 FOR UPDATE`, c.session.DeviceID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now) }()
	time.Sleep(1200 * time.Millisecond)
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, ErrDenied) {
		t.Fatal("late SQL effects committed", e)
	}
	var head, versions int64
	if e = fixtureOwner.QueryRow(`SELECT revision,(SELECT count(*) FROM identity_capability_versions) FROM identity_capability_heads WHERE device=$1`, c.session.DeviceID).Scan(&head, &versions); e != nil || head != 1 || versions != 1 {
		t.Fatal("late approval partially committed", e)
	}
}

func TestCapabilityMalformedApiReceiptCannotApproveAndMissingCleanupRightsFailClosed(t *testing.T) {
	for _, kind := range []string{"envelope", "request-hash", "cleanup-update", "cleanup-delete"} {
		t.Run(kind, func(t *testing.T) {
			c := newCapabilityFixture(t)
			raw := capabilityBody(t, "malformed "+kind, c.snapshot(t), "overlay.credentials.v1")
			var input CapabilityInput
			json.Unmarshal(raw, &input)
			if kind == "envelope" || kind == "request-hash" {
				binding, e := c.f.store.Lookup(context.Background(), c.session.AccessToken, false)
				if e != nil {
					t.Fatal(e)
				}
				protected := c.f.store.Seal([]byte(`{"untrusted":true}`), capabilityReceiptAAD(c.session.DeviceID, input.RequestID))
				hash := identity.Hash(raw)
				if kind == "request-hash" {
					hash = identity.Hash([]byte("different body"))
				}
				if _, e = fixtureAPI.Exec(`INSERT INTO identity_capability_requests(device,request_id,owner,jkt,grant_hash,request_hash,body,receipt,accepted_ms,deadline_ms,auth_kind,session_id,session_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'device',$11,$12)`, c.session.DeviceID, input.RequestID, binding.Owner, binding.Jkt, c.f.grant.Hash(), hash, raw, protected, c.f.now.UnixMilli(), c.f.now.Add(time.Minute).UnixMilli(), binding.Session, binding.Generation); e != nil {
					t.Fatal(e)
				}
				if e = c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); !errors.Is(e, ErrDenied) {
					t.Fatal("malformed API record approved", e)
				}
			} else {
				c.call(t, "POST", raw, 200)
				privilege := "DELETE"
				if kind == "cleanup-update" {
					privilege = "UPDATE(state,receipt,result_revision,result_hash,error_code)"
				}
				if _, e := fixtureOwner.Exec(`REVOKE ` + privilege + ` ON identity_capability_requests FROM syn443_identity_publisher`); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() {
					if _, e := fixtureOwner.Exec(`GRANT ` + privilege + ` ON identity_capability_requests TO syn443_identity_publisher`); e != nil {
						t.Error(e)
					}
				})
				if e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); !errors.Is(e, ErrUnavailable) {
					t.Fatal("missing required SQL privileges silently succeeded", e)
				}
			}
			c.assertNoHead(t)
		})
	}
}

func newCapabilityFixture(t *testing.T) capabilityFixture {
	t.Helper()
	f := newFixture(t, 2)
	k := key(t)
	session, original, token := f.register(t, k)
	f.v.mu.Lock()
	p := f.v.principals[token]
	p.Expires = f.now.Unix() + 300
	p.Scope = "syn443.enroll"
	f.v.principals[token] = p
	f.v.mu.Unlock()
	publisher := f.publisher()
	if e := publisher.RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	return capabilityFixture{f, k, session, original, publisher}
}

func TestCapabilityConcurrentApprovalAndStrictDowngradeCAS(t *testing.T) {
	c := newCapabilityFixture(t)
	before := c.snapshot(t)
	for _, name := range []string{"first.feature.v1", "second.feature.v1"} {
		c.call(t, "POST", capabilityBody(t, name, before, name), 200)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now) }()
	}
	wg.Wait()
	close(results)
	for e := range results {
		if e != nil && !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	if e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); e != nil && !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	after := c.snapshot(t)
	if after.Version != 1 || len(after.Capabilities) != 4 {
		t.Fatal("concurrent approval lost CAS")
	}
	var approved, rejected int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FILTER(WHERE state='approved'),count(*) FILTER(WHERE state='rejected') FROM identity_capability_requests`).Scan(&approved, &rejected); e != nil || approved != 1 || rejected != 1 {
		t.Fatal("concurrent requests not terminal", e)
	}
	stale := capabilityBody(t, "stale head", before, "third.feature.v1")
	c.call(t, "POST", stale, 409)
	downgrade, _ := json.Marshal(CapabilityInput{RequestID: random(), PreviousHash: after.Hash, Capabilities: before.Capabilities})
	c.call(t, "POST", downgrade, 409)
	noChange := capabilityBody(t, "already aligned", after)
	var view CapabilityRequestView
	json.Unmarshal(c.call(t, "POST", noChange, 200).Body.Bytes(), &view)
	if view.State != "approved" || view.Version != 1 {
		t.Fatal("aligned no-op changed authority")
	}
}

func TestCapabilityWrongCipherRetainsPendingReceiptUntilRecoveryAndDeadline(t *testing.T) {
	c := newCapabilityFixture(t)
	raw := capabilityBody(t, "cipher retry", c.snapshot(t), "overlay.credentials.v1")
	c.call(t, "POST", raw, 200)
	original := c.publisher.Store
	bad, e := NewStore(fixturePublisher, bytes.Repeat([]byte{91}, 32))
	if e != nil {
		t.Fatal(e)
	}
	c.publisher.Store = bad
	if e = c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wrong cipher approved or terminally denied", e)
	}
	c.assertNoHead(t)
	var state string
	var secret []byte
	if e = fixtureOwner.QueryRow(`SELECT state,receipt FROM identity_capability_requests`).Scan(&state, &secret); e != nil || state != "queued" || len(secret) == 0 {
		t.Fatal("transient error destroyed retry evidence", e)
	}
	c.publisher.Store = original
	if e = c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); e != nil {
		t.Fatal(e)
	}
	if c.snapshot(t).Version != 1 {
		t.Fatal("recovered publisher could not approve")
	}
}

func TestCapabilityPublisherRechecksSessionAfterSqlLockWait(t *testing.T) {
	c := newCapabilityFixture(t)
	if _, e := fixtureOwner.Exec(`UPDATE identity_sessions SET access_until=$2 WHERE access_hash=$1`, identity.Hash([]byte(c.session.AccessToken)), c.f.now.Unix()+1); e != nil {
		t.Fatal(e)
	}
	c.call(t, "POST", capabilityBody(t, "late session", c.snapshot(t), "overlay.credentials.v1"), 200)
	tx, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`SELECT id FROM identity_devices WHERE id=$1 FOR UPDATE`, c.session.DeviceID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now) }()
	time.Sleep(1200 * time.Millisecond)
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, ErrDenied) {
		t.Fatal("late session granted new capabilities", e)
	}
	c.assertNoHead(t)
}

func TestCapabilitySessionFenceIsNarrowAndRolesCannotApprove(t *testing.T) {
	c := newCapabilityFixture(t)
	ctx := context.Background()
	binding, e := c.f.store.Lookup(ctx, c.session.AccessToken, false)
	if e != nil {
		t.Fatal(e)
	}
	call := func(token string, generation, at int64) bool {
		t.Helper()
		var allowed bool
		if e := fixturePublisher.QueryRow(`SELECT public.identity_capability_session_fence($1::text,$2::text,$3::bigint,$4::text,$5::text,$6::bigint)`, binding.Session, binding.Device, generation, identity.Hash([]byte(token)), c.session.Nonce, at).Scan(&allowed); e != nil {
			t.Fatal(e)
		}
		return allowed
	}
	if !call(c.session.AccessToken, binding.Generation, c.f.now.Unix()) || call(random(), binding.Generation, c.f.now.Unix()) || call(c.session.AccessToken, binding.Generation+1, c.f.now.Unix()) || call(c.session.AccessToken, binding.Generation, binding.AccessUntil) {
		t.Fatal("session fence did not bind token/generation/deadline")
	}
	var definer, apiExec, sessionRead bool
	var path string
	if e = fixtureOwner.QueryRow(`SELECT prosecdef,array_to_string(proconfig,','),has_function_privilege('syn443_identity_api',oid,'EXECUTE') FROM pg_proc WHERE oid='public.identity_capability_session_fence(text,text,bigint,text,text,bigint)'::regprocedure`).Scan(&definer, &path, &apiExec); e != nil || !definer || path != "search_path=pg_catalog" || apiExec {
		t.Fatal("unsafe definer function exposure", e)
	}
	if e = fixturePublisher.QueryRow(`SELECT has_any_column_privilege(current_user,'identity_sessions','SELECT')`).Scan(&sessionRead); e != nil || sessionRead {
		t.Fatal("publisher can inspect session hashes", e)
	}
	for _, statement := range []string{`INSERT INTO identity_capability_heads(device,revision,body_hash) VALUES('unknown',1,'unknown')`, `INSERT INTO identity_capability_versions(device,revision) VALUES('unknown',1)`} {
		if _, e = fixtureAPI.Exec(statement); e == nil {
			t.Fatal("API approved capabilities")
		}
	}
	if _, e = fixtureOwner.Exec(`GRANT EXECUTE ON FUNCTION identity_capability_session_fence(text,text,bigint,text,text,bigint) TO syn443_identity_api`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := fixtureOwner.Exec(`REVOKE EXECUTE ON FUNCTION identity_capability_session_fence(text,text,bigint,text,text,bigint) FROM syn443_identity_api`); e != nil {
			t.Error(e)
		}
	})
	if e = c.f.store.RuntimeRole(ctx, false); !errors.Is(e, ErrDenied) {
		t.Fatal("API privilege contamination accepted", e)
	}
}

func TestCapabilityRequestPendingQuotaAndExpiredTerminalCleanup(t *testing.T) {
	c := newCapabilityFixture(t)
	before := c.snapshot(t)
	for i := 0; i < 4; i++ {
		c.call(t, "POST", capabilityBody(t, fmt.Sprint("pending", i), before, fmt.Sprintf("feature-%d.v1", i)), 200)
	}
	c.call(t, "POST", capabilityBody(t, "fifth pending", before, "feature-5.v1"), 403)
	c.assertNoHead(t)
	if e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now.Add(181*time.Second)); e != nil {
		t.Fatal(e)
	}
	var retained int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_capability_requests WHERE receipt IS NOT NULL`).Scan(&retained); e != nil || retained != 0 {
		t.Fatal("expired request retained credentials", e)
	}
	if e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now.Add(25*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_capability_requests`).Scan(&retained); e != nil || retained != 0 {
		t.Fatal("terminal receipt retention unbounded", e)
	}
}

func TestCapabilityHttpRejectsMalformedAndForeignRequestsWithoutApproval(t *testing.T) {
	c := newCapabilityFixture(t)
	before := c.snapshot(t)
	raw := capabilityBody(t, "HTTP boundaries", before, "overlay.credentials.v1")
	for _, bad := range [][]byte{nil, []byte(`{}`), append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"approved":true}`)...), append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"requestId":"duplicate"}`)...)} {
		c.call(t, "POST", bad, 401)
	}
	expect(t, c.f.call(t, key(t), "GET", "/v1/device/capabilities", c.session.AccessToken, c.session.Nonce, nil), 403)
	expect(t, c.f.call(t, c.key, "PUT", "/v1/device/capabilities", c.session.AccessToken, c.session.Nonce, nil), 404)
	c.assertNoHead(t)
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_capability_requests`).Scan(&count); e != nil || count != 0 {
		t.Fatal("malformed/foreign request queued authority", e)
	}
}

func TestCapabilityPublisherRuntimeRejectsSessionReadContamination(t *testing.T) {
	c := newCapabilityFixture(t)
	if _, e := fixtureOwner.Exec(`GRANT SELECT(access_until) ON identity_sessions TO syn443_identity_publisher`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := fixtureOwner.Exec(`REVOKE SELECT(access_until) ON identity_sessions FROM syn443_identity_publisher`); e != nil {
			t.Error(e)
		}
	})
	if e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("publisher session-table privilege accepted", e)
	}
	if e := c.publisher.RunOnce(context.Background(), c.f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("unsafe publisher continued ordinary policy work", e)
	}
}
func (c capabilityFixture) call(t *testing.T, method string, raw []byte, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := c.f.call(t, c.key, method, "/v1/device/capabilities", c.session.AccessToken, c.session.Nonce, raw)
	expect(t, r, want)
	return r
}
func (c capabilityFixture) snapshot(t *testing.T) CapabilitySnapshot {
	t.Helper()
	var v CapabilitySnapshot
	if e := json.Unmarshal(c.call(t, "GET", nil, 200).Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func capabilityBody(t *testing.T, id string, previous CapabilitySnapshot, extra ...string) []byte {
	t.Helper()
	raw, e := json.Marshal(CapabilityInput{RequestID: identity.Hash([]byte(id)), PreviousHash: previous.Hash, Capabilities: append(append([]string(nil), previous.Capabilities...), extra...)})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func (c capabilityFixture) assertNoHead(t *testing.T) {
	t.Helper()
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_capability_heads`).Scan(&count); e != nil || count != 0 {
		t.Fatal("denied upgrade approved capabilities", e)
	}
}

func TestCapabilityDeviceApprovalPreservesOriginalEvidenceAndReplaysLostReply(t *testing.T) {
	c := newCapabilityFixture(t)
	ctx := context.Background()
	before := c.snapshot(t)
	if before.Version != 0 || len(before.Capabilities) != 3 || len(before.Hash) != 43 || len(before.AuthorityHash) != 43 {
		t.Fatal("original capability binding")
	}
	var originalReceipt []byte
	if e := fixtureOwner.QueryRow(`SELECT receipt FROM identity_devices WHERE id=$1`, c.session.DeviceID).Scan(&originalReceipt); e != nil {
		t.Fatal(e)
	}
	raw := capabilityBody(t, "upgrade one", before, "overlay.credentials.v1")
	var queued CapabilityRequestView
	json.Unmarshal(c.call(t, "POST", raw, 200).Body.Bytes(), &queued)
	if queued.State != "queued" {
		t.Fatal("API approved its own capability request")
	}
	c.assertNoHead(t)
	if e := c.publisher.ApproveCapabilitiesOnce(ctx, c.f.now); e != nil {
		t.Fatal(e)
	}
	after := c.snapshot(t)
	if after.Version != 1 || len(after.Capabilities) != 4 || after.Hash == before.Hash {
		t.Fatal("independent approval missing")
	}
	var replay CapabilityRequestView
	json.Unmarshal(c.call(t, "POST", raw, 200).Body.Bytes(), &replay)
	if replay.State != "approved" || replay.Version != 1 || replay.Hash != after.Hash {
		t.Fatal("lost acknowledgement changed approval")
	}
	changed := capabilityBody(t, "upgrade one", before, "another.feature.v1")
	c.call(t, "POST", changed, 409)
	second := capabilityBody(t, "upgrade two", after, "configuration.layers.v1")
	c.call(t, "POST", second, 200)
	if e := c.publisher.ApproveCapabilitiesOnce(ctx, c.f.now); e != nil {
		t.Fatal(e)
	}
	final := c.snapshot(t)
	if final.Version != 2 || len(final.Capabilities) != 5 {
		t.Fatal("second version missing")
	}
	var retained, retainedReceipt []byte
	var liveSecrets int
	if e := fixtureOwner.QueryRow(`SELECT request_body,receipt FROM identity_devices WHERE id=$1`, c.session.DeviceID).Scan(&retained, &retainedReceipt); e != nil || !bytes.Equal(retained, c.original) || !bytes.Equal(retainedReceipt, originalReceipt) {
		t.Fatal("approved enrollment evidence overwritten", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_capability_requests WHERE receipt IS NOT NULL`).Scan(&liveSecrets); e != nil || liveSecrets != 0 {
		t.Fatal("terminal credentials retained", e)
	}
	// Reauthentication accepts the approved set without replacing the original
	// receipt/body. A remaining old-set login remains a bounded conflict.
	var input Request
	json.Unmarshal(c.original, &input)
	input.RequestID = random()
	input.Capabilities = final.Capabilities
	fresh, _ := json.Marshal(input)
	currentSession := changedEnrollment(t, c.f, c.key, fresh, 200)
	input.RequestID = random()
	input.Capabilities = before.Capabilities
	old, _ := json.Marshal(input)
	changedEnrollment(t, c.f, c.key, old, 409)
	if e := fixtureOwner.QueryRow(`SELECT request_body,receipt FROM identity_devices WHERE id=$1`, c.session.DeviceID).Scan(&retained, &retainedReceipt); e != nil || !bytes.Equal(retained, c.original) || !bytes.Equal(retainedReceipt, originalReceipt) {
		t.Fatal("reauthentication replaced identity evidence", e)
	}
	// The normal policy publisher consumes independently approved availability,
	// rather than the deliberately unchanged original three-capability request.
	c.f.grant.Template.RequiredCapabilities = append(c.f.grant.Template.RequiredCapabilities, "overlay.credentials.v1")
	if e := Authorize(ctx, fixtureOwner, c.f.grant, c.f.now); e != nil {
		t.Fatal(e)
	}
	if e := c.f.publisher().RunOnce(ctx, c.f.now); e != nil {
		t.Fatal(e)
	}
	expect(t, c.f.call(t, c.key, "GET", "/v1/device/policy", c.session.AccessToken, c.session.Nonce, nil), 403)
	expect(t, c.f.call(t, c.key, "GET", "/v1/device/policy", currentSession.AccessToken, currentSession.Nonce, nil), 200)
}

func TestCapabilityOIDCApprovalUsesFreshBoundIdentityWithoutSessionReadPrivileges(t *testing.T) {
	c := newCapabilityFixture(t)
	token := c.f.token(c.key)
	c.f.v.mu.Lock()
	principal := c.f.v.principals[token]
	principal.Scope = "syn443.enroll"
	principal.Expires = c.f.now.Unix() + 300
	c.f.v.principals[token] = principal
	c.f.v.mu.Unlock()
	path := "/v1/devices/capabilities"
	r := c.f.call(t, c.key, "GET", path, token, "", nil)
	expect(t, r, 401)
	nonce := r.Header().Get("DPoP-Nonce")
	r = c.f.call(t, c.key, "GET", path, token, nonce, nil)
	expect(t, r, 200)
	var before CapabilitySnapshot
	json.Unmarshal(r.Body.Bytes(), &before)
	raw := capabilityBody(t, "OIDC capability upgrade", before, "overlay.credentials.v1")
	expect(t, c.f.call(t, c.key, "POST", path, token, nonce, raw), 200)
	if e := c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); e != nil {
		t.Fatal(e)
	}
	if c.snapshot(t).Version != 1 {
		t.Fatal("OIDC approval not published")
	}
	var read bool
	if e := fixturePublisher.QueryRow(`SELECT has_any_column_privilege(current_user,'identity_sessions','SELECT')`).Scan(&read); e != nil || read {
		t.Fatal("publisher gained session hashes", e)
	}
	principal.Scope = "syn443.control"
	c.f.v.mu.Lock()
	c.f.v.principals[token] = principal
	c.f.v.mu.Unlock()
	expect(t, c.f.call(t, c.key, "GET", path, token, nonce, nil), 403)
}

func TestCapabilityPendingAuthorityWithdrawalCannotApprove(t *testing.T) {
	for _, kind := range []string{"device", "account", "grant", "session", "generation", "nonce", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			c := newCapabilityFixture(t)
			raw := capabilityBody(t, "withdrawn "+kind, c.snapshot(t), "overlay.credentials.v1")
			c.call(t, "POST", raw, 200)
			var e error
			at := c.f.now
			switch kind {
			case "device":
				_, e = fixtureOwner.Exec(`UPDATE identity_devices SET active=false WHERE id=$1`, c.session.DeviceID)
			case "account":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false WHERE owner=$1`, Owner(c.f.grant.Issuer, c.f.grant.Subject))
			case "grant":
				_, e = fixtureOwner.Exec(`UPDATE identity_accounts SET grant_hash=$2 WHERE owner=$1`, Owner(c.f.grant.Issuer, c.f.grant.Subject), identity.Hash([]byte("new owner grant")))
			case "session":
				_, e = fixtureOwner.Exec(`UPDATE identity_sessions SET active=false WHERE access_hash=$1`, identity.Hash([]byte(c.session.AccessToken)))
			case "generation":
				_, e = fixtureOwner.Exec(`UPDATE identity_sessions SET generation=generation+1 WHERE access_hash=$1`, identity.Hash([]byte(c.session.AccessToken)))
			case "nonce":
				_, e = fixtureOwner.Exec(`UPDATE identity_sessions SET nonce=$2 WHERE access_hash=$1`, identity.Hash([]byte(c.session.AccessToken)), random())
			case "expiry":
				at = at.Add(181 * time.Second)
			}
			if e != nil {
				t.Fatal(e)
			}
			e = c.publisher.ApproveCapabilitiesOnce(context.Background(), at)
			if kind != "expiry" && !errors.Is(e, ErrDenied) {
				t.Fatal("withdrawn authority accepted", e)
			}
			if kind == "expiry" && e != nil {
				t.Fatal(e)
			}
			c.assertNoHead(t)
			var state string
			var secret []byte
			if e = fixtureOwner.QueryRow(`SELECT state,receipt FROM identity_capability_requests WHERE device=$1`, c.session.DeviceID).Scan(&state, &secret); e != nil || state != "rejected" || secret != nil {
				t.Fatal("withdrawn receipt not retired", e)
			}
		})
	}
}

func TestCapabilityPublisherReverifiesOriginalProofInsteadOfApiFlags(t *testing.T) {
	for _, kind := range []string{"uri", "token", "body", "key", "nonce", "foreign-nonce", "proof-time"} {
		t.Run(kind, func(t *testing.T) {
			c := newCapabilityFixture(t)
			raw := capabilityBody(t, "untrusted receipt "+kind, c.snapshot(t), "overlay.credentials.v1")
			uri := c.f.origin + "/v1/device/capabilities"
			encoded := signed(t, c.key, "POST", uri, c.session.AccessToken, c.session.Nonce, raw, c.f.now)
			proof, e := identity.RequestProof(encoded, identity.ProofContext{Method: "POST", URI: uri, Token: c.session.AccessToken, BodyHash: identity.Hash(raw), Now: c.f.now})
			if e != nil {
				t.Fatal(e)
			}
			receipt := CapabilityReceipt{Token: c.session.AccessToken, Proof: encoded, URI: uri, AcceptedAt: c.f.now.Unix()}
			switch kind {
			case "uri":
				receipt.URI = "https://other.example.invalid/v1/device/capabilities"
			case "token":
				receipt.Token = random()
			case "body":
				receipt.Proof = signed(t, c.key, "POST", uri, c.session.AccessToken, c.session.Nonce, []byte(`{}`), c.f.now)
			case "key":
				receipt.Proof = signed(t, key(t), "POST", uri, c.session.AccessToken, c.session.Nonce, raw, c.f.now)
			case "nonce":
				receipt.Proof = signed(t, c.key, "POST", uri, c.session.AccessToken, "", raw, c.f.now)
			case "foreign-nonce":
				receipt.Proof = signed(t, c.key, "POST", uri, c.session.AccessToken, random(), raw, c.f.now)
			case "proof-time":
				receipt.Proof = signed(t, c.key, "POST", uri, c.session.AccessToken, c.session.Nonce, raw, c.f.now.Add(-5*time.Minute))
			}
			binding, e := c.f.store.Lookup(context.Background(), c.session.AccessToken, false)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = c.f.store.CapabilityDevice(context.Background(), binding, c.session.AccessToken, proof, raw, receipt, c.f.now); e != nil {
				t.Fatal("fixture did not queue original untrusted receipt", e)
			}
			if e = c.publisher.ApproveCapabilitiesOnce(context.Background(), c.f.now); !errors.Is(e, ErrDenied) {
				t.Fatal("API substitution became approval", e)
			}
			c.assertNoHead(t)
		})
	}
}
