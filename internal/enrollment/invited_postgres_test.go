//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"net/http/httptest"
	"testing"
	"time"
)

type externalApproval struct {
	input    ApprovalInput
	deny     bool
	fenceErr error
	locked   bool
}

func (a *externalApproval) Verify(_ context.Context, in ApprovalInput, _ time.Time) (ApprovalFence, error) {
	a.input = in
	if a.deny {
		return nil, identity.ErrInvalid
	}
	return a, nil
}
func (a *externalApproval) Lock(context.Context, *sql.Tx, time.Time) error {
	a.locked = true
	return a.fenceErr
}
func TestSQLPublisherRequiresExplicitIndependentInvitationApproval(t *testing.T) {
	f := newFixture(t, 2)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session, raw, _ := f.register(t, key)
	ctx := context.Background()
	p := Publisher{Store: f.worker, Verifier: f.v, Grants: map[string]Grant{Owner(f.grant.Issuer, f.grant.Subject): f.grant}, Key: f.key, KeyID: "fixture-root", Origin: f.origin}
	receipt := func(kind, id string) {
		t.Helper()
		value, _ := json.Marshal(Receipt{Kind: kind, InvitationID: id, AcceptedAt: f.now.Unix()})
		if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET receipt=$2 WHERE id=$1`, session.DeviceID, f.worker.Seal(value, "receipt/v1/"+session.DeviceID)); e != nil {
			t.Fatal(e)
		}
	}
	receipt("unknown", "")
	if e := p.publish(ctx, session.DeviceID, f.now); !errors.Is(e, identity.ErrInvalid) {
		t.Fatal("unknown authority kind", e)
	}
	id := random()
	receipt("invite-v1", id)
	if e := p.publish(ctx, session.DeviceID, f.now); !errors.Is(e, identity.ErrInvalid) {
		t.Fatal("missing independent verifier", e)
	}
	approval := &externalApproval{deny: true}
	p.InvitationApproval = approval
	if e := p.publish(ctx, session.DeviceID, f.now); !errors.Is(e, identity.ErrInvalid) {
		t.Fatal("denied independent approval", e)
	}
	approval.deny = false
	approval.fenceErr = ErrConflict
	if e := p.publish(ctx, session.DeviceID, f.now); !errors.Is(e, ErrConflict) || !approval.locked {
		t.Fatal("final authorization fence omitted", e)
	}
	approval.fenceErr = nil
	approval.locked = false
	if e := p.publish(ctx, session.DeviceID, f.now); e != nil || !approval.locked {
		t.Fatal("verified independent publication", e)
	}
	thumb, _ := identity.PublicJWK(&key.PublicKey).Thumbprint()
	if approval.input.InvitationID != id || approval.input.Device != session.DeviceID || approval.input.Thumbprint != thumb || !bytes.Equal(approval.input.Request, raw) || approval.input.GrantHash != f.grant.Hash() {
		t.Fatal("approval scope changed")
	}
	var approved bool
	if e := fixtureOwner.QueryRow(`SELECT approved FROM identity_devices WHERE id=$1`, session.DeviceID).Scan(&approved); e != nil || !approved {
		t.Fatal("publication readback", e)
	}
}
func TestSQLInvitedSessionSharesCacheAndGenerationRevocationFences(t *testing.T) {
	f := newFixture(t, 2)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	previous, _, _ := f.register(t, key)
	ctx := context.Background()
	owner := Owner(f.grant.Issuer, f.grant.Subject)
	if _, e := fixtureOwner.Exec(`UPDATE identity_sessions SET active=false WHERE device=$1;`, previous.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET approved=true,offline_until=$2 WHERE id=$1`, previous.DeviceID, f.now.Unix()+600); e != nil {
		t.Fatal(e)
	}
	jkt, _ := identity.PublicJWK(&key.PublicKey).Thumbprint()
	id := random()
	hash := identity.Hash([]byte("synthetic-invitation-complete"))
	call := func(owner, jkt, device, id, hash string) (Session, error) {
		t.Helper()
		tx, e := fixtureAPI.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		value, _, e := f.store.InvitedSession(ctx, tx, owner, jkt, device, id, hash, f.now)
		if e == nil {
			e = tx.Commit()
		}
		return value, e
	}
	first, e := call(owner, jkt, previous.DeviceID, id, hash)
	if e != nil {
		t.Fatal(e)
	}
	again, e := call(owner, jkt, previous.DeviceID, id, hash)
	if e != nil || first != again {
		t.Fatal("lost invited session reply", e)
	}
	if _, e = call(owner, jkt, previous.DeviceID, random(), hash); !errors.Is(e, ErrConflict) {
		t.Fatal("second live session minted", e)
	}
	if _, e = call(owner, identity.Hash([]byte("wrong-key")), previous.DeviceID, id, hash); !errors.Is(e, ErrDenied) {
		t.Fatal("wrong invited key", e)
	}
	if _, e = call(owner, jkt, previous.DeviceID, "invalid", hash); !errors.Is(e, ErrDenied) {
		t.Fatal("invalid request identity", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_sessions SET generation=generation+1 WHERE device=$1 AND active`, previous.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e = call(owner, jkt, previous.DeviceID, id, hash); !errors.Is(e, ErrConflict) {
		t.Fatal("old cached generation returned", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_devices SET active=false WHERE id=$1`, previous.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e = call(owner, jkt, previous.DeviceID, id, hash); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked cached reply", e)
	}
}

type invitationDispatch struct {
	calls int
	err   error
}

func (d *invitationDispatch) Dispatch(context.Context, string, []byte, string, time.Time) (any, error) {
	d.calls++
	return map[string]string{"state": "pending_approval"}, d.err
}
func TestSQLInvitationHTTPUsesExistingAdmissionAndNoBearerAuthority(t *testing.T) {
	f := newFixture(t, 2)
	handler := &invitationDispatch{}
	f.api.Invitations = handler
	for _, path := range []string{"claim", "status", "complete", "abandon"} {
		r := httptest.NewRequest("POST", f.origin+"/v1/invitations/"+path, bytes.NewReader([]byte(`{}`)))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("DPoP", "synthetic-proof")
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("configured invitation handler not called", w.Code)
		}
	}
	handler.err = ErrPending
	r := httptest.NewRequest("POST", f.origin+"/v1/invitations/complete", bytes.NewReader([]byte(`{}`)))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("DPoP", "synthetic-proof")
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	if w.Code != 202 {
		t.Fatal("pending handler response", w.Code)
	}
	r.Header.Set("Authorization", "DPoP unwanted")
	w = httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	if w.Code != 401 || handler.calls != 5 {
		t.Fatal("bearer changed invitation authority", w.Code)
	}
}
func TestSQLOIDCEnrollmentCountsReservedInvitationSeats(t *testing.T) {
	f := newFixture(t, 2)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := f.token(key)
	body, _ := json.Marshal(Request{random(), identity.PublicJWK(&key.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}})
	f.store.Reservations = func(context.Context, *sql.Tx, string, time.Time) (int, error) { return 2, nil }
	r := f.call(t, key, "POST", "/v1/devices/enroll", token, "", body)
	if r.Code != 401 {
		t.Fatal("initial challenge", r.Code)
	}
	nonce := r.Header().Get("DPoP-Nonce")
	r = f.call(t, key, "POST", "/v1/devices/enroll", token, nonce, body)
	if r.Code != 403 {
		t.Fatal("reservation quota bypass", r.Code)
	}
	f.store.Reservations = func(context.Context, *sql.Tx, string, time.Time) (int, error) { return 0, ErrUnavailable }
	r = f.call(t, key, "POST", "/v1/devices/enroll", token, nonce, body)
	if r.Code != 503 {
		t.Fatal("unavailable reservation count admitted registration", r.Code)
	}
}
