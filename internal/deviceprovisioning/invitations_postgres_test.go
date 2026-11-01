//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto/ecdsa"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

func (f *fixture) bridge(t *testing.T) (*Invitations, enrollment.Grant, *enrollment.Store) {
	t.Helper()
	g := f.grantConfig(t)
	store, e := enrollment.NewStore(fixtureSigner, bytes.Repeat([]byte{62}, 32))
	if e != nil {
		t.Fatal(e)
	}
	api, e := enrollment.NewStore(fixtureDevice, bytes.Repeat([]byte{62}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return &Invitations{Identity: store, Invitations: f.signer, Verification: f.verification(), Grants: map[string]enrollment.Grant{f.owner: g}}, g, api
}
func (f *fixture) approved(t *testing.T) invitation.ClaimState {
	t.Helper()
	state, _ := f.claim(t, f.issue(t))
	thumb, _ := identity.PublicJWK(&f.phone.PublicKey).Thumbprint()
	if _, e := f.adminCall(t, "invite.approve", invitation.Approval{ID: state.ID, Version: state.Version, Thumbprint: thumb, PairCode: state.PairCode}); e != nil {
		t.Fatal(e)
	}
	return state
}
func (f *fixture) deviceCall(t *testing.T, store *enrollment.Store, path string, state invitation.ClaimState, id string) ([]byte, int) {
	t.Helper()
	roots := map[string]*ecdsa.PublicKey{"fixture-root": &f.key.PublicKey}
	api, e := enrollment.NewAPI(store, f.v, "https://api.example.invalid", roots, false)
	if e != nil {
		t.Fatal(e)
	}
	api.Clock = func() time.Time { return f.now }
	api.Invitations = &invitation.DeviceService{Store: f.device, Identity: store, Origin: "https://api.example.invalid", ServiceID: "service-a"}
	body, _ := json.Marshal(invitation.DeviceRequest{ID: state.ID, RequestID: id})
	proof := signed(t, f.phone, "https://api.example.invalid"+path, "", state.Nonce, body, f.now)
	request := httptest.NewRequest("POST", "https://api.example.invalid"+path, bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("DPoP", proof)
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	return response.Body.Bytes(), response.Code
}
func TestSQLInvitationToPublisherToNormalSessionAndCancellation(t *testing.T) {
	f := newFixture(t)
	bridge, g, api := f.bridge(t)
	ctx := context.Background()
	state := f.approved(t)
	id, _ := random()
	if _, code := f.deviceCall(t, api, "/v1/invitations/complete", state, id); code != 202 {
		t.Fatal("session before device publication", code)
	}
	if e := bridge.Prepare(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	// A prepared identity is still unapproved and cannot authenticate.
	if _, code := f.deviceCall(t, api, "/v1/invitations/complete", state, id); code != 202 {
		t.Fatal("prepared device treated as signed", code)
	}
	if e := bridge.Prepare(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	var devices, sessions int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_devices`).Scan(&devices); e != nil || devices != 1 {
		t.Fatal("nonidempotent device creation", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_sessions`).Scan(&sessions); e != nil || sessions != 0 {
		t.Fatal("preapproval session", e)
	}
	p := enrollment.Publisher{Store: bridge.Identity, Verifier: f.v, Grants: bridge.Grants, Key: f.key, KeyID: "fixture-root", Origin: "https://api.example.invalid", InvitationApproval: bridge}
	if e := p.RunOnce(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	body, code := f.deviceCall(t, api, "/v1/invitations/complete", state, id)
	if code != 200 {
		t.Fatal("approved completion", code, string(body))
	}
	var completed invitation.Completion
	if json.Unmarshal(body, &completed) != nil {
		t.Fatal("completion schema")
	}
	value := completed.Session
	if len(completed.OwnerTag) != 43 || value.DeviceID == "" || len(value.AccessToken) != 43 {
		t.Fatal("normal session not returned")
	}
	again, code := f.deviceCall(t, api, "/v1/invitations/complete", state, id)
	if code != 200 || !bytes.Equal(again, body) {
		t.Fatal("lost completion reply changed session", code)
	}
	binding, e := api.Lookup(ctx, value.AccessToken, false)
	if e != nil || binding.Device != value.DeviceID || binding.Owner != enrollment.Owner(g.Issuer, g.Subject) {
		t.Fatal("session did not converge on ordinary API", e)
	}
	statusID, _ := random()
	status, code := f.deviceCall(t, api, "/v1/invitations/status", state, statusID)
	if code != 200 || !bytes.Contains(status, []byte(`"state":"completed"`)) {
		t.Fatal("completion readback", code)
	}
	otherID, _ := random()
	if _, code = f.deviceCall(t, api, "/v1/invitations/complete", state, otherID); code != 409 {
		t.Fatal("one invitation issued two sessions", code)
	}
	if _, code = f.deviceCall(t, api, "/v1/invitations/abandon", state, otherID); code != 200 {
		t.Fatal("cancel captured identity", code)
	}
	binding, e = api.Lookup(ctx, value.AccessToken, false)
	if e != nil || binding.Active {
		t.Fatal("cancelled device still active", e)
	}
	if _, code = f.deviceCall(t, api, "/v1/invitations/complete", state, id); code != 403 {
		t.Fatal("revocation resurrected cached session", code)
	}
	if _, code = f.deviceCall(t, api, "/v1/invitations/abandon", state, otherID); code != 200 {
		t.Fatal("lost cancellation reply", code)
	}
}
func TestSQLPublisherRechecksRevocationAndFailureBackoff(t *testing.T) {
	f := newFixture(t)
	bridge, _, _ := f.bridge(t)
	ctx := context.Background()
	state := f.approved(t)
	// A missing grant is recorded without blocking the next scheduler cycle.
	saved := bridge.Grants
	bridge.Grants = nil
	if e := bridge.Prepare(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	pending, e := f.signer.Pending(ctx, f.now)
	if e != nil || len(pending) != 0 {
		t.Fatal("failed item starved queue", e)
	}
	bridge.Grants = saved
	if e = bridge.Prepare(ctx, f.now.Add(31*time.Second)); e != nil {
		t.Fatal(e)
	}
	publication, e := f.signer.Ready(ctx, state.ID, f.verification(), f.now)
	if e != nil || publication.Device == "" {
		t.Fatal("prepared invitation receipt", e)
	}
	input := enrollment.ApprovalInput{Device: publication.Device, Owner: publication.Owner, Thumbprint: publication.Thumbprint, GrantHash: publication.GrantHash, InvitationID: publication.ID, Request: publication.Enrollment}
	fence, e := bridge.Verify(ctx, input, f.now)
	if e != nil || fence == nil {
		t.Fatal(e)
	}
	changed := input
	changed.Request = []byte(`{}`)
	if _, e = bridge.Verify(ctx, changed, f.now); e == nil {
		t.Fatal("modified enrollment reached signer")
	}
	if _, e = f.adminCall(t, "invite.revoke", invitation.Mutation{ID: state.ID, Version: publication.Version}); e != nil {
		t.Fatal(e)
	}
	tx, e := fixtureSigner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = fence.Lock(ctx, tx, f.now); !errors.Is(e, invitation.ErrConflict) {
		t.Fatal("late revoke reached publication", e)
	}
}
func TestSQLPublisherUnconfiguredAndDeviceHTTPBounds(t *testing.T) {
	ctx := context.Background()
	if e := (&Invitations{}).Prepare(ctx, time.Now()); !errors.Is(e, invitation.ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e := (&Invitations{}).Verify(ctx, enrollment.ApprovalInput{}, time.Now()); !errors.Is(e, identity.ErrInvalid) {
		t.Fatal(e)
	}
	f := newFixture(t)
	_, _, store := f.bridge(t)
	state := f.approved(t)
	api, e := enrollment.NewAPI(store, f.v, "https://api.example.invalid", map[string]*ecdsa.PublicKey{"fixture": &f.key.PublicKey}, false)
	if e != nil {
		t.Fatal(e)
	}
	api.Clock = func() time.Time { return f.now }
	api.Invitations = &invitation.DeviceService{Store: f.device, Identity: store, Origin: "https://api.example.invalid", ServiceID: "service-a"}
	for _, item := range []struct{ method, path, body, origin, auth string }{
		{"POST", "/v1/invitations/status", `{}`, "https://evil.example.invalid", ""},
		{"POST", "/v1/invitations/status", strings.Repeat("x", 8193), "", ""},
		{"POST", "/v1/invitations/status", `{}`, "", "DPoP unwanted"},
		{"GET", "/v1/invitations/status", ``, "", ""},
		{"POST", "/v1/invitations/status?code=untrusted", `{}`, "", ""},
	} {
		r := httptest.NewRequest(item.method, "https://api.example.invalid"+item.path, strings.NewReader(item.body))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("DPoP", "invalid")
		if item.origin != "" {
			r.Header.Set("Origin", item.origin)
		}
		if item.auth != "" {
			r.Header.Set("Authorization", item.auth)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("invalid invitation HTTP accepted", w.Code)
		}
	}
	_ = state
}

func TestSQLUnsupportedCapabilitiesAndQuotaFailWithoutPartialDevice(t *testing.T) {
	f := newFixture(t)
	bridge, g, _ := f.bridge(t)
	ctx := context.Background()
	g.Template.RequiredCapabilities = append(g.Template.RequiredCapabilities, "netbird.direct")
	if e := enrollment.Authorize(ctx, fixtureOwner, g, f.now); e != nil {
		t.Fatal(e)
	}
	f.grant = g.Hash()
	bridge.Grants[f.owner] = g
	state := f.approved(t)
	if e := bridge.Prepare(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	var code string
	var count int
	if e := fixtureOwner.QueryRow(`SELECT publication_error FROM managed_invitations WHERE id=$1`, state.ID).Scan(&code); e != nil || code != "unsupported_capabilities" {
		t.Fatal("unsupported capabilities not isolated", e)
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_devices`).Scan(&count); e != nil || count != 0 {
		t.Fatal("unsupported device inserted", e)
	}
	publication, e := f.signer.Ready(ctx, state.ID, f.verification(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	// Exercise the final quota guard, independently of the earlier reservation.
	for n := 0; n < 2; n++ {
		device, _ := random()
		jkt, _ := random()
		if _, e = fixtureOwner.Exec(`INSERT INTO identity_devices(id,owner,jkt,request_body,receipt) VALUES($1,$2,$3,$4,$5)`, device, f.owner, jkt, []byte(`{}`), []byte("synthetic-receipt")); e != nil {
			t.Fatal(e)
		}
	}
	if e = bridge.createDevice(ctx, publication, g, f.now); !errors.Is(e, invitation.ErrDenied) {
		t.Fatal("final quota ignored", e)
	}
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_devices`).Scan(&count); e != nil || count != 2 {
		t.Fatal("failed transaction leaked device", e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if e = bridge.Prepare(cancelled, f.now); e == nil {
		t.Fatal("cancelled worker acknowledged work")
	}
}
