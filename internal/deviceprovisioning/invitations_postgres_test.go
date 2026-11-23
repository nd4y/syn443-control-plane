//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	f.approve(t, state)
	return state
}

func (f *fixture) approve(t *testing.T, state invitation.ClaimState) {
	t.Helper()
	thumb, _ := identity.PublicJWK(&f.phone.PublicKey).Thumbprint()
	if _, e := f.adminCall(t, "invite.approve", invitation.Approval{ID: state.ID, Version: state.Version, Thumbprint: thumb, PairCode: state.PairCode}); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) invitationAPI(t *testing.T, store *enrollment.Store) *enrollment.API {
	t.Helper()
	roots := map[string]*ecdsa.PublicKey{"fixture-root": &f.key.PublicKey}
	api, e := enrollment.NewAPI(store, f.v, "https://api.example.invalid", roots, false)
	if e != nil {
		t.Fatal(e)
	}
	api.Clock = func() time.Time { return f.now }
	api.Invitations = &invitation.DeviceService{Store: f.device, Identity: store, Origin: "https://api.example.invalid", ServiceID: "service-a"}
	return api
}

func (f *fixture) deviceCall(t *testing.T, store *enrollment.Store, path string, state invitation.ClaimState, id string) ([]byte, int) {
	t.Helper()
	api := f.invitationAPI(t, store)
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

// Close the actual TLS connection after the real API has committed, before
// sending its first response. Retry the same body with a new DPoP proof.
func (f *fixture) retryAfterDroppedInvitationReply(t *testing.T, api *enrollment.API, path, nonce string, body []byte) []byte {
	t.Helper()
	committed := make(chan *httptest.ResponseRecorder, 1)
	var dropped atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !dropped.CompareAndSwap(false, true) {
			api.ServeHTTP(w, request)
			return
		}
		reply := httptest.NewRecorder()
		api.ServeHTTP(reply, request)
		committed <- reply
		panic(http.ErrAbortHandler)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 12 * time.Second
	send := func() (*http.Response, error) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal("invitation TLS fixture request", err)
		}
		request.Close = true
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("DPoP", signed(t, f.phone, api.Origin+path, "", nonce, body, f.now))
		return client.Do(request)
	}
	response, err := send()
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("expected TLS connection to close before the first HTTP response")
	}
	var first *httptest.ResponseRecorder
	select {
	case first = <-committed:
	default:
		t.Fatal("connection closed before the real handler finished")
	}
	if first.Code != http.StatusOK {
		t.Fatal("first request did not commit before its response was dropped", first.Code)
	}
	response, err = send()
	if err != nil {
		t.Fatal("invitation retry transport failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || response.StatusCode != http.StatusOK || len(data) > 8192 || !bytes.Equal(data, first.Body.Bytes()) {
		t.Fatal("retry changed the committed invitation response", response.StatusCode)
	}
	return data
}

func TestSQLInvitationToPublisherToNormalSessionAndCancellation(t *testing.T) {
	f := newFixture(t)
	bridge, g, api := f.bridge(t)
	ctx := context.Background()
	deviceAPI := f.invitationAPI(t, api)
	origin, claim := f.decodeClaim(t, f.issue(t))
	if origin != deviceAPI.Origin {
		t.Fatal("signed invitation and server origin differ")
	}
	claimReply := f.retryAfterDroppedInvitationReply(t, deviceAPI, "/v1/invitations/claim", "", claim)
	var state invitation.ClaimState
	if json.Unmarshal(claimReply, &state) != nil || state.State != "pending_approval" || state.Version != 2 {
		t.Fatal("lost claim response changed the invitation reservation")
	}
	f.approve(t, state)
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
	finish, _ := json.Marshal(invitation.DeviceRequest{ID: state.ID, RequestID: id})
	body := f.retryAfterDroppedInvitationReply(t, deviceAPI, "/v1/invitations/complete", state.Nonce, finish)
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_sessions`).Scan(&sessions); e != nil || sessions != 1 {
		t.Fatal("completion retry created more than one session", e)
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
	// Initial time is public, bounded and service-bound; no code/key/token is sent.
	for _, item := range []struct {
		method, body, origin string
		expected             int
	}{{"GET", "", "", 200}, {"GET", "x", "", 401}, {"GET", "", "https://evil.example.invalid", 401}, {"POST", "", "", 404}} {
		r := httptest.NewRequest(item.method, "https://api.example.invalid/v1/invitations/time", strings.NewReader(item.body))
		r.RemoteAddr = "127.0.0.1:12345"
		if item.origin != "" {
			r.Header.Set("Origin", item.origin)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		if w.Code != item.expected {
			t.Fatal("time service boundary", w.Code)
		}
		if w.Code == 200 && (!bytes.Contains(w.Body.Bytes(), []byte(`"serviceId":"service-a"`)) || w.Header().Get("Date") == "" || bytes.Contains(w.Body.Bytes(), []byte("Token"))) {
			t.Fatal("public time leaked authority")
		}
	}
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

func TestSQLExistingKeyCannotBeReassignedByInvitation(t *testing.T) {
	f := newFixture(t)
	bridge, g, _ := f.bridge(t)
	ctx := context.Background()
	state := f.approved(t)
	p, e := f.signer.Ready(ctx, state.ID, f.verification(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	device, _ := random()
	if _, e = fixtureOwner.Exec(`INSERT INTO identity_devices(id,owner,jkt,request_body,receipt) VALUES($1,$2,$3,$4,$5)`, device, f.owner, p.Thumbprint, []byte(`{}`), []byte("synthetic-existing-identity")); e != nil {
		t.Fatal(e)
	}
	if e = bridge.createDevice(ctx, p, g, f.now); !errors.Is(e, invitation.ErrDenied) {
		t.Fatal("invitation reassigned an existing key", e)
	}
	var stored string
	if e = fixtureOwner.QueryRow(`SELECT id FROM identity_devices WHERE jkt=$1`, p.Thumbprint).Scan(&stored); e != nil || stored != device {
		t.Fatal("preexisting key changed", e)
	}
	p.Owner = identity.Hash([]byte("foreign-owner"))
	if e = bridge.createDevice(ctx, p, g, f.now); !errors.Is(e, invitation.ErrDenied) {
		t.Fatal("foreign owner accepted", e)
	}
}
