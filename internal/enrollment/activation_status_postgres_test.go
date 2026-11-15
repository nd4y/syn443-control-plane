//go:build postgres

package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func activationBody(t *testing.T, report ActivationReport) []byte {
	t.Helper()
	raw, e := json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestActivationReportRequiresCurrentPublicationAndBoundProof(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	session, _, _ := f.register(t, k)
	post := func(report ActivationReport, status int) {
		t.Helper()
		expect(t, f.call(t, k, "POST", activationStatusPath, session.AccessToken, session.Nonce, activationBody(t, report)), status)
	}
	report := ActivationReport{Version: 1, PolicyRevision: 1, EnvelopeHash: identity.Hash([]byte("synthetic envelope")), ActivationGeneration: 3, Outcome: "committed", ActivePolicyRevision: 1}
	post(report, http.StatusForbidden)
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	publication := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, publication, http.StatusOK)
	post(report, http.StatusConflict)
	report.EnvelopeHash = identity.Hash(publication.Body.Bytes())
	raw := activationBody(t, report)
	expect(t, f.call(t, key(t), "POST", activationStatusPath, session.AccessToken, session.Nonce, raw), http.StatusForbidden)
	expect(t, f.call(t, k, "POST", activationStatusPath, session.AccessToken, "invalid", raw), http.StatusUnauthorized)
	proof := signed(t, k, "POST", f.origin+activationStatusPath, session.AccessToken, session.Nonce, raw, f.now)
	changed := report
	changed.Outcome = "degraded"
	expect(t, f.rawCall("POST", activationStatusPath, session.AccessToken, proof, activationBody(t, changed)), http.StatusUnauthorized)
	expect(t, f.rawCall("POST", activationStatusPath, session.AccessToken, proof, raw), http.StatusNoContent)
	expect(t, f.rawCall("POST", activationStatusPath, session.AccessToken, proof, raw), http.StatusUnauthorized)
	post(report, http.StatusNoContent)
	post(changed, http.StatusConflict)
	changed.ActivePolicyRevision = 0
	post(changed, http.StatusUnauthorized)
	var revision, received int64
	var outcome string
	if e := fixtureOwner.QueryRow(`SELECT policy_revision,outcome,received_at_ms FROM identity_policy_activation WHERE device=$1`, session.DeviceID).Scan(&revision, &outcome, &received); e != nil || revision != 1 || outcome != "committed" || received != f.now.UnixMilli() {
		t.Fatal("activation readback mismatch", e)
	}
	if _, e := fixturePublisher.Exec(`UPDATE identity_policy_activation SET outcome='degraded'`); e == nil {
		t.Fatal("publisher acquired device-report mutation")
	}
}

func TestActivationRollbackReportsPreviousActiveRevisionWithoutChangingDesiredPolicy(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	session, _, _ := f.register(t, k)
	ctx := context.Background()
	if e := f.publisher().RunOnce(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	first := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, first, http.StatusOK)
	firstReport := ActivationReport{Version: 1, PolicyRevision: 1, EnvelopeHash: identity.Hash(first.Body.Bytes()), ActivationGeneration: 1, Outcome: "committed", ActivePolicyRevision: 1}
	expect(t, f.call(t, k, "POST", activationStatusPath, session.AccessToken, session.Nonce, activationBody(t, firstReport)), http.StatusNoContent)
	if _, e := fixturePublisher.Exec(`UPDATE identity_devices SET refresh_after=0 WHERE id=$1`, session.DeviceID); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(time.Second)
	f.api.Clock = func() time.Time { return f.now }
	if e := f.publisher().RunOnce(ctx, f.now); e != nil {
		t.Fatal(e)
	}
	second := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, second, http.StatusOK)
	if first.Body.String() == second.Body.String() {
		t.Fatal("test did not publish a newer policy")
	}
	expect(t, f.call(t, k, "POST", activationStatusPath, session.AccessToken, session.Nonce, activationBody(t, firstReport)), http.StatusConflict)
	rollback := ActivationReport{Version: 1, PolicyRevision: 2, EnvelopeHash: identity.Hash(second.Body.Bytes()), ActivationGeneration: 2, Outcome: "rolled_back", ActivePolicyRevision: 1}
	expect(t, f.call(t, k, "POST", activationStatusPath, session.AccessToken, session.Nonce, activationBody(t, rollback)), http.StatusNoContent)
	var desired, reported, active int64
	var outcome string
	if e := fixtureOwner.QueryRow(`SELECT d.revision,r.policy_revision,r.active_policy_revision,r.outcome FROM identity_devices d JOIN identity_policy_activation r ON r.device=d.id WHERE d.id=$1`, session.DeviceID).Scan(&desired, &reported, &active, &outcome); e != nil || desired != 2 || reported != 2 || active != 1 || outcome != "rolled_back" {
		t.Fatal("rollback report altered the desired policy", e)
	}
	current := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, current, http.StatusOK)
	if current.Body.String() != second.Body.String() {
		t.Fatal("report rewrote signed policy")
	}
}
