//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func changedEnrollment(t *testing.T, f *fixture, k *ecdsa.PrivateKey, raw []byte, want int) {
	t.Helper()
	token := f.token(k)
	r := f.call(t, k, "POST", "/v1/devices/enroll", token, "", raw)
	expect(t, r, 401)
	nonce := r.Header().Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("missing fresh nonce")
	}
	expect(t, f.call(t, k, "POST", "/v1/devices/enroll", token, nonce, raw), want)
}

func TestApprovedRequestAndReceiptSurviveReauthenticationAndPolicyRenewal(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	first, raw, _ := f.register(t, k)
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	var original, receipt []byte
	if e := fixtureOwner.QueryRow(`SELECT request_body,receipt FROM identity_devices WHERE id=$1 AND approved`, first.DeviceID).Scan(&original, &receipt); e != nil || !bytes.Equal(raw, original) {
		t.Fatal("initial evidence", e)
	}
	second, fresh, _ := f.register(t, k)
	if first.DeviceID != second.DeviceID || first.AccessToken == second.AccessToken || bytes.Equal(fresh, original) {
		t.Fatal("reauthentication did not create a fresh session on the same device")
	}
	var retained, retainedReceipt []byte
	if e := fixtureOwner.QueryRow(`SELECT request_body,receipt FROM identity_devices WHERE id=$1`, first.DeviceID).Scan(&retained, &retainedReceipt); e != nil || !bytes.Equal(retained, original) || !bytes.Equal(retainedReceipt, receipt) {
		t.Fatal("API replaced approved evidence", e)
	}
	// Equivalent capability ordering is not an upgrade. Preserve original bytes.
	var request Request
	json.Unmarshal(fresh, &request)
	request.RequestID = random()
	request.Capabilities[0], request.Capabilities[2] = request.Capabilities[2], request.Capabilities[0]
	reordered, _ := json.Marshal(request)
	changedEnrollment(t, f, k, reordered, 200)
	for _, mutation := range []string{`request_body='{}'`, `receipt='changed'`, `request_body=request_body||' '`} {
		if _, e := fixtureAPI.Exec(`UPDATE identity_devices SET `+mutation+` WHERE id=$1`, first.DeviceID); e == nil {
			t.Fatal("approved evidence remained API-writeable", mutation)
		}
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET refresh_after=0 WHERE id=$1`, first.DeviceID); e != nil {
		t.Fatal(e)
	}
	if e := f.publisher().RunOnce(context.Background(), f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var revision int64
	if e := fixtureOwner.QueryRow(`SELECT request_body,receipt,revision FROM identity_devices WHERE id=$1`, first.DeviceID).Scan(&retained, &retainedReceipt, &revision); e != nil || revision != 2 || !bytes.Equal(retained, original) || !bytes.Equal(retainedReceipt, receipt) {
		t.Fatal("renewal lost independent evidence", e, revision)
	}
}

func TestApprovedCapabilitiesCannotBeUpgradedThroughFreshApiEnrollment(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	session, original, _ := f.register(t, k)
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	var request Request
	json.Unmarshal(original, &request)
	request.RequestID = random()
	request.Capabilities = append(request.Capabilities, "overlay.credentials.v1")
	changed, _ := json.Marshal(request)
	changedEnrollment(t, f, k, changed, 409)
	var stored []byte
	var revision, activeSessions int64
	if e := fixtureOwner.QueryRow(`SELECT request_body,revision,(SELECT count(*) FROM identity_sessions WHERE device=$1 AND active) FROM identity_devices WHERE id=$1`, session.DeviceID).Scan(&stored, &revision, &activeSessions); e != nil || !bytes.Equal(stored, original) || revision != 1 || activeSessions != 1 {
		t.Fatal("denied capability change had side effects", e)
	}
	// The existing session and signed policy remain usable after the conflict.
	expect(t, f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil), 200)
}

func TestPendingEnrollmentCanRefreshEvidenceButMalformedApprovedEvidenceFailsClosed(t *testing.T) {
	f := newFixture(t, 1)
	k := key(t)
	session, original, _ := f.register(t, k)
	var request Request
	json.Unmarshal(original, &request)
	request.RequestID = random()
	request.Capabilities = append(request.Capabilities, "overlay.credentials.v1")
	changed, _ := json.Marshal(request)
	changedEnrollment(t, f, k, changed, 200)
	var stored []byte
	if e := fixtureOwner.QueryRow(`SELECT request_body FROM identity_devices WHERE id=$1 AND NOT approved`, session.DeviceID).Scan(&stored); e != nil || !bytes.Equal(stored, changed) {
		t.Fatal("pending fresh receipt not stored", e)
	}
	// Owner-only corruption fixture, before approval. An API session cannot
	// repair an invalid trusted row by inventing new approved evidence.
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET request_body=$2,approved=true WHERE id=$1`, session.DeviceID, []byte(`[]`)); e != nil {
		t.Fatal(e)
	}
	request.RequestID = random()
	request.Key = identity.PublicJWK(&k.PublicKey)
	changed, _ = json.Marshal(request)
	changedEnrollment(t, f, k, changed, 403)
	if e := fixtureOwner.QueryRow(`SELECT request_body FROM identity_devices WHERE id=$1`, session.DeviceID).Scan(&stored); e != nil || string(stored) != "[]" {
		t.Fatal("malformed evidence was adopted", e)
	}
}
