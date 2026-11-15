//go:build postgres

package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func runtimeBody(r RuntimeObservation) []byte { raw, _ := json.Marshal(r); return raw }

func TestRuntimeObservationRequiresTheBoundLiveDeviceAndPreservesPublication(t *testing.T) {
	f := newFixture(t, 1)
	f.api.Clock = func() time.Time { return f.now }
	k := key(t)
	session, _, _ := f.register(t, k)
	r := RuntimeObservation{Version: 1, Sequence: 1, Build: 74, Phase: "online", PolicyRevision: 1, EngineKnown: true, EngineActive: true, Network: "wifi", SampledAtMs: f.now.UnixMilli()}
	post := func(raw []byte, status int) {
		t.Helper()
		expect(t, f.call(t, k, "POST", runtimeObservationPath, session.AccessToken, session.Nonce, raw), status)
	}
	post(runtimeBody(r), http.StatusForbidden)
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	publication := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, publication, http.StatusOK)
	raw := runtimeBody(r)
	expect(t, f.call(t, key(t), "POST", runtimeObservationPath, session.AccessToken, session.Nonce, raw), http.StatusForbidden)
	expect(t, f.call(t, k, "POST", runtimeObservationPath, session.AccessToken, "wrong", raw), http.StatusUnauthorized)
	proof := signed(t, k, "POST", f.origin+runtimeObservationPath, session.AccessToken, session.Nonce, raw, f.now)
	changed := r
	changed.Phase, changed.EngineActive = "off", false
	expect(t, f.rawCall("POST", runtimeObservationPath, session.AccessToken, proof, runtimeBody(changed)), http.StatusUnauthorized)
	expect(t, f.rawCall("POST", runtimeObservationPath, session.AccessToken, proof, raw), http.StatusNoContent)
	expect(t, f.rawCall("POST", runtimeObservationPath, session.AccessToken, proof, raw), http.StatusUnauthorized)
	var first int64
	if e := fixtureOwner.QueryRow(`SELECT received_at_ms FROM identity_runtime_observations WHERE device=$1`, session.DeviceID).Scan(&first); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(time.Second)
	post(raw, http.StatusNoContent)
	var repeated int64
	if e := fixtureOwner.QueryRow(`SELECT received_at_ms FROM identity_runtime_observations WHERE device=$1`, session.DeviceID).Scan(&repeated); e != nil || first != repeated {
		t.Fatal("acknowledgement renewed observation time", e)
	}
	post(runtimeBody(changed), http.StatusConflict)
	r.Sequence++
	r.SampledAtMs = f.now.UnixMilli()
	limited := f.call(t, k, "POST", runtimeObservationPath, session.AccessToken, session.Nonce, runtimeBody(r))
	expect(t, limited, http.StatusTooManyRequests)
	if limited.Header().Get("Retry-After") != "30" {
		t.Fatal("missing bounded retry")
	}
	f.now = f.now.Add(31 * time.Second)
	r.SampledAtMs = f.now.UnixMilli()
	post(runtimeBody(r), http.StatusNoContent)
	post(raw, http.StatusConflict)
	if _, e := fixturePublisher.Exec(`UPDATE identity_runtime_observations SET phase='unknown'`); e == nil {
		t.Fatal("publisher acquired observation mutation")
	}
	current := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
	expect(t, current, http.StatusOK)
	if current.Body.String() != publication.Body.String() {
		t.Fatal("observation changed signed policy")
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET active=false WHERE id=$1`, session.DeviceID); e != nil {
		t.Fatal(e)
	}
	post(runtimeBody(r), http.StatusForbidden)
}

func TestRuntimeObservationRejectsOldAndFutureSamplesAndRollsBackAWriteFailure(t *testing.T) {
	f := newFixture(t, 1)
	f.api.Clock = func() time.Time { return f.now }
	k := key(t)
	session, _, _ := f.register(t, k)
	if e := f.publisher().RunOnce(context.Background(), f.now); e != nil {
		t.Fatal(e)
	}
	r := RuntimeObservation{Version: 1, Sequence: 1, Build: 74, Phase: "off", EngineKnown: true, Network: "none", SampledAtMs: f.now.UnixMilli()}
	for _, delta := range []int64{-120001, 60000} {
		bad := r
		bad.SampledAtMs += delta
		expect(t, f.call(t, k, "POST", runtimeObservationPath, session.AccessToken, session.Nonce, runtimeBody(bad)), http.StatusConflict)
	}
	if _, e := fixtureOwner.Exec(`CREATE FUNCTION fixture_runtime_write_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic observation failure'; END $$; CREATE TRIGGER fixture_runtime_failure BEFORE INSERT ON identity_runtime_observations FOR EACH ROW EXECUTE FUNCTION fixture_runtime_write_failure()`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		fixtureOwner.Exec(`DROP TRIGGER IF EXISTS fixture_runtime_failure ON identity_runtime_observations; DROP FUNCTION IF EXISTS fixture_runtime_write_failure()`)
	})
	raw := runtimeBody(r)
	proof := signed(t, k, "POST", f.origin+runtimeObservationPath, session.AccessToken, session.Nonce, raw, f.now)
	expect(t, f.rawCall("POST", runtimeObservationPath, session.AccessToken, proof, raw), http.StatusServiceUnavailable)
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_runtime_observations`).Scan(&count); e != nil || count != 0 {
		t.Fatal("failed write escaped transaction", e)
	}
	if _, e := fixtureOwner.Exec(`DROP TRIGGER fixture_runtime_failure ON identity_runtime_observations`); e != nil {
		t.Fatal(e)
	}
	expect(t, f.rawCall("POST", runtimeObservationPath, session.AccessToken, proof, raw), http.StatusNoContent)
	// This old exact acknowledgement succeeds without manufacturing a new sample.
	f.now = f.now.Add(121 * time.Second)
	expect(t, f.call(t, k, "POST", runtimeObservationPath, session.AccessToken, session.Nonce, raw), http.StatusNoContent)
	if _, e := fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false`); e != nil {
		t.Fatal(e)
	}
	expect(t, f.call(t, k, "POST", runtimeObservationPath, session.AccessToken, session.Nonce, raw), http.StatusForbidden)
}
