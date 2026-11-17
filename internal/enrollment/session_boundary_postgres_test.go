//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const refreshBoundaryPath = "/v1/device/session/refresh"

// The owner configures only the fixture account. Registration and every
// refresh use the restricted API role and the ordinary signed proof path.
func newRefreshBoundaryFixture(t *testing.T) (*fixture, *ecdsa.PrivateKey, Session) {
	t.Helper()
	f := newFixture(t, 1)
	f.grant.Until = f.now.Add(48 * time.Hour).Unix()
	if err := Authorize(context.Background(), fixtureOwner, f.grant, f.now); err != nil {
		t.Fatal(err)
	}
	f.api.Clock = func() time.Time { return f.now }
	var role string
	if err := f.store.DB.QueryRowContext(context.Background(), `SELECT current_user`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if f.store.DB != fixtureAPI || role != "syn443_identity_api" {
		t.Fatal("refresh fixture must use the restricted API role")
	}
	k := key(t)
	session, _, _ := f.register(t, k)
	if session.RefreshUntilMs != f.now.Add(24*time.Hour).UnixMilli() || session.Generation != 0 {
		t.Fatal("fixture must start with the ordinary absolute 24-hour refresh family")
	}
	return f, k, session
}

func refreshBoundaryRequest(t *testing.T) (string, []byte) {
	t.Helper()
	id := random()
	body, err := json.Marshal(map[string]string{"requestId": id})
	if err != nil {
		t.Fatal(err)
	}
	return id, body
}

func refreshBoundarySession(t *testing.T, response *httptest.ResponseRecorder) Session {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("refresh status %d, expected 200", response.Code)
	}
	var next Session
	if err := identity.Decode(response.Body.Bytes(), &next, true); err != nil {
		t.Fatal("refresh response must retain the closed session shape")
	}
	return next
}

func requireRefreshBoundaryRotation(t *testing.T, old, next Session, accessUntilMs int64) {
	t.Helper()
	if next.DeviceID != old.DeviceID || next.Generation != old.Generation+1 ||
		next.AccessToken == old.AccessToken || next.RefreshToken == old.RefreshToken || next.Nonce == old.Nonce ||
		next.AccessToken == "" || next.RefreshToken == "" || next.Nonce == "" ||
		next.AccessUntilMs != accessUntilMs || next.RefreshUntilMs != old.RefreshUntilMs ||
		next.AccessUntilMs > next.RefreshUntilMs {
		t.Fatal("refresh must rotate once within the unchanged absolute family boundary")
	}
}

type refreshBoundaryState struct {
	accessHash, refreshHash, nonce string
	accessUntil, refreshUntil      int64
	generation                     int64
	active                         bool
	history, requests              int
}

func readRefreshBoundaryState(t *testing.T, f *fixture, device string) refreshBoundaryState {
	t.Helper()
	var state refreshBoundaryState
	err := f.store.DB.QueryRowContext(context.Background(), `SELECT access_hash,refresh_hash,nonce,access_until,refresh_until,generation,active,
 (SELECT count(*) FROM identity_refresh_history h WHERE h.session=s.id),
 (SELECT count(*) FROM identity_requests r WHERE r.session=s.id AND r.kind='refresh')
 FROM identity_sessions s WHERE device=$1`, device).Scan(&state.accessHash, &state.refreshHash, &state.nonce,
		&state.accessUntil, &state.refreshUntil, &state.generation, &state.active, &state.history, &state.requests)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func requireRefreshBoundaryStored(t *testing.T, f *fixture, next Session, history, requests int) {
	t.Helper()
	state := readRefreshBoundaryState(t, f, next.DeviceID)
	if state.accessHash != identity.Hash([]byte(next.AccessToken)) || state.refreshHash != identity.Hash([]byte(next.RefreshToken)) ||
		state.nonce != next.Nonce || state.accessUntil*1000 != next.AccessUntilMs || state.refreshUntil*1000 != next.RefreshUntilMs ||
		state.generation != next.Generation || !state.active || state.history != history || state.requests != requests {
		t.Fatal("stored session and bounded rotation history must match the returned generation")
	}
}

func TestRefreshBoundaryLastTenMinutesCapsAccessAtAbsoluteFamilyDeadline(t *testing.T) {
	for _, remaining := range []int64{1, 72, 528, 599, 600, 601} {
		t.Run(fmt.Sprintf("remaining_%d_seconds", remaining), func(t *testing.T) {
			f, k, original := newRefreshBoundaryFixture(t)
			f.now = time.Unix(original.RefreshUntilMs/1000-remaining, 0)
			_, body := refreshBoundaryRequest(t)
			next := refreshBoundarySession(t, f.call(t, k, "POST", refreshBoundaryPath, original.RefreshToken, original.Nonce, body))
			want := min(f.now.Unix()+600, original.RefreshUntilMs/1000) * 1000
			requireRefreshBoundaryRotation(t, original, next, want)
			if next.AccessUntilMs <= f.now.UnixMilli() {
				t.Fatal("a live family must retain its positive remaining access lifetime")
			}
			requireRefreshBoundaryStored(t, f, next, 2, 1)
		})
	}
}

func TestRefreshBoundaryUsesCurrentLockedDeadlineAfterLookupSnapshotBecomesStale(t *testing.T) {
	f, k, original := newRefreshBoundaryFixture(t)
	ctx := context.Background()
	stale, err := f.store.Lookup(ctx, original.RefreshToken, true)
	if err != nil {
		t.Fatal(err)
	}
	currentUntil := f.now.Unix() + 90
	// Owner-only fixture setup changes the live row after Lookup. Refresh must
	// use lockSession's current row, not the caller's older Binding snapshot.
	if _, err = fixtureOwner.ExecContext(ctx, `UPDATE identity_sessions SET refresh_until=$2 WHERE id=$1`, stale.Session, currentUntil); err != nil {
		t.Fatal(err)
	}
	if _, err = fixtureOwner.ExecContext(ctx, `UPDATE identity_refresh_history SET expires=$2 WHERE session=$1`, stale.Session, currentUntil); err != nil {
		t.Fatal(err)
	}
	if stale.RefreshUntil != original.RefreshUntilMs/1000 || stale.RefreshUntil == currentUntil {
		t.Fatal("fixture must retain a genuinely stale caller snapshot")
	}
	id, body := refreshBoundaryRequest(t)
	proof, err := identity.VerifyProof(signed(t, k, "POST", f.origin+refreshBoundaryPath, original.RefreshToken, original.Nonce, body, f.now), identity.ProofContext{
		Method: "POST", URI: f.origin + refreshBoundaryPath, Token: original.RefreshToken,
		Nonce: original.Nonce, BodyHash: identity.Hash(body), Now: f.now,
	})
	if err != nil {
		t.Fatal("fixture must pass actual signature, target, token, nonce and body verification")
	}
	next, err := f.store.Refresh(ctx, stale, original.RefreshToken, id, identity.Hash(body), proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	current := original
	current.RefreshUntilMs = currentUntil * 1000
	requireRefreshBoundaryRotation(t, current, next, currentUntil*1000)
	requireRefreshBoundaryStored(t, f, next, 2, 1)
}

func TestRefreshBoundaryShorterCurrentAccountStillCapsAccessWithoutRenewingFamily(t *testing.T) {
	f, k, original := newRefreshBoundaryFixture(t)
	accountUntil := f.now.Unix() + 45
	if _, err := fixtureOwner.ExecContext(context.Background(), `UPDATE identity_accounts SET valid_until=$2 WHERE owner=$1`, Owner(f.grant.Issuer, f.grant.Subject), accountUntil); err != nil {
		t.Fatal(err)
	}
	_, body := refreshBoundaryRequest(t)
	next := refreshBoundarySession(t, f.call(t, k, "POST", refreshBoundaryPath, original.RefreshToken, original.Nonce, body))
	requireRefreshBoundaryRotation(t, original, next, accountUntil*1000)
	requireRefreshBoundaryStored(t, f, next, 2, 1)
}

func TestRefreshBoundaryAtOrPastRefreshOrAccountDeadlineDeniesWithoutRotation(t *testing.T) {
	for _, kind := range []string{"refresh", "account"} {
		for _, offset := range []int64{0, -1} {
			t.Run(fmt.Sprintf("%s_deadline_offset_%d", kind, offset), func(t *testing.T) {
				f, k, original := newRefreshBoundaryFixture(t)
				deadline := f.now.Unix() + offset
				var err error
				if kind == "refresh" {
					_, err = fixtureOwner.ExecContext(context.Background(), `UPDATE identity_sessions SET refresh_until=$2 WHERE device=$1`, original.DeviceID, deadline)
				} else {
					_, err = fixtureOwner.ExecContext(context.Background(), `UPDATE identity_accounts SET valid_until=$2 WHERE owner=$1`, Owner(f.grant.Issuer, f.grant.Subject), deadline)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := readRefreshBoundaryState(t, f, original.DeviceID)
				_, body := refreshBoundaryRequest(t)
				response := f.call(t, k, "POST", refreshBoundaryPath, original.RefreshToken, original.Nonce, body)
				if response.Code != http.StatusForbidden {
					t.Fatalf("expired boundary status %d, expected 403", response.Code)
				}
				after := readRefreshBoundaryState(t, f, original.DeviceID)
				if after != before || after.generation != 0 || after.history != 1 || after.requests != 0 {
					t.Fatal("expired boundary must not rotate, revoke, add history or cache a new session")
				}
			})
		}
	}
}

func TestRefreshBoundaryEarlyAndLateCachedReplaysKeepExactSessionAndGeneration(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("late_%t", late), func(t *testing.T) {
			f, k, original := newRefreshBoundaryFixture(t)
			if late {
				f.now = time.Unix(original.RefreshUntilMs/1000-528, 0)
			}
			_, body := refreshBoundaryRequest(t)
			response := f.call(t, k, "POST", refreshBoundaryPath, original.RefreshToken, original.Nonce, body)
			next := refreshBoundarySession(t, response)
			requireRefreshBoundaryRotation(t, original, next, min(f.now.Unix()+600, original.RefreshUntilMs/1000)*1000)
			before := readRefreshBoundaryState(t, f, original.DeviceID)
			f.now = f.now.Add(time.Second)
			challenge := f.call(t, k, "POST", refreshBoundaryPath, original.RefreshToken, original.Nonce, body)
			if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("DPoP-Nonce") != next.Nonce {
				t.Fatal("lost response must retain the authenticated current nonce challenge")
			}
			replay := f.call(t, k, "POST", refreshBoundaryPath, original.RefreshToken, next.Nonce, body)
			again := refreshBoundarySession(t, replay)
			if again != next || !bytes.Equal(replay.Body.Bytes(), response.Body.Bytes()) {
				t.Fatal("same request and body must replay the byte-exact original session without reminting")
			}
			if readRefreshBoundaryState(t, f, original.DeviceID) != before {
				t.Fatal("cached replay must not change hashes, nonce, generation, lifetimes or history")
			}
			requireRefreshBoundaryStored(t, f, again, 2, 1)
		})
	}
}

func TestRefreshBoundaryRepeatedFreshRotationsNeverExtendAbsoluteFamily(t *testing.T) {
	f, k, original := newRefreshBoundaryFixture(t)
	f.now = time.Unix(original.RefreshUntilMs/1000-90, 0)
	current := original
	for generation := int64(1); generation <= 3; generation++ {
		_, body := refreshBoundaryRequest(t)
		next := refreshBoundarySession(t, f.call(t, k, "POST", refreshBoundaryPath, current.RefreshToken, current.Nonce, body))
		requireRefreshBoundaryRotation(t, current, next, original.RefreshUntilMs)
		if next.Generation != generation || next.RefreshUntilMs != original.RefreshUntilMs {
			t.Fatal("successive refreshes must not slide the absolute family or reset its generation")
		}
		requireRefreshBoundaryStored(t, f, next, int(generation)+1, int(generation))
		current = next
		f.now = f.now.Add(5 * time.Second)
	}
}
