//go:build postgres

package invitation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func (f *fixture) verification() Verification {
	return Verification{AdminVerifier: f.v, ControlOrigin: f.admin.ControlOrigin, IdentityOrigin: "https://api.example.invalid", AssuranceACR: f.admin.AssuranceACR, Anchor: f.root}
}
func TestSQLSignerIndependentlyVerifiesReceiptsAndFinalRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	issued := f.issue(t)
	state, _ := f.claim(t, issued)
	thumb, _ := identity.PublicJWK(&f.phone.PublicKey).Thumbprint()
	if _, e := f.signer.Ready(ctx, state.ID, f.verification(), f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("unapproved invitation became publication authority")
	}
	if _, e := f.adminCall(t, "invite.approve", Approval{state.ID, state.Version, thumb, state.PairCode}); e != nil {
		t.Fatal(e)
	}
	p, e := f.signer.Ready(ctx, state.ID, f.verification(), f.now)
	if e != nil || p.Thumbprint != thumb || p.Owner != f.owner || bytes.Contains(p.Enrollment, []byte(`"code":`)) {
		t.Fatal("independent signer admission", e)
	}
	tx, e := fixtureSigner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.signer.LockPublication(ctx, tx, p, f.now); e != nil {
		t.Fatal(e)
	}
	tx.Rollback()
	tampered := p
	tampered.Enrollment = append([]byte(nil), p.Enrollment...)
	tampered.Enrollment[0] ^= 1
	tx, e = fixtureSigner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.signer.LockPublication(ctx, tx, tampered, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("mutable compilation dependency reached signer")
	}
	tx.Rollback()
	if _, e := f.adminCall(t, "invite.revoke", Mutation{ID: state.ID, Version: 3}); e != nil {
		t.Fatal(e)
	}
	tx, e = fixtureSigner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.signer.LockPublication(ctx, tx, p, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("late invitation revocation did not fence signer")
	}
	tx.Rollback()
}

func TestSQLForgedApprovalRowCannotReplaceAdminProof(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	state, _ := f.claim(t, f.issue(t))
	thumb, _ := identity.PublicJWK(&f.phone.PublicKey).Thumbprint()
	id, _ := random()
	payload, _ := json.Marshal(Approval{state.ID, state.Version, thumb, state.PairCode})
	body, _ := json.Marshal(Envelope{1, "invite.approve", id, payload})
	// Even an approval ciphertext manufactured with the control role's envelope
	// key cannot manufacture the administrator's IdP-bound DPoP private key.
	forged := Receipt{Token: token, Proof: signed(t, f.phone, f.admin.ControlOrigin+"/v1/control/action", token, "", body, f.now), URI: f.admin.ControlOrigin + "/v1/control/action", Body: body, AcceptedAt: f.now.Unix()}
	protected, e := protect(f.admin.Store, forged, "invitation/approval-receipt/"+state.ID)
	if e != nil {
		t.Fatal(e)
	}
	actor := identity.Hash([]byte(f.v.p.Issuer + "\x00" + f.v.p.Subject))
	if _, e = fixtureControl.Exec(`UPDATE managed_invitations SET approval_actor=$2,approval_request=$3,approval_hash=$4,approval_receipt=$5,approved_at=$6,version=version+1 WHERE id=$1`, state.ID, actor, id, identity.Hash(body), protected, f.now.Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.signer.Ready(ctx, state.ID, f.verification(), f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("database row bypassed independent administrator proof", e)
	}
}

func TestSQLPendingBackoffAndAtomicDeviceBinding(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	state, _ := f.claim(t, f.issue(t))
	thumb, _ := identity.PublicJWK(&f.phone.PublicKey).Thumbprint()
	if _, e := f.adminCall(t, "invite.approve", Approval{state.ID, state.Version, thumb, state.PairCode}); e != nil {
		t.Fatal(e)
	}
	tickets, e := f.signer.Pending(ctx, f.now)
	if e != nil || len(tickets) != 1 {
		t.Fatal("eligible publication", e)
	}
	if e = f.signer.PublicationFailure(ctx, tickets[0], "temporarily_unavailable", f.now); e != nil {
		t.Fatal(e)
	}
	tickets, e = f.signer.Pending(ctx, f.now)
	if e != nil || len(tickets) != 0 {
		t.Fatal("backoff ignored", e)
	}
	tickets, e = f.signer.Pending(ctx, f.now.Add(30*time.Second))
	if e != nil || len(tickets) != 1 {
		t.Fatal("backoff did not recover", e)
	}
	if e = f.signer.PublicationFailure(ctx, tickets[0], "unbounded-error-text", f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("unbounded diagnostic accepted")
	}
	p, e := f.signer.Ready(ctx, state.ID, f.verification(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	device, _ := random()
	bind := func(commit bool) {
		t.Helper()
		tx, e := fixtureSigner.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, `INSERT INTO identity_devices(id,owner,jkt,request_body,receipt) VALUES($1,$2,$3,$4,$5)`, device, f.owner, thumb, p.Enrollment, []byte("synthetic-protected-receipt")); e != nil {
			t.Fatal(e)
		}
		if e = f.signer.BindDevice(ctx, tx, p, device, f.now); e != nil {
			t.Fatal(e)
		}
		if commit {
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
		}
	}
	bind(false)
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_devices WHERE id=$1`, device).Scan(&count); e != nil || count != 0 {
		t.Fatal("binding escaped rollback", e)
	}
	bind(true)
	// A late metadata failure from the old version cannot override new authority.
	if e = f.signer.PublicationFailure(ctx, tickets[0], "authorization_changed", f.now); e != nil {
		t.Fatal(e)
	}
	value, e := f.adminCall(t, "invite.get", Mutation{ID: state.ID})
	if e != nil || value.(View).State != "provisioning" {
		t.Fatal("unapproved device reported ready", e)
	}
	if _, e = fixtureSigner.Exec(`UPDATE identity_devices SET approved=true,offline_until=$2,publication_error='' WHERE id=$1`, device, f.now.Unix()+60); e != nil {
		t.Fatal(e)
	}
	value, e = f.adminCall(t, "invite.get", Mutation{ID: state.ID})
	if e != nil || value.(View).State != "ready" {
		t.Fatal("signed state not visible", e)
	}
	tx, e := fixtureSigner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = f.signer.BindDevice(ctx, tx, p, device, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("stale dependency bound device", e)
	}
}
