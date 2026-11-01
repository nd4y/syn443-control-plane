//go:build postgres

package invitation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

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
