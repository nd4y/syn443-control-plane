//go:build postgres

package enrollment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestSQLGrantTimingFencesPublisherAndSchedulesSignedRenewal(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()
	first := f.now
	stale := f.publisher()
	f.grant.PolicyTiming = &PolicyTiming{RefreshAfterSeconds: 45, OfflineLeaseSeconds: 604800}
	if err := Authorize(ctx, fixtureOwner, f.grant, first); err != nil {
		t.Fatal(err)
	}
	f.api.Clock = func() time.Time { return f.now }
	k := key(t)
	session, _, _ := f.register(t, k)
	thumb, err := identity.PublicJWK(&k.PublicKey).Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(stale.publish(ctx, session.DeviceID, first), ErrDenied) {
		t.Fatal("stale worker could publish after a timing grant change")
	}
	publisher := f.publisher()
	for _, step := range []struct{ seconds, revision, issued int64 }{{0, 1, 0}, {44, 1, 0}, {45, 2, 45}} {
		f.now = first.Add(time.Duration(step.seconds) * time.Second)
		if err := publisher.RunOnce(ctx, f.now); err != nil {
			t.Fatal(err)
		}
		reply := f.call(t, k, "GET", "/v1/device/policy", session.AccessToken, session.Nonce, nil)
		expect(t, reply, 200)
		p, err := policy.VerifyBound(reply.Body.String(), f.api.Roots, session.DeviceID, thumb, f.now)
		if err != nil || p.Revision != step.revision || p.IssuedAtMs != first.Add(time.Duration(step.issued)*time.Second).UnixMilli() ||
			p.RefreshAfterMs != p.IssuedAtMs+45_000 || p.OfflineUntilMs != f.grant.Until*1000 {
			t.Fatal("signed revision, renewal or account expiry differs", step.seconds, err)
		}
	}
}
