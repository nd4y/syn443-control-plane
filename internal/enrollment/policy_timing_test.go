package enrollment

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestOperatorPolicyTimingBoundsAndLegacyGrantHash(t *testing.T) {
	now := time.Unix(1800000000, 0)
	g := Grant{Issuer: "issuer", Subject: "owner", DeviceLimit: 1, Until: now.Add(7 * 24 * time.Hour).Unix()}
	template, err := json.Marshal(g.Template)
	if err != nil {
		t.Fatal(err)
	}
	original := `{"issuer":"issuer","subject":"owner","deviceLimit":1,"until":1800604800,"template":` + string(template) + "}"
	if g.Hash() != identity.Hash([]byte(original)) {
		t.Fatal("omitting policy timing changed the legacy grant hash")
	}
	var p policy.Payload
	if err := g.setPolicyTimes(&p, now); err != nil || p.RefreshAfterMs != now.Add(5*time.Minute).UnixMilli() || p.OfflineUntilMs != now.Add(time.Hour).UnixMilli() {
		t.Fatal("default grant schedule changed", err)
	}
	for _, invalid := range []PolicyTiming{{0, 0}, {29, 3600}, {60, 60}, {61, 60}, {300, 604801}, {300, -1}, {1 << 62, 1 << 62}, {300, 1 << 62}} {
		g.PolicyTiming = &invalid
		if err := g.setPolicyTimes(&p, now); err == nil {
			t.Fatalf("accepted invalid schedule %+v", invalid)
		}
	}
	g.PolicyTiming = &PolicyTiming{RefreshAfterSeconds: 300, OfflineLeaseSeconds: 604800}
	if err := g.setPolicyTimes(&p, now); err != nil || p.OfflineUntilMs != now.Add(7*24*time.Hour).UnixMilli() || g.Hash() == identity.Hash([]byte(original)) {
		t.Fatal("explicit seven-day lease must affect the grant and signed deadline", err)
	}
	g.Until = now.Add(35 * time.Second).Unix()
	if err := g.setPolicyTimes(&p, now); err != nil || p.OfflineUntilMs != g.Until*1000 || p.RefreshAfterMs != p.OfflineUntilMs-1000 {
		t.Fatal("account expiry must shorten both dates", err)
	}
}
