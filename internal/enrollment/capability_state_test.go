package enrollment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestCapabilityCanonicalSetHasStableHashBoundsAndNoCallerMutation(t *testing.T) {
	base := []string{"tun.lease.v1", "engine-config.v1", "policy.keybound.v2"}
	caps, raw, e := canonicalCapabilities(base)
	if e != nil {
		t.Fatal(e)
	}
	if string(raw) != `["engine-config.v1","policy.keybound.v2","tun.lease.v1"]` || base[0] != "tun.lease.v1" || caps[0] != "engine-config.v1" {
		t.Fatal("canonical set or ownership")
	}
	_, again, e := canonicalCapabilities(caps)
	if e != nil || identity.Hash(raw) != identity.Hash(again) {
		t.Fatal("capability hash unstable")
	}
	for _, bad := range [][]string{nil, base[:2], append(append([]string(nil), base...), base[0]), append(append([]string(nil), base...), "invalid feature"), {"engine-config.v1", "tun.lease.v1", "other"}, append(append([]string(nil), base...), strings.Repeat("a", 65))} {
		if _, _, e := canonicalCapabilities(bad); e == nil {
			t.Fatal("invalid capability set")
		}
	}
	tooMany := append([]string(nil), base...)
	for i := 0; i < 14; i++ {
		tooMany = append(tooMany, fmt.Sprint("feature", i))
	}
	if _, _, e := canonicalCapabilities(tooMany); e == nil {
		t.Fatal("unbounded set")
	}
}

func TestCapabilityPublisherRequiresInitializedContextAndVerifier(t *testing.T) {
	var absent *Publisher
	if e := absent.ApproveCapabilitiesOnce(context.Background(), time.Unix(1800000000, 0)); e == nil {
		t.Fatal("missing publisher")
	}
	if e := (&Publisher{}).ApproveCapabilitiesOnce(nil, time.Unix(1800000000, 0)); e == nil {
		t.Fatal("missing context")
	}
	if e := (&Publisher{Store: &Store{}}).ApproveCapabilitiesOnce(context.Background(), time.Unix(1800000000, 0)); e == nil {
		t.Fatal("missing independent verifier")
	}
}

func TestCapabilityInputIsClosedAndDiagnosticObjectsRedact(t *testing.T) {
	_, canonical, e := canonicalCapabilities([]string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"})
	if e != nil {
		t.Fatal(e)
	}
	input := CapabilityInput{RequestID: identity.Hash([]byte("operation")), PreviousHash: identity.Hash(canonical), Capabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}}
	raw, _ := json.Marshal(input)
	if _, e = capabilityInput(raw); e != nil {
		t.Fatal(e)
	}
	for _, body := range [][]byte{[]byte(`{}`), []byte(`{"requestId":"short"}`), []byte(strings.Repeat(" ", 8193)), append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"approved":true}`)...), append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"requestId":"duplicate"}`)...)} {
		if _, e = capabilityInput(body); e == nil {
			t.Fatal("untrusted capability input")
		}
	}
	if _, e = EffectiveCapabilities(nil, nil, "device-a", input.Capabilities); e == nil {
		t.Fatal("missing authority query")
	}
	if _, e = EffectiveCapabilities(context.Background(), nil, "device-a", input.Capabilities); e == nil {
		t.Fatal("missing SQL reader")
	}
	secret := "synthetic-capability-device-token"
	for _, value := range []any{input, CapabilityState{Hash: secret}, CapabilitySnapshot{AuthorityHash: secret}, CapabilityRequestView{Hash: secret}, CapabilityReceipt{Token: secret}, capabilityWork{owner: secret}} {
		if strings.Contains(fmt.Sprintf("%v %#v", value, value), secret) {
			t.Fatal("default diagnostics exposed capability evidence")
		}
	}
}
