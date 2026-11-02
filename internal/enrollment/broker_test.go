package enrollment

import (
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
	"testing"
	"time"
)

func TestBrokerScopeIsBoundedAndDoesNotContainProviderMaterial(t *testing.T) {
	now := time.Unix(1800000000, 0)
	b := BrokerScope{Binding: overlay.CredentialBinding{Address: overlay.Address{ServiceID: "fixture-service", OwnerTag: identity.Hash([]byte("owner")), DeviceID: "fixture-device", OverlayID: "home", Provider: "netbird", ResourceID: "resource", NetworkID: "tenant", IdentityEpoch: 1, ManagementURL: "https://overlay.example.invalid"}, KeyThumbprint: identity.Hash([]byte("key")), Reference: identity.Hash([]byte("ref")), Version: 1, OfflineUntilMs: now.Add(time.Hour).UnixMilli()}, Owner: identity.Hash([]byte("owner")), GrantHash: identity.Hash([]byte("grant")), ResourceRevision: 1, Account: "account-a", Groups: []string{"group-a"}, DeadlineMs: now.Add(time.Minute).UnixMilli()}
	if e := b.validate(now); e != nil {
		t.Fatal("valid bounded scope", e)
	}
	for _, mutate := range []func(*BrokerScope){
		func(v *BrokerScope) { v.Binding.Address.Provider = "unsupported" },
		func(v *BrokerScope) { v.Binding.Reference = "invalid" },
		func(v *BrokerScope) { v.Binding.Version = 0 },
		func(v *BrokerScope) { v.ResourceRevision = 0 },
		func(v *BrokerScope) { v.Account = "../account" },
		func(v *BrokerScope) { v.Groups = []string{"group-a", "group-a"} },
		func(v *BrokerScope) { v.Groups = nil },
		func(v *BrokerScope) { v.Owner = "not-digest" },
		func(v *BrokerScope) { v.DeadlineMs = now.UnixMilli() },
		func(v *BrokerScope) { v.DeadlineMs = now.Add(31 * time.Minute).UnixMilli() },
		func(v *BrokerScope) { v.Binding.OfflineUntilMs = now.UnixMilli() },
	} {
		c := b
		mutate(&c)
		if c.validate(now) == nil {
			t.Fatal("unbounded/invalid scope accepted")
		}
	}
}
