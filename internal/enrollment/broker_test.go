package enrollment

import (
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/netbirdapi"
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

func TestBrokerPeerReceiptPreservesCreationNanosecondsAndRejectsAmbiguousDates(t *testing.T) {
	at := time.Unix(1800000000, 123456789).UTC()
	p := netbirdapi.PeerOwnership{ResourceID: "resource-a", AccountID: "account-a", PeerID: "peer-a", SetupKeyID: "key-a", OperationName: "syn443-operation", EventID: "event-a", RegisteredAt: at.Add(time.Second), CreatedAt: at}
	raw, e := marshalBrokerPeer(p)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := unmarshalBrokerPeer(raw)
	if e != nil || restored != p {
		t.Fatal("strict persisted peer receipt did not roundtrip", e)
	}
	for _, bad := range [][]byte{nil, []byte(`{"CreatedAt":null}`), []byte(`{"CreatedAt":"not-a-time","RegisteredAt":"not-a-time"}`), []byte(`{"CreatedAt":"2027-01-15T08:00:00Z","RegisteredAt":"invalid"}`), []byte(`{"CreatedAt":"a","CreatedAt":"b"}`), []byte(`{"unknown":true}`)} {
		if _, e = unmarshalBrokerPeer(bad); e == nil {
			t.Fatal("ambiguous peer receipt accepted")
		}
	}
}

func TestBrokerMetadataCannotDecreaseKnownUseOrChangeOwnedKeyScope(t *testing.T) {
	at := time.Unix(1800000000, 0)
	j := &brokerJob{operation: "operation", providerID: "key-a", providerExpires: at.UnixMilli(), used: 1, scope: BrokerScope{Groups: []string{"group-a", "group-b"}}}
	k := netbirdapi.SetupKey{ID: "key-a", Name: "syn443-operation", Type: "one-off", UsageLimit: 1, UsedTimes: 1, Expires: at, Groups: []string{"group-b", "group-a"}}
	if !validBrokerKey(j, k) {
		t.Fatal("same owned metadata with reordered set rejected")
	}
	for _, mutate := range []func(*netbirdapi.SetupKey){func(v *netbirdapi.SetupKey) { v.ID = "foreign" }, func(v *netbirdapi.SetupKey) { v.Name = "foreign" }, func(v *netbirdapi.SetupKey) { v.Type = "reusable" }, func(v *netbirdapi.SetupKey) { v.UsageLimit = 2 }, func(v *netbirdapi.SetupKey) { v.UsedTimes = 0 }, func(v *netbirdapi.SetupKey) { v.UsedTimes = 2 }, func(v *netbirdapi.SetupKey) { v.Expires = at.Add(time.Second) }, func(v *netbirdapi.SetupKey) { v.Groups = []string{"foreign"} }} {
		c := k
		mutate(&c)
		if validBrokerKey(j, c) {
			t.Fatal("changed/regressed provider evidence accepted")
		}
	}
}
