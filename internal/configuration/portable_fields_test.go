package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestPortableFieldsFollowTypedObjectsAndMapKeys(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct{ field, value string }{
		{"/graph/profiles/localState/profileId", "\"portable-profile\""},
		{"/graph/netbird/identityEpoch", "2"},
		{"/activation/timeoutSeconds", "30.125"},
		{"/network/schemaVersion", "1e0"},
		{"/network/routeChecks", `[{"outbound":"route","checks":[{"method":"https_status","target":"https://example.invalid/status","expected_status":204}]}]`},
		{"/graph/netbird", "{\"mode\":\"direct\"}"},
		{"/network/rules", "[{\"id\":\"rule\",\"match\":{\"domainSuffixes\":[\"example.invalid\"]}}]"},
	} {
		if err := checkPortableField(ctx, test.field, json.RawMessage(test.value)); err != nil {
			t.Fatalf("portable field %s: %v", test.field, err)
		}
	}
	for _, test := range []struct{ field, value string }{
		{"/runtime/counters", "1"},
		{"/graph/netbird/deviceKey", ""},
		{"/graph/netbird", "{\"androidPermissions\":{}}"},
		{"/graph/NetBird/identityEpoch", "1"},
		{"/graph/netbird/identityEpoch", "\"2\""},
		{"/network/rules/runtime", ""},
		{"/network/rules", "[{\"match\":{\"observedAddress\":\"fixture\"}}]"},
	} {
		if err := checkPortableField(ctx, test.field, json.RawMessage(test.value)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("nonportable field accepted: %s", test.field)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := checkPortableField(cancelled, "/graph", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled validation", err)
	}
}

func TestNetworkLayerOverrideCannotRetainDeviceLocalState(t *testing.T) {
	raw, err := json.Marshal(planBase())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	base := Layer{ID: "base", Kind: "template", Revision: 1}
	for _, name := range []string{"schemaVersion", "graph", "network", "activation"} {
		base.Changes = append(base.Changes, Change{Path: "/" + name, Operation: "set", Value: fields[name]})
	}
	device := Layer{ID: "device", Kind: "device", Revision: 1}
	// A legitimate template can leave an allowed choice for another layer.
	base.Permissions = []Permission{{Path: "/network/dnsStrategy", Mode: "free"}}
	device.Changes = []Change{{Path: "/network/dnsStrategy", Operation: "set", Value: json.RawMessage("\"ipv4_only\"")}}
	if _, plan, err := MergeNetworkPlan(context.Background(), []Layer{base, device}); err != nil || plan.Network.DNSStrategy != "ipv4_only" {
		t.Fatal("portable override", err)
	}

	base.Changes = append(base.Changes, Change{Path: "/learnedPeers", Operation: "set", Value: json.RawMessage("[]")})
	base.Permissions = append(base.Permissions, Permission{Path: "/learnedPeers", Mode: "free"})
	device.Changes = append(device.Changes, Change{Path: "/learnedPeers", Operation: "delete"})
	layers := []Layer{base, device}
	// The final JSON is valid after deletion; the retained raw edits are not.
	_, err = Merge(context.Background(), layers, func(raw json.RawMessage) error {
		_, err := DecodeNetworkPlan(raw)
		return err
	})
	if err != nil {
		t.Fatal("fixture did not produce a valid effective document", err)
	}
	if _, _, err := MergeNetworkPlan(context.Background(), layers); !errors.Is(err, ErrInvalid) {
		t.Fatal("device-local state retained in raw layers", err)
	}
}
