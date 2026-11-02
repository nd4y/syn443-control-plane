package enrollment

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func brokerPolicyResourceExample() BrokerPolicyResource {
	return BrokerPolicyResource{ResourceID: "resource-a", Revision: 1, AccountID: "account-a", ManagementOrigin: "https://overlay.example.invalid", NetworkID: "tenant", Groups: []string{"group-a"}}
}
func TestBrokerPolicyMetadataIsClosedBoundedAndIndependentOfProviderCredentials(t *testing.T) {
	store := &Store{DB: &sql.DB{}}
	r := brokerPolicyResourceExample()
	for _, input := range [][]BrokerPolicyResource{nil, make([]BrokerPolicyResource, 17), {r, r}} {
		if _, e := NewBrokerPolicies(store, "fixture", input); e == nil {
			t.Fatal("unbounded/duplicate policy resources")
		}
	}
	if _, e := NewBrokerPolicies(nil, "fixture", []BrokerPolicyResource{r}); e == nil {
		t.Fatal("missing publisher store accepted")
	}
	for _, mutate := range []func(*BrokerPolicyResource){func(v *BrokerPolicyResource) { v.Revision = 0 }, func(v *BrokerPolicyResource) { v.AccountID = "" }, func(v *BrokerPolicyResource) { v.ManagementOrigin += "/" }, func(v *BrokerPolicyResource) { v.Groups = nil }, func(v *BrokerPolicyResource) { v.Groups = []string{"a", "a"} }, func(v *BrokerPolicyResource) { v.Groups = []string{"../a"} }, func(v *BrokerPolicyResource) { v.NetworkID = "../network" }} {
		v := r
		mutate(&v)
		if _, e := NewBrokerPolicies(store, "fixture", []BrokerPolicyResource{v}); e == nil {
			t.Fatal("invalid policy resource metadata")
		}
	}
	path := filepath.Join(t.TempDir(), "metadata.json")
	raw, _ := json.Marshal([]BrokerPolicyResource{r})
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := ReadBrokerPolicyResources(path); e != nil || len(got) != 1 {
		t.Fatal("owner-only metadata read", e)
	}
	for _, raw := range []string{`[{"resourceId":"x","token":"synthetic-token-not-permitted-here"}]`, `[]`, `[{"resourceId":"x","resourceId":"y"}]`} {
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := ReadBrokerPolicyResources(path); e == nil {
			t.Fatal("secret/ambiguous/empty metadata accepted")
		}
	}
	if _, e := ReadBrokerPolicyResources(path + "-absent"); e == nil {
		t.Fatal("missing metadata accepted")
	}
}
func TestGrantOverlayAutoGroupsRejectsAmbiguityBeforeAnySQL(t *testing.T) {
	for _, groups := range []map[string][]string{{"../resource": {"group"}}, {"resource": {}}, {"resource": {"a", "a"}}, {"resource": {"../group"}}} {
		grant := Grant{OverlayGroups: groups}
		if grant.Validate(time.Unix(1800000000, 0)) == nil {
			t.Fatal("invalid overlay group authority accepted")
		}
	}
}
