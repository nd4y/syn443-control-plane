package resources

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRegistryAndNamespaces(t *testing.T) {
	i := Instance{ResourceID: "panel-a", ProviderType: Remnawave, APIVersion: "3.4", CredentialRef: "owner-token", Endpoint: "private-value", Enabled: true}
	if ValidateRegistry([]Instance{i}) != nil {
		t.Fatal("single supported instance rejected")
	}
	for _, list := range [][]Instance{nil, {i, i}, {{ResourceID: "x", ProviderType: "panel.3x-ui", APIVersion: "3.4", CredentialRef: "c", Enabled: true}}, {{ResourceID: "bad/id", Enabled: false}}} {
		if ValidateRegistry(list) == nil {
			t.Fatal("invalid registry accepted")
		}
	}
	planned := Instance{ResourceID: "planned", ProviderType: "panel.x-ui"}
	if ValidateRegistry([]Instance{i, planned}) != nil {
		t.Fatal("disabled extension contract rejected")
	}
	if (ObjectRef{"a", "bc"}).Namespace() == (ObjectRef{"ab", "c"}).Namespace() {
		t.Fatal("namespace collision")
	}
	if (ObjectRef{"a", "42"}).Namespace() == (ObjectRef{"b", "42"}).Namespace() {
		t.Fatal("resources conflated")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", i, i), "private-value") {
		t.Fatal("instance log leaked endpoint")
	}
	b, _ := json.Marshal(i)
	if strings.Contains(string(b), "private-value") || strings.Contains(string(b), "owner-token") {
		t.Fatal("resource descriptor leaked privileged fields")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", Snapshot{Links: []string{"secret-link"}}, Binding{"private-id", "secret-id"}), "secret") {
		t.Fatal("log leaked assignment")
	}
	if Failure("adapter_busy", true).Error() != "adapter_busy" {
		t.Fatal("error normalization changed")
	}
}
