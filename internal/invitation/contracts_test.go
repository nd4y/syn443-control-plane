package invitation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"testing"
)

func TestInvitationWireSchemasMatchRuntimeAndRejectUnknownFields(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/invitation-openapi.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("wire JSON")
	}
	compiler := jsonschema.NewCompiler()
	base := "https://contracts.example.invalid/invitation-openapi.json"
	if e = compiler.AddResource(base, doc); e != nil {
		t.Fatal(e)
	}
	id := func() string {
		v, e := random()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	session := enrollment.Session{DeviceID: id(), AccessToken: id(), RefreshToken: id(), AccessUntilMs: 1800000600000, RefreshUntilMs: 1800086400000, Generation: 0, Nonce: id()}
	values := map[string]any{
		"Claim":         Claim{id(), id(), identity.PublicJWK(&key.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}},
		"DeviceRequest": DeviceRequest{id(), id()},
		"ClaimState":    ClaimState{ID: id(), Version: 2, State: "pending_approval", PairCode: "123456", Nonce: id(), Expires: 1800000600, OwnerTag: id()},
		"Session":       session, "Completion": Completion{session, id()}, "Abandoned": map[string]bool{"revoked": true}, "Time": map[string]string{"serviceId": "service-a"},
	}
	for name, value := range values {
		schema, e := compiler.Compile(base + "#/components/schemas/" + name)
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(value)
		var object map[string]any
		if json.Unmarshal(encoded, &object) != nil {
			t.Fatal("runtime JSON")
		}
		if e = schema.Validate(object); e != nil {
			t.Fatal("runtime/schema disagree", name, e)
		}
		object["unexpected"] = true
		if schema.Validate(object) == nil {
			t.Fatal("unknown field accepted", name)
		}
		delete(object, "unexpected")
		for field := range object {
			copy := map[string]any{}
			for k, v := range object {
				if k != field {
					copy[k] = v
				}
			}
			if schema.Validate(copy) == nil {
				t.Fatal("missing required field", name, field)
			}
		}
	}
	paths := doc["paths"].(map[string]any)
	if len(paths) != 5 {
		t.Fatal("unbounded invitation route scope")
	}
	for path, value := range paths {
		entry := value.(map[string]any)
		if len(entry) != 1 {
			t.Fatal("unexpected method", path)
		}
		method := "post"
		if path == "/v1/invitations/time" {
			method = "get"
		}
		if entry[method] == nil {
			t.Fatal("wire/runtime verb mismatch", path)
		}
	}
}
