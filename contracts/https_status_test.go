package contracts

import (
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestPortableSchemaValidatesHTTPSStatusVectors(t *testing.T) {
	raw, err := Files.ReadFile("v1/route-check-profile-v2.schema.json")
	var profile map[string]any
	if err != nil || json.Unmarshal(raw, &profile) != nil {
		t.Fatal("missing profile schema")
	}
	compiler := jsonschema.NewCompiler()
	id := profile["$id"].(string)
	if err := compiler.AddResource(id, profile); err != nil {
		t.Fatal(err)
	}
	check, err := compiler.Compile(id + "#/$defs/check")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ Valid, Invalid []any }
	raw, err = Files.ReadFile("v1/https-status-check-vectors.json")
	if err != nil || json.Unmarshal(raw, &v) != nil || len(v.Valid) != 3 || len(v.Invalid) != 12 {
		t.Fatal("missing method/status vectors")
	}
	for i, value := range v.Valid {
		if err := check.Validate(value); err != nil {
			t.Fatalf("valid check %d: %v", i, err)
		}
	}
	for i, value := range v.Invalid {
		if check.Validate(value) == nil {
			t.Fatalf("invalid check %d accepted", i)
		}
	}
}
