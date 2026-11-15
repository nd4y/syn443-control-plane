package contracts

import (
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRouteGraphSchemaAndSharedPositiveVectors(t *testing.T) {
	raw, err := Files.ReadFile("v1/route-graph.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var definition map[string]any
	if err = json.Unmarshal(raw, &definition); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	location := "https://contracts.example.invalid/route-graph.schema.json"
	if err = compiler.AddResource(location, definition); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(location)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = Files.ReadFile("v1/route-graph-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		ValidCases []struct {
			Name  string
			Graph any
		}
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.ValidCases) == 0 {
		t.Fatal("no schema conformance evidence")
	}
	for _, v := range vectors.ValidCases {
		if err = schema.Validate(v.Graph); err != nil {
			t.Fatal(v.Name, err)
		}
		doc := v.Graph.(map[string]any)
		doc["unexpected"] = true
		if schema.Validate(doc) == nil {
			t.Fatal("open metadata root")
		}
		delete(doc, "unexpected")
		for _, key := range []string{"schemaVersion", "hops", "edges", "templates", "groups"} {
			saved := doc[key]
			delete(doc, key)
			if schema.Validate(doc) == nil {
				t.Fatal("missing required root member", key)
			}
			doc[key] = saved
		}
	}
}
