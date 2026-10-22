package contracts

import (
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestNormativeSchemasAndVectors(t *testing.T) {
	schemas := map[string]*jsonschema.Schema{}
	for _, name := range []string{"decision-request", "decision-result", "policy-payload"} {
		raw, err := Files.ReadFile("v1/" + name + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err = json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		compiler := jsonschema.NewCompiler()
		url := doc["$id"].(string)
		if err = compiler.AddResource(url, doc); err != nil {
			t.Fatal(err)
		}
		schema, err := compiler.Compile(url)
		if err != nil {
			t.Fatal(err)
		}
		schemas[name] = schema
	}
	raw, _ := Files.ReadFile("v1/decision-vectors.json")
	var vectors struct {
		Cases []struct {
			Name     string
			Input    any
			Expected any
		}
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Cases {
		if err := schemas["decision-request"].Validate(c.Input); err != nil {
			t.Fatalf("%s input: %v", c.Name, err)
		}
		if err := schemas["decision-result"].Validate(c.Expected); err != nil {
			t.Fatalf("%s result: %v", c.Name, err)
		}
	}
	for _, bad := range []string{
		`{"selectedPathId":null,"orderedPathIds":[]}`,
		`{"selectedPathId":1,"orderedPathIds":[],"rejected":[]}`,
		`{"selectedPathId":null,"orderedPathIds":[],"rejected":[{"pathId":"p","reason":"bypass"}]}`,
		`{"selectedPathId":null,"orderedPathIds":["p","p"],"rejected":[]}`,
	} {
		var value any
		_ = json.Unmarshal([]byte(bad), &value)
		if err := schemas["decision-result"].Validate(value); err == nil {
			t.Fatalf("bad result accepted: %s", bad)
		}
	}
}

func TestPreviewOpenAPIReferences(t *testing.T) {
	raw, err := Files.ReadFile("v1/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatal("unsupported OpenAPI")
	}
	paths := doc["paths"].(map[string]any)
	post := paths["/v1/decision-preview"].(map[string]any)["post"].(map[string]any)
	request := post["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if request["$ref"] != "./decision-request.schema.json" {
		t.Fatal("request reference mismatch")
	}
	result := post["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if result["$ref"] != "./decision-result.schema.json" {
		t.Fatal("result reference mismatch")
	}
}
