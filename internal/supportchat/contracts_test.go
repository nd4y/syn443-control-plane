package supportchat

import (
	"encoding/json"
	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"testing"
)

func TestChatWireContractIsClosedAndMatchesRuntime(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/chat-openapi.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("json")
	}
	compiler := jsonschema.NewCompiler()
	base := "https://contracts.example.invalid/chat-openapi.json"
	if e = compiler.AddResource(base, doc); e != nil {
		t.Fatal(e)
	}
	values := map[string]any{"Send": SendRequest{Conversation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ClientID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Text: "hello", Attachments: []string{}}, "Begin": UploadRequest{Conversation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ClientID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Name: "fixture.bin", MIME: "application/octet-stream", Kind: "file", Size: MaxFileBytes, SHA256: Hash([]byte("fixture"))}}
	values["IncidentLookup"] = map[string]any{"reference": "SYN-0123456789ab"}
	values["IncidentResult"] = incidentResult{Reference: "SYN-0123456789ab", State: "found", Report: &incidentMatch{Text: "synthetic", CreatedAt: 1}}
	for name, value := range values {
		schema, e := compiler.Compile(base + "#/components/schemas/" + name)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := json.Marshal(value)
		var object map[string]any
		json.Unmarshal(data, &object)
		if e = schema.Validate(object); e != nil {
			t.Fatal(e)
		}
		object["owner"] = "not-authority"
		if schema.Validate(object) == nil {
			t.Fatal("unknown authority field")
		}
		delete(object, "owner")
		for field := range object {
			copy := map[string]any{}
			for k, v := range object {
				if k != field {
					copy[k] = v
				}
			}
			if schema.Validate(copy) == nil {
				t.Fatal("missing field", field)
			}
		}
	}
	paths := doc["paths"].(map[string]any)
	if len(paths) != 24 {
		t.Fatal("API paths")
	}
	for _, path := range []string{"/v1/chat/incident/lookup", "/v1/admin/chat/incident/lookup"} {
		if paths[path] == nil {
			t.Fatal("missing incident operation", path)
		}
	}
	for _, p := range paths {
		post := p.(map[string]any)["post"].(map[string]any)
		if post["security"] == nil || post["parameters"] == nil {
			t.Fatal("unbound path")
		}
	}
}
