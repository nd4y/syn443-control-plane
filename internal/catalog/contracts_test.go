package catalog

import (
	"encoding/json"
	"testing"
	"time"
)

func TestControlWireRequiresExplicitMutableFields(t *testing.T) {
	schema, e := loadControlSchema()
	if e != nil {
		t.Fatal(e)
	}
	source := sourceExample(time.Now())
	value := Action{Version: 1, Action: "source.put", RequestID: "synthetic-request-identifier", Payload: func() []byte {
		raw, _ := json.Marshal(map[string]any{"source": source, "secret": SecretPatch{Operation: "keep"}})
		return raw
	}()}
	raw, _ := json.Marshal(value)
	var wire map[string]any
	json.Unmarshal(raw, &wire)
	if e = schema.Validate(wire); e != nil {
		t.Fatal("runtime shape rejected", e)
	}
	for _, member := range []string{"version", "action", "requestId", "payload"} {
		var bad map[string]any
		json.Unmarshal(raw, &bad)
		delete(bad, member)
		if schema.Validate(bad) == nil {
			t.Fatal("missing envelope member", member)
		}
	}
	for _, member := range []string{"id", "owner", "enabled", "revision", "format", "networkModes", "validUntil"} {
		var bad map[string]any
		json.Unmarshal(raw, &bad)
		body := bad["payload"].(map[string]any)["source"].(map[string]any)
		delete(body, member)
		if schema.Validate(bad) == nil {
			t.Fatal("missing source member", member)
		}
	}
	var bad map[string]any
	json.Unmarshal(raw, &bad)
	bad["payload"].(map[string]any)["source"].(map[string]any)["enabled"] = false
	if schema.Validate(bad) != nil {
		t.Fatal("explicit false rejected")
	}
	bad["unexpected"] = true
	if schema.Validate(bad) == nil {
		t.Fatal("unknown envelope member")
	}
}
