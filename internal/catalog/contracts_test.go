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

func TestControlNetworkDraftSchemaRejectsNativeEscapesUnknownScopeAndServerTimestamp(t *testing.T) {
	schema, e := loadControlSchema()
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"draft": draftExample()})
	raw, _ := json.Marshal(Action{Version: 1, Action: "configuration.draft.put", RequestID: "synthetic-request-identifier", Payload: body})
	decode := func() map[string]any { var v map[string]any; json.Unmarshal(raw, &v); return v }
	if e = schema.Validate(decode()); e != nil {
		t.Fatal("closed draft runtime shape", e)
	}
	for _, change := range []func(map[string]any){
		func(d map[string]any) { d["targetKind"] = "*" }, func(d map[string]any) { d["savedAt"] = 1 },
		func(d map[string]any) { delete(d, "targetId") }, func(d map[string]any) { d["baseHash"] = "caller-asserted-hash" },
		func(d map[string]any) { d["native"] = map[string]any{} },
		func(d map[string]any) { d["plan"].(map[string]any)["setup_key"] = "synthetic-invalid" },
		func(d map[string]any) { d["plan"].(map[string]any)["graph"] = nil },
		func(d map[string]any) {
			d["plan"].(map[string]any)["network"].(map[string]any)["requiredNetworks"] = nil
		},
		func(d map[string]any) {
			d["plan"].(map[string]any)["activation"].(map[string]any)["timeoutSeconds"] = 121
		},
	} {
		wire := decode()
		change(wire["payload"].(map[string]any)["draft"].(map[string]any))
		if schema.Validate(wire) == nil {
			t.Fatal("invalid draft shape accepted")
		}
	}
}
