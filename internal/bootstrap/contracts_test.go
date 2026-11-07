package bootstrap

import (
	"encoding/json"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestBootstrapWireSchemasAreClosedAndRequireEveryAuthorityField(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/bootstrap.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("schema JSON")
	}
	compiler := jsonschema.NewCompiler()
	const base = "https://schemas.example.invalid/syn443/bootstrap-v1"
	if e = compiler.AddResource(base, doc); e != nil {
		t.Fatal(e)
	}
	d, anchor, key, now := descriptorFixture(t)
	manifest, e := SignDescriptor(d, anchor, key, now)
	if e != nil {
		t.Fatal(e)
	}
	_, floor, e := VerifyDescriptor(manifest, anchor, Floor{}, now)
	if e != nil {
		t.Fatal(e)
	}
	next, newKey := anchorFixture(t, "next-root", 2)
	transition := Transition{SchemaVersion: 1, Audience: "syn443-root-transition", From: anchor.ID, To: next.ID, SPKI: next.SPKI, Epoch: 2, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Unix() + 3600}
	rotation, e := SignRotation(transition, anchor, key, newKey, now)
	if e != nil {
		t.Fatal(e)
	}
	for name, value := range map[string]any{"Anchor": anchor, "Floor": floor, "Descriptor": d, "Transition": transition, "Rotation": rotation} {
		schema, e := compiler.Compile(base + "#/$defs/" + name)
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(value)
		var object map[string]any
		json.Unmarshal(encoded, &object)
		if schema.Validate(object) != nil {
			t.Fatal("runtime disagrees with bootstrap schema", name)
		}
		object["unexpected"] = true
		if schema.Validate(object) == nil {
			t.Fatal("unknown authority field", name)
		}
		delete(object, "unexpected")
		for field := range object {
			bad := map[string]any{}
			for k, v := range object {
				if k != field {
					bad[k] = v
				}
			}
			if schema.Validate(bad) == nil {
				t.Fatal("missing authority field", name, field)
			}
		}
	}
}
