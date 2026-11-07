package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func setting(path, raw string) Change {
	return Change{Path: path, Operation: "set", Value: json.RawMessage(raw)}
}
func layer(id, kind string, changes ...Change) Layer {
	return Layer{ID: id, Kind: kind, Revision: 1, Changes: changes}
}
func supported(raw json.RawMessage) error {
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil {
		return ErrInvalid
	}
	for name := range root {
		if name != "dns" && name != "ui" && name != "retry" && name != "mode" && name != "routes" && name != "flag" {
			return ErrInvalid
		}
	}
	return nil
}
func TestLayersPreserveProvenanceRightsAndPermutation(t *testing.T) {
	minimum, maximum := int64(100), int64(5000)
	base := layer("base", "template", setting("/dns/final", `"physical"`), setting("/ui/theme", `"dark"`), setting("/retry/ms", `1000`), setting("/mode", `"direct"`))
	base.Permissions = []Permission{{Path: "/retry/ms", Mode: "range", Minimum: &minimum, Maximum: &maximum}, {Path: "/ui", Mode: "free"}}
	low := layer("group-low", "group", setting("/dns/final", `"low"`))
	low.Priority = -10
	high := layer("group-high", "group", setting("/dns/final", `"high"`))
	high.Priority = 10
	user := layer("user-a", "user", setting("/retry/ms", `2000`))
	device := layer("device-a", "device", setting("/mode", `"proxy"`))
	device.Permissions = []Permission{{Path: "/ui/theme", Mode: "choice", Choices: []json.RawMessage{[]byte(`"dark"`), []byte(`"system"`)}}}
	local := layer("local-a", "local", setting("/retry/ms", `2500`), setting("/ui/theme", `"system"`))
	input := []Layer{local, high, user, base, device, low}
	result, e := Merge(context.Background(), input, supported)
	if e != nil {
		t.Fatal(e)
	}
	if result.Fields["/dns/final"].LayerID != high.ID || result.Fields["/mode"].LayerID != device.ID || result.Fields["/ui/theme"].Kind != "local" || len(result.Restrictions) != 3 {
		t.Fatal("field provenance/permission intersection lost")
	}
	encoded, _ := json.Marshal(result)
	random := rand.New(rand.NewSource(37))
	for i := 0; i < 24; i++ {
		shuffled := append([]Layer(nil), input...)
		random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		actual, e := Merge(context.Background(), shuffled, supported)
		raw, _ := json.Marshal(actual)
		if e != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("layer permutation changed result", e)
		}
	}
	minimum = 4000
	if *result.Restrictions[0].Permission.Minimum != 100 {
		t.Fatal("result aliases mutable input constraints")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", base, result), "physical") {
		t.Fatal("configuration values leaked to formatter")
	}
}

func TestEqualPriorityCollisionsIncludeExplicitUnchangedValues(t *testing.T) {
	base := layer("base", "template", setting("/mode", `"direct"`))
	a := layer("a", "group", setting("/mode", `"direct"`))
	b := layer("b", "group", setting("/mode", `"proxy"`))
	if _, e := Merge(context.Background(), []Layer{base, a, b}, supported); !errors.Is(e, ErrConflict) {
		t.Fatal("equal priority conflict hidden", e)
	}
	b.Changes = []Change{setting("/dns/final", `"other"`)}
	if _, e := Merge(context.Background(), []Layer{base, a, b}, supported); e != nil {
		t.Fatal("independent group fields", e)
	}
	b.Changes = []Change{setting("/mode", `"direct"`)}
	if _, e := Merge(context.Background(), []Layer{base, a, b}, supported); e != nil {
		t.Fatal("equal values conflict", e)
	}
	a.Changes = []Change{{Path: "/dns", Operation: "delete"}}
	b.Changes = []Change{setting("/dns/final", `"new"`)}
	if _, e := Merge(context.Background(), []Layer{base, a, b}, supported); !errors.Is(e, ErrConflict) {
		t.Fatal("parent deletion collision hidden", e)
	}
	a.Changes = []Change{setting("/dns/final", `"one"`)}
	b.Changes = []Change{setting("/dns", `{}`)}
	if _, e := Merge(context.Background(), []Layer{base, a, b}, supported); !errors.Is(e, ErrConflict) {
		t.Fatal("structural collision hidden", e)
	}
}

func TestGroupContainerChangesDoNotCreateFalseSiblingConflicts(t *testing.T) {
	base := layer("base", "template", setting("/dns", `{}`))
	a := layer("a", "group", setting("/dns/final", `"physical"`))
	b := layer("b", "group", setting("/dns/timeout", `1000`))
	if _, e := Merge(context.Background(), []Layer{base, a, b}, supported); e != nil {
		t.Fatal("independent children of empty parent conflicted", e)
	}
	base.Changes = []Change{setting("/dns", `{"final":"physical","timeout":1000}`)}
	a.Changes = []Change{setting("/dns", `{}`)}
	if _, e := Merge(context.Background(), []Layer{base, a}, supported); e != nil {
		t.Fatal("one group whole-object removal conflicted with itself", e)
	}
	if _, e := Merge(context.Background(), []Layer{base, a, b}, supported); !errors.Is(e, ErrConflict) {
		t.Fatal("whole-object replacement lost cross-group collision", e)
	}
	a.Changes = []Change{setting("/dns", `{}`), setting("/dns/final", `"other"`)}
	if _, e := Merge(context.Background(), []Layer{base, a}, supported); !errors.Is(e, ErrInvalid) {
		t.Fatal("overlapping same-layer edits are ambiguous")
	}
}

func TestLocalChangesCannotBypassParentLocksOrWidenPermissions(t *testing.T) {
	base := layer("base", "template", setting("/dns", `{"final":"physical","timeout":1000}`), setting("/ui/theme", `"dark"`))
	base.Permissions = []Permission{{Path: "/dns", Mode: "free"}, {Path: "/dns/final", Mode: "locked"}}
	for _, change := range []Change{setting("/dns/final", `"other"`), setting("/dns", `{"final":"other"}`), {Path: "/dns", Operation: "delete"}, setting("/ui/theme", `"light"`)} {
		if _, e := Merge(context.Background(), []Layer{base, layer("local", "local", change)}, supported); !errors.Is(e, ErrLocked) {
			t.Fatal("locked field bypass", e)
		}
	}
	if _, e := Merge(context.Background(), []Layer{base, layer("local", "local", setting("/dns/timeout", `2000`))}, supported); e != nil {
		t.Fatal("allowed sibling edit", e)
	}
	child := layer("device", "device")
	child.Permissions = []Permission{{Path: "/ui/theme", Mode: "free"}}
	if _, e := Merge(context.Background(), []Layer{base, child}, supported); !errors.Is(e, ErrLocked) {
		t.Fatal("absent parent permission widened")
	}
	child.Permissions = []Permission{{Path: "/dns/final", Mode: "free"}}
	if _, e := Merge(context.Background(), []Layer{base, child}, supported); !errors.Is(e, ErrLocked) {
		t.Fatal("locked parent permission widened")
	}
	child.Permissions = []Permission{{Path: "/dns/timeout", Mode: "range", Minimum: func() *int64 { v := int64(500); return &v }(), Maximum: func() *int64 { v := int64(3000); return &v }()}}
	if _, e := Merge(context.Background(), []Layer{base, child, layer("local", "local", setting("/dns/timeout", `4000`))}, supported); !errors.Is(e, ErrLocked) {
		t.Fatal("child range not enforced")
	}
	base.Permissions = []Permission{{Path: "/ui/theme", Mode: "choice", Choices: []json.RawMessage{[]byte(`"dark"`), []byte(`"system"`)}}}
	child.Permissions = []Permission{{Path: "/ui/theme", Mode: "free"}}
	if _, e := Merge(context.Background(), []Layer{base, child, layer("local", "local", setting("/ui/theme", `"light"`))}, supported); !errors.Is(e, ErrLocked) {
		t.Fatal("free child widened choices")
	}
}

func TestLayerBoundsAndFailClosedSupportedSchema(t *testing.T) {
	base := layer("base", "template", setting("/mode", `"direct"`))
	ctx := context.Background()
	for _, change := range []Change{setting("/mode", `null`), setting("/mode", `1e1000000000`), setting("/mode", `1e-1000000000`), setting("/mode", `9007199254740992`), setting("/mode", `{"a":1,"a":2}`), setting("/routes/0", `1`), setting("/bad~1path", `1`), setting("/runtime", `"forbidden by schema"`), {Path: "/mode", Operation: "delete", Value: []byte(`1`)}, {Path: "/mode", Operation: "unknown"}, {Path: "", Operation: "set", Value: []byte(`1`)}} {
		b := base
		b.Changes = []Change{change}
		if _, e := Merge(ctx, []Layer{b}, supported); e == nil {
			t.Fatal("invalid change accepted")
		}
	}
	for _, modify := range []func(*Layer){func(l *Layer) { l.ID = "../bad" }, func(l *Layer) { l.Kind = "unknown" }, func(l *Layer) { l.Revision = 0 }, func(l *Layer) { l.Priority = 1 }, func(l *Layer) { l.Changes = append(l.Changes, l.Changes[0]) }, func(l *Layer) { l.Changes = make([]Change, 257) }, func(l *Layer) { l.Permissions = make([]Permission, 257) }} {
		b := base
		modify(&b)
		if _, e := Merge(ctx, []Layer{b}, supported); e == nil {
			t.Fatal("invalid layer")
		}
	}
	if _, e := Merge(ctx, []Layer{base, base}, supported); e == nil {
		t.Fatal("duplicate layer")
	}
	if _, e := Merge(ctx, nil, supported); e == nil {
		t.Fatal("missing template")
	}
	if _, e := Merge(ctx, []Layer{base}, nil); e == nil {
		t.Fatal("missing supported-schema validator")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := Merge(cancelled, []Layer{base}, supported); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled compilation returned candidate")
	}
	if _, e := Merge(ctx, []Layer{base}, func(json.RawMessage) error { cancel(); return ErrInvalid }); !errors.Is(e, ErrInvalid) {
		t.Fatal("schema rejection bypass")
	}
}

func TestDeviceAndLocalLayerShareTheirBoundDeviceIDWithoutLosingRestrictions(t *testing.T) {
	base := layer("base", "template", setting("/ui/theme", `"dark"`))
	base.Permissions = []Permission{{Path: "/ui", Mode: "free"}}
	device := layer("device-a", "device")
	device.Permissions = []Permission{{Path: "/ui/theme", Mode: "choice", Choices: []json.RawMessage{[]byte(`"dark"`), []byte(`"system"`)}}}
	local := layer("device-a", "local", setting("/ui/theme", `"system"`))
	merged, e := Merge(context.Background(), []Layer{base, device, local}, supported)
	if e != nil || merged.Fields["/ui/theme"].Kind != "local" || merged.Fields["/ui/theme"].LayerID != "device-a" {
		t.Fatal("scoped identity collision", e)
	}
	local.Changes = []Change{setting("/ui/theme", `"light"`)}
	if _, e = Merge(context.Background(), []Layer{base, device, local}, supported); !errors.Is(e, ErrLocked) {
		t.Fatal("same ID bypassed inherited choice", e)
	}
	device.Permissions = []Permission{{Path: "/ui/theme", Mode: "locked"}}
	local.Changes = []Change{setting("/ui/theme", `"system"`)}
	if _, e = Merge(context.Background(), []Layer{base, device, local}, supported); !errors.Is(e, ErrLocked) {
		t.Fatal("same ID bypassed parent lock", e)
	}
	if _, e = Merge(context.Background(), []Layer{base, device, device}, supported); !errors.Is(e, ErrInvalid) {
		t.Fatal("duplicate within same kind admitted", e)
	}
}

func TestPermissionBoundsAndAtomicArrays(t *testing.T) {
	lo, hi := int64(10), int64(1)
	for _, p := range []Permission{{Path: "bad", Mode: "free"}, {Path: "/mode", Mode: "unknown"}, {Path: "/mode", Mode: "locked", Minimum: &lo}, {Path: "/mode", Mode: "choice"}, {Path: "/mode", Mode: "choice", Choices: []json.RawMessage{[]byte(`"a"`), []byte(`"a"`)}}, {Path: "/mode", Mode: "range"}, {Path: "/mode", Mode: "range", Minimum: &lo, Maximum: &hi}} {
		if p.Validate() == nil {
			t.Fatal("invalid permission")
		}
	}
	base := layer("base", "template", setting("/routes", `["first","second"]`))
	base.Permissions = []Permission{{Path: "/routes", Mode: "choice", Choices: []json.RawMessage{[]byte(`["first","second"]`), []byte(`["second","first"]`)}}}
	merged, e := Merge(context.Background(), []Layer{base, layer("local", "local", setting("/routes", `["second","first"]`))}, supported)
	if e != nil || !bytes.Contains(merged.Document, []byte(`["second","first"]`)) {
		t.Fatal("ordered route choice", e)
	}
}
