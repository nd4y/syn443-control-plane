// Generates deterministic public layer-byte evidence in disposable Actions only.
// It has no input document, credentials, keys, database or network constructor.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

const fixtureLimit = 32768
const layerLimit = 8192

var errFixture = errors.New("layer_fixture_failed")

type layerVector struct {
	Name            string   `json:"name"`
	LayerWire       string   `json:"layerWire"`
	GlobalLayerHash string   `json:"globalLayerHash"`
	KnownFieldPaths []string `json:"knownFieldPaths"`
}

type scenarioVector struct {
	Name             string   `json:"name"`
	LayerNames       []string `json:"layerNames"`
	UnchangedParents []string `json:"unchangedParents"`
	EditedLayers     []string `json:"editedLayers"`
	EffectiveWire    string   `json:"effectiveWire"`
	KnownFieldPaths  []string `json:"knownFieldPaths"`
}

type fixtureDocument struct {
	SchemaVersion int              `json:"schemaVersion"`
	HashAlgorithm string           `json:"hashAlgorithm"`
	Layers        []layerVector    `json:"layers"`
	Scenarios     []scenarioVector `json:"scenarios"`
}

type namedLayer struct {
	name  string
	layer configuration.Layer
}

func knownPaths() []string {
	return []string{"/activation/timeoutSeconds", "/graph/final", "/network/dnsFinal", "/network/dnsStrategy"}
}

func setting(path, raw string) configuration.Change {
	return configuration.Change{Path: path, Operation: "set", Value: json.RawMessage(raw)}
}

func knownLayerPaths(layer configuration.Layer) []string {
	paths := []string{}
	for _, path := range knownPaths() {
		for _, change := range layer.Changes {
			if path == change.Path || strings.HasPrefix(path, change.Path+"/") {
				paths = append(paths, path)
				break
			}
		}
	}
	return paths
}

func fixtureLayers() []namedLayer {
	parent := configuration.Layer{ID: "fixture-template", Kind: "template", Revision: 1,
		Changes: []configuration.Change{
			setting("/schemaVersion", `1.00`),
			setting("/graph", " \n {\"final\":\"direct\", \"balancers\":{}, \"chains\":{}, \"profiles\":{}} \t"),
			setting("/network", `{
  "dnsStrategy":"prefer_ipv4<&>é\u2028\u2029", "dnsFinal":"syst\u0065m",
  "requiredNetworks":["tcp","udp"], "schemaVersion":1e0
}`),
			setting("/activation", `{"timeoutSeconds":30.125,"checks":[{"required":true,"target":"https://health.example.invalid/generate_204","type":"https_204","id":"intern\u0061l"}]}`),
		},
		Permissions: []configuration.Permission{
			{Path: "/schemaVersion", Mode: "free"}, {Path: "/graph", Mode: "free"},
			{Path: "/network", Mode: "free"}, {Path: "/activation", Mode: "free"},
		}}
	device := func(revision int64, strategy string) configuration.Layer {
		return configuration.Layer{ID: "fixture-device", Kind: "device", Revision: revision,
			Changes: []configuration.Change{
				setting("/schemaVersion", `1`), setting("/network/schemaVersion", `1`),
				setting("/network/dnsStrategy", strategy), setting("/activation/timeoutSeconds", `30`),
			}, Permissions: []configuration.Permission{}}
	}
	local := func(revision int64, timeout string) configuration.Layer {
		return configuration.Layer{ID: "fixture-device", Kind: "local", Revision: revision,
			Changes:     []configuration.Change{setting("/activation/timeoutSeconds", timeout)},
			Permissions: []configuration.Permission{}}
	}
	return []namedLayer{{"template-parent", parent}, {"device-before", device(1, `"prefer_ipv4"`)},
		{"device-after", device(2, `"prefer_ipv6"`)}, {"local-before", local(1, `45`)}, {"local-after", local(2, `60`)}}
}

// This is the exact private deviceprovisioning.configurationHash formula. The
// source-bound test also pins the publisher's json.Marshal(layer) call site.
func globalLayerHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func makeFixture() (fixtureDocument, error) {
	document := fixtureDocument{SchemaVersion: 1, HashAlgorithm: "sha256-lowercase-hex",
		Layers: []layerVector{}, Scenarios: []scenarioVector{}}
	layers := make(map[string]configuration.Layer)
	for _, sample := range fixtureLayers() {
		raw, err := json.Marshal(sample.layer)
		if err != nil || len(raw) == 0 || len(raw) > layerLimit {
			return fixtureDocument{}, errFixture
		}
		decoded, err := configuration.DecodeLayers(append(append([]byte{'['}, raw...), ']'))
		if err != nil || len(decoded) != 1 {
			return fixtureDocument{}, errFixture
		}
		layers[sample.name] = decoded[0]
		document.Layers = append(document.Layers, layerVector{sample.name, string(raw), globalLayerHash(raw), knownLayerPaths(sample.layer)})
	}
	definitions := []scenarioVector{
		{Name: "before-device-edit", LayerNames: []string{"template-parent", "device-before"}, UnchangedParents: []string{"template-parent"}, EditedLayers: []string{"device-before"}},
		{Name: "after-device-edit", LayerNames: []string{"template-parent", "device-after"}, UnchangedParents: []string{"template-parent"}, EditedLayers: []string{"device-after"}},
		{Name: "before-local-edit", LayerNames: []string{"template-parent", "device-after", "local-before"}, UnchangedParents: []string{"template-parent", "device-after"}, EditedLayers: []string{"local-before"}},
		{Name: "after-local-edit", LayerNames: []string{"template-parent", "device-after", "local-after"}, UnchangedParents: []string{"template-parent", "device-after"}, EditedLayers: []string{"local-after"}},
	}
	for _, sample := range definitions {
		input := make([]configuration.Layer, 0, len(sample.LayerNames))
		for _, name := range sample.LayerNames {
			input = append(input, layers[name])
		}
		effective, plan, err := configuration.MergeNetworkPlan(context.Background(), input)
		if err != nil {
			return fixtureDocument{}, errFixture
		}
		resolved := false
		_, err = configuration.CompileNetworkPlan(context.Background(), plan, func(configuration.ProfileReference) (subscriptions.Profile, error) {
			resolved = true
			return subscriptions.Profile{}, configuration.ErrInvalid
		})
		if err != nil || resolved || len(effective.Document) > layerLimit {
			return fixtureDocument{}, errFixture
		}
		for _, path := range knownPaths() {
			if _, found := effective.Fields[path]; !found {
				return fixtureDocument{}, errFixture
			}
		}
		sample.EffectiveWire, sample.KnownFieldPaths = string(effective.Document), knownPaths()
		document.Scenarios = append(document.Scenarios, sample)
	}
	return document, nil
}

func run(getenv func(string) string, output io.Writer) error {
	if getenv == nil || output == nil || getenv("GITHUB_ACTIONS") != "true" {
		return errFixture
	}
	document, err := makeFixture()
	if err != nil {
		return errFixture
	}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(raw)+1 > fixtureLimit {
		return errFixture
	}
	raw = append(raw, '\n')
	if written, err := output.Write(raw); err != nil || written != len(raw) {
		return errFixture
	}
	return nil
}

func main() {
	var err error
	switch {
	case len(os.Args) == 1:
		err = run(os.Getenv, os.Stdout)
	case len(os.Args) == 2 && os.Args[1] == "--projection":
		err = runProjection(os.Getenv, os.Stdout)
	case len(os.Args) == 2 && os.Args[1] == "--operations":
		err = runOperations(os.Getenv, os.Stdout)
	default:
		err = errFixture
	}
	if err != nil {
		os.Stderr.WriteString("layer_fixture_failed\n")
		os.Exit(1)
	}
}

// Projection conformance is a separate artifact. The original fixtureDocument,
// default CLI bytes and its CP55 resource contract remain unchanged.
const projectionLimit = 65536

type projectionLayer struct {
	Name            string `json:"name"`
	LayerWire       string `json:"layerWire"`
	GlobalLayerHash string `json:"globalLayerHash"`
}
type projectionVector struct {
	Name          string   `json:"name"`
	LayerNames    []string `json:"layerNames"`
	ExpectedCode  string   `json:"expectedCode"`
	EffectiveWire string   `json:"effectiveWire"`
}
type rebaseVector struct {
	Name             string   `json:"name"`
	BaseLayerNames   []string `json:"baseLayerNames"`
	LocalLayerNames  []string `json:"localLayerNames"`
	RemoteLayerNames []string `json:"remoteLayerNames"`
	ChosenLayerNames []string `json:"chosenLayerNames"`
	Resolution       string   `json:"resolution"`
	ExpectedCode     string   `json:"expectedCode"`
	EffectiveWire    string   `json:"effectiveWire"`
}
type projectionBound struct {
	Name               string `json:"name"`
	Generator          string `json:"generator"`
	Groups             int    `json:"groups"`
	LeavesPerGroup     int    `json:"leavesPerGroup"`
	ExtraLeaves        int    `json:"extraLeaves"`
	GlobalLayerHash    string `json:"globalLayerHash"`
	ExpectedCode       string `json:"expectedCode"`
	ExpectedFieldCount int    `json:"expectedFieldCount"`
}
type projectionDocument struct {
	SchemaVersion int                `json:"schemaVersion"`
	HashAlgorithm string             `json:"hashAlgorithm"`
	Layers        []projectionLayer  `json:"layers"`
	Projections   []projectionVector `json:"projections"`
	Rebases       []rebaseVector     `json:"rebases"`
	Bounds        []projectionBound  `json:"bounds"`
}
type projectionSpec struct {
	name, want string
	layers     []string
}

func projectionLayers() []namedLayer {
	all := []namedLayer{}
	add := func(name, kind, id string, priority int, changes []configuration.Change, permissions []configuration.Permission) {
		if changes == nil {
			changes = []configuration.Change{}
		}
		if permissions == nil {
			permissions = []configuration.Permission{}
		}
		all = append(all, namedLayer{name, configuration.Layer{ID: id, Kind: kind, Priority: priority, Revision: 1, Changes: changes, Permissions: permissions}})
	}
	base := `{"a":1.00,"b":2,"label":"\u0061","arr":[1,2],"nested":{"left":1,"right":2},"empty":{}}`
	free := []configuration.Permission{{Path: "/app", Mode: "free"}}
	add("base", "template", "projection-template", 0, []configuration.Change{setting("/app", base)}, free)
	add("remote-parent", "template", "projection-template", 0, []configuration.Change{setting("/app", strings.Replace(base, `"right":2`, `"right":9`, 1))}, free)
	add("no-permission", "template", "projection-template", 0, []configuration.Change{setting("/app", base)}, nil)
	add("scalar-parent", "template", "projection-template", 0, []configuration.Change{setting("/app", `7`)}, free)
	add("empty-parent", "template", "projection-template", 0, []configuration.Change{setting("/app", `{}`)}, free)
	own := func(name string, changes ...configuration.Change) {
		add(name, "device", "synthetic-device", 0, changes, nil)
	}
	own("inherit")
	own("a3", setting("/app/a", `3`))
	own("a4", setting("/app/a", `4`))
	own("a5", setting("/app/a", `5`))
	own("a3-dot", setting("/app/a", `3.0`))
	own("a3-exp", setting("/app/a", `3e0`))
	own("ab", setting("/app/a", `3`), setting("/app/b", `4`))
	own("a-label", setting("/app/a", `3`), setting("/app/label", `"remote"`))
	own("merged-ab-label", setting("/app/a", `3`), setting("/app/b", `4`), setting("/app/label", `"remote"`))
	own("label-escaped", setting("/app/label", `"\u0061"`))
	own("label-plain", setting("/app/label", `"a"`))
	own("delete-a", configuration.Change{Path: "/app/a", Operation: "delete"})
	own("delete-missing", configuration.Change{Path: "/app/missing", Operation: "delete"})
	own("nested-scalar", setting("/app/nested", `7`))
	own("nested-array", setting("/app/nested", `[{"x":1},2]`))
	own("nested-object", setting("/app/nested", `{"only":9}`))
	own("nested-empty", setting("/app/nested", `{}`))
	own("nested-empty-array", setting("/app/nested", `[]`))
	own("root-object", setting("/app", `{"child":9}`))
	own("root-array", setting("/app", `[2,1]`))
	own("array-reordered", setting("/app/arr", `[2,1]`))
	own("array-remote", setting("/app/arr", `[1,3]`))
	own("array-same-numbers", setting("/app/arr", `[2.0,1e0]`))
	own("descend-scalar", setting("/app/a/child", `5`))
	own("null", setting("/app/a", `null`))
	own("nested-null", setting("/app/nested", `{"x":null}`))
	own("invalid-delete", configuration.Change{Path: "/app/a", Operation: "delete", Value: json.RawMessage(`1`)})
	own("overlap", setting("/app/nested", `{}`), setting("/app/nested/child", `1`))
	own("unicode", setting("/app/label", `"line<&>é\u2028\u2029\u0061"`))
	group := func(name, id string, priority int, changes ...configuration.Change) {
		add(name, "group", id, priority, changes, nil)
	}
	group("group-a3", "group-a", 0, setting("/app/a", `3`))
	group("group-b4", "group-b", 0, setting("/app/b", `4`))
	group("group-same", "group-b", 0, setting("/app/a", `3`))
	group("group-different", "group-b", 0, setting("/app/a", `4`))
	group("group-lexical", "group-b", 0, setting("/app/a", `3.0`))
	group("group-priority", "group-b", 10, setting("/app/a", `4`))
	group("group-empty", "group-a", 0, setting("/app/nested", `{}`))
	group("group-child", "group-b", 0, setting("/app/nested/right", `2`))
	group("group-left", "group-a", 0, setting("/app/left", `1`))
	group("group-right", "group-b", 0, setting("/app/right", `2`))
	group("group-delete", "group-a", 0, configuration.Change{Path: "/app/nested/missing", Operation: "delete"})
	group("group-delete-same", "group-b", 0, configuration.Change{Path: "/app/nested/missing", Operation: "delete"})
	group("group-create-missing", "group-b", 0, setting("/app/nested/missing", `1`))
	minimum, maximum := int64(1), int64(10)
	add("locked-parent", "template", "projection-template", 0, []configuration.Change{setting("/app", `{"a":3}`)}, []configuration.Permission{{Path: "/app/a", Mode: "locked"}})
	add("range-parent", "template", "projection-template", 0, []configuration.Change{setting("/app", `{"a":5}`)}, []configuration.Permission{{Path: "/app/a", Mode: "range", Minimum: &minimum, Maximum: &maximum}})
	add("choice-parent", "template", "projection-template", 0, []configuration.Change{setting("/app", `{"a":1}`)}, []configuration.Permission{{Path: "/app/a", Mode: "choice", Choices: []json.RawMessage{json.RawMessage(`1`), json.RawMessage(`2`)}}})
	add("choice-remote", "template", "projection-template", 0, []configuration.Change{setting("/app", `{"a":3}`)}, []configuration.Permission{{Path: "/app/a", Mode: "choice", Choices: []json.RawMessage{json.RawMessage(`3`), json.RawMessage(`5`)}}})
	tightMaximum := int64(3)
	add("range-remote", "template", "projection-template", 0, []configuration.Change{setting("/app", `{"a":3}`)}, []configuration.Permission{{Path: "/app/a", Mode: "range", Minimum: &minimum, Maximum: &tightMaximum}})
	add("device-lock", "device", "synthetic-device", 0, nil, []configuration.Permission{{Path: "/app/a", Mode: "locked"}})
	add("device-widen", "device", "synthetic-device", 0, nil, []configuration.Permission{{Path: "/app/a", Mode: "free"}})
	add("device-range", "device", "synthetic-device", 0, []configuration.Change{setting("/app/a", `5`)}, []configuration.Permission{{Path: "/app/a", Mode: "range", Minimum: &minimum, Maximum: &maximum}})
	add("local-eight", "local", "synthetic-device", 0, []configuration.Change{setting("/app/a", `8`)}, nil)
	add("local-eleven", "local", "synthetic-device", 0, []configuration.Change{setting("/app/a", `11`)}, nil)
	own("one-dot", setting("/app/a", `1.00`))
	own("two", setting("/app/a", `2`))
	return all
}

func projectionSpecs() []projectionSpec {
	return []projectionSpec{
		{"base", "ok", []string{"base"}}, {"inherit-absent-own-change", "ok", []string{"base", "inherit"}},
		{"delete-distinct-from-inherit", "ok", []string{"base", "delete-a"}}, {"delete-nonexistent", "ok", []string{"base", "delete-missing"}},
		{"nested-shared-siblings", "ok", []string{"base", "ab"}}, {"scalar-to-object", "ok", []string{"scalar-parent", "root-object"}},
		{"object-to-scalar", "ok", []string{"base", "nested-scalar"}}, {"object-to-array", "ok", []string{"base", "nested-array"}},
		{"object-replacement-drops-old-leaves", "ok", []string{"base", "nested-object"}}, {"empty-object-is-leaf", "ok", []string{"base", "nested-empty"}},
		{"empty-array-is-atomic-leaf", "ok", []string{"base", "nested-empty-array"}},
		{"root-array-atomic", "ok", []string{"base", "root-array"}}, {"array-order-atomic", "ok", []string{"base", "array-reordered"}},
		{"raw-fraction-and-escaped-string", "ok", []string{"base", "label-plain"}}, {"unicode-and-go-escaping", "ok", []string{"base", "unicode"}},
		{"descend-into-scalar", "configuration_invalid", []string{"base", "descend-scalar"}},
		{"null-forbidden", "configuration_invalid", []string{"base", "null"}}, {"nested-null-forbidden", "configuration_invalid", []string{"base", "nested-null"}},
		{"delete-value-forbidden", "configuration_invalid", []string{"base", "invalid-delete"}}, {"overlapping-own-writes", "configuration_invalid", []string{"base", "overlap"}},
		{"groups-disjoint", "ok", []string{"base", "group-b4", "group-a3"}}, {"groups-same-value", "ok", []string{"base", "group-a3", "group-same"}},
		{"groups-conflict", "configuration_conflict", []string{"base", "group-a3", "group-different"}},
		{"groups-number-spelling-conflict", "configuration_conflict", []string{"base", "group-a3", "group-lexical"}},
		{"groups-priority", "ok", []string{"group-priority", "base", "group-a3"}},
		{"groups-ancestor-conflict", "configuration_conflict", []string{"base", "group-empty", "group-child"}},
		{"groups-empty-container-disjoint", "ok", []string{"empty-parent", "group-left", "group-right"}},
		{"groups-delete-nonexistent-same", "ok", []string{"base", "group-delete", "group-delete-same"}},
		{"groups-delete-nonexistent-conflict", "configuration_conflict", []string{"base", "group-delete", "group-create-missing"}},
		{"locked-same-value", "ok", []string{"locked-parent", "a3"}}, {"locked-changed-value", "configuration_field_locked", []string{"locked-parent", "a4"}},
		{"range-valid", "ok", []string{"range-parent", "two"}}, {"range-noninteger-spelling", "configuration_field_locked", []string{"range-parent", "one-dot"}},
		{"choice-valid", "ok", []string{"choice-parent", "two"}}, {"choice-number-spelling", "configuration_field_locked", []string{"choice-parent", "one-dot"}},
		{"choice-delete", "configuration_field_locked", []string{"choice-parent", "delete-a"}},
		{"permission-only-narrowing", "ok", []string{"base", "device-lock"}}, {"permission-widening-denied", "configuration_field_locked", []string{"locked-parent", "device-widen"}},
		{"local-inherited-range", "ok", []string{"base", "device-range", "local-eight"}},
		{"local-range-denied", "configuration_field_locked", []string{"base", "device-range", "local-eleven"}},
		{"local-without-permission", "configuration_field_locked", []string{"no-permission", "local-eight"}},
	}
}

func projectionResult(layers []configuration.Layer) (string, string, int) {
	raw, err := json.Marshal(layers)
	if err != nil {
		return "configuration_invalid", "", 0
	}
	owned, err := configuration.DecodeLayers(raw)
	if err != nil {
		return "configuration_invalid", "", 0
	}
	result, err := configuration.Merge(context.Background(), owned, func(json.RawMessage) error { return nil })
	if err != nil {
		switch {
		case errors.Is(err, configuration.ErrLocked):
			return "configuration_field_locked", "", 0
		case errors.Is(err, configuration.ErrConflict):
			return "configuration_conflict", "", 0
		default:
			return "configuration_invalid", "", 0
		}
	}
	body, err := json.Marshal(result)
	if err != nil {
		return "configuration_invalid", "", 0
	}
	return "ok", string(body), len(result.Fields)
}

func boundLayer(groups, perGroup, extra int) (configuration.Layer, error) {
	if groups != 64 || perGroup != 64 || extra < 0 || extra > 1 {
		return configuration.Layer{}, errFixture
	}
	grid := map[string]any{}
	for g := 0; g < groups; g++ {
		group := map[string]any{}
		for v := 0; v < perGroup; v++ {
			group[fmt.Sprintf("v%02d", v)] = v
		}
		grid[fmt.Sprintf("g%02d", g)] = group
	}
	if extra == 1 {
		grid["extra"] = 1
	}
	raw, err := json.Marshal(grid)
	if err != nil {
		return configuration.Layer{}, errFixture
	}
	return configuration.Layer{ID: "projection-template", Kind: "template", Revision: 1, Changes: []configuration.Change{setting("/grid", string(raw))}, Permissions: []configuration.Permission{}}, nil
}

func makeProjection() (projectionDocument, error) {
	doc := projectionDocument{SchemaVersion: 1, HashAlgorithm: "sha256-lowercase-hex", Layers: []projectionLayer{}, Projections: []projectionVector{}, Rebases: []rebaseVector{}, Bounds: []projectionBound{}}
	catalogue := map[string]configuration.Layer{}
	for _, sample := range projectionLayers() {
		raw, err := json.Marshal(sample.layer)
		if err != nil || len(raw) > layerLimit || catalogue[sample.name].ID != "" {
			return projectionDocument{}, errFixture
		}
		catalogue[sample.name] = sample.layer
		doc.Layers = append(doc.Layers, projectionLayer{sample.name, string(raw), globalLayerHash(raw)})
	}
	resolve := func(names []string) ([]configuration.Layer, error) {
		input := []configuration.Layer{}
		for _, name := range names {
			layer, ok := catalogue[name]
			if !ok {
				return nil, errFixture
			}
			input = append(input, layer)
		}
		return input, nil
	}
	for _, spec := range projectionSpecs() {
		input, err := resolve(spec.layers)
		if err != nil {
			return projectionDocument{}, errFixture
		}
		code, wire, _ := projectionResult(input)
		if code != spec.want {
			return projectionDocument{}, errFixture
		}
		doc.Projections = append(doc.Projections, projectionVector{spec.name, spec.layers, code, wire})
	}
	// These chosen own-layer expectations are explicit fixture cases, not an
	// existing server three-way rebase implementation. Go Merge validates only
	// each declared chosen projection, including current permission restrictions.
	definitions := []rebaseVector{
		{"disjoint-own-edits-current-parent-changed", []string{"base", "a3"}, []string{"base", "ab"}, []string{"remote-parent", "a-label"}, []string{"remote-parent", "merged-ab-label"}, "merged", "ok", ""},
		{"same-path-different-values", []string{"base", "a3"}, []string{"base", "a4"}, []string{"base", "a5"}, []string{}, "conflict", "configuration_conflict", ""},
		{"equal-decimals-retain-current-spelling", []string{"base", "a3"}, []string{"base", "a3-dot"}, []string{"base", "a3-exp"}, []string{"base", "a3-exp"}, "merged", "ok", ""},
		{"equal-escaped-strings-retain-current-layer", []string{"base", "label-escaped"}, []string{"base", "label-plain"}, []string{"base", "label-escaped"}, []string{"base", "label-escaped"}, "merged", "ok", ""},
		{"inherit-removes-own-change", []string{"base", "a3"}, []string{"base", "inherit"}, []string{"base", "a3"}, []string{"base", "inherit"}, "merged", "ok", ""},
		{"delete-is-not-inherit", []string{"base", "a3"}, []string{"base", "delete-a"}, []string{"base", "a3"}, []string{"base", "delete-a"}, "merged", "ok", ""},
		{"arrays-conflict-as-ordered-atoms", []string{"base", "inherit"}, []string{"base", "array-reordered"}, []string{"base", "array-remote"}, []string{}, "conflict", "configuration_conflict", ""},
		{"equal-array-numbers-retain-current-layer", []string{"base", "inherit"}, []string{"base", "array-reordered"}, []string{"base", "array-same-numbers"}, []string{"base", "array-same-numbers"}, "merged", "ok", ""},
		{"current-lock-blocks-chosen-own-edit", []string{"base", "a3"}, []string{"base", "a4"}, []string{"locked-parent", "a3"}, []string{"locked-parent", "a4"}, "merged", "configuration_field_locked", ""},
		{"current-range-blocks-chosen-own-edit", []string{"base", "a3"}, []string{"base", "a4"}, []string{"range-remote", "a3"}, []string{"range-remote", "a4"}, "merged", "configuration_field_locked", ""},
		{"current-choice-blocks-chosen-own-edit", []string{"base", "a3"}, []string{"base", "a4"}, []string{"choice-remote", "a3"}, []string{"choice-remote", "a4"}, "merged", "configuration_field_locked", ""},
	}
	for _, sample := range definitions {
		for _, names := range [][]string{sample.BaseLayerNames, sample.LocalLayerNames, sample.RemoteLayerNames} {
			input, err := resolve(names)
			if err != nil {
				return projectionDocument{}, errFixture
			}
			code, _, _ := projectionResult(input)
			if code != "ok" {
				return projectionDocument{}, errFixture
			}
		}
		if sample.Resolution == "merged" {
			input, err := resolve(sample.ChosenLayerNames)
			if err != nil {
				return projectionDocument{}, errFixture
			}
			code, wire, _ := projectionResult(input)
			if code != sample.ExpectedCode {
				return projectionDocument{}, errFixture
			}
			sample.EffectiveWire = wire
		}
		doc.Rebases = append(doc.Rebases, sample)
	}
	for extra := 0; extra <= 1; extra++ {
		layer, err := boundLayer(64, 64, extra)
		if err != nil {
			return projectionDocument{}, errFixture
		}
		raw, err := json.Marshal(layer)
		if err != nil {
			return projectionDocument{}, errFixture
		}
		code, _, count := projectionResult([]configuration.Layer{layer})
		want := "ok"
		if extra == 1 {
			want = "configuration_invalid"
		}
		if code != want || extra == 0 && count != 4096 {
			return projectionDocument{}, errFixture
		}
		doc.Bounds = append(doc.Bounds, projectionBound{fmt.Sprintf("leaves-%d", 4096+extra), "leaf-grid-v1", 64, 64, extra, globalLayerHash(raw), code, count})
	}
	return doc, nil
}

func runProjection(getenv func(string) string, output io.Writer) error {
	if getenv == nil || output == nil || getenv("GITHUB_ACTIONS") != "true" {
		return errFixture
	}
	doc, err := makeProjection()
	if err != nil {
		return errFixture
	}
	raw, err := json.Marshal(doc)
	if err != nil || len(raw)+1 > projectionLimit {
		return errFixture
	}
	raw = append(raw, '\n')
	if n, err := output.Write(raw); err != nil || n != len(raw) {
		return errFixture
	}
	return nil
}
