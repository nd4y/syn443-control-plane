package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
)

func fixture(t *testing.T) fixtureDocument {
	t.Helper()
	value, err := makeFixture()
	if err != nil {
		t.Fatal("synthetic fixture generation failed")
	}
	return value
}

func render(t *testing.T, set *token.FileSet, node ast.Node) string {
	t.Helper()
	var output bytes.Buffer
	if format.Node(&output, set, node) != nil {
		t.Fatal("cannot inspect publisher syntax")
	}
	return output.String()
}

func TestLayerFixturePublisherHashFormulaAndMarshalSiteRemainSourceBound(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "../.."))
	set := token.NewFileSet()
	store, err := parser.ParseFile(set, filepath.Join(root, "internal/deviceprovisioning/layer_store.go"), nil, 0)
	if err != nil {
		t.Fatal("cannot inspect actual publisher hash")
	}
	hashes := 0
	for _, node := range store.Decls {
		function, ok := node.(*ast.FuncDecl)
		if ok && function.Name.Name == "configurationHash" {
			hashes++
			if render(t, set, function) != "func configurationHash(raw []byte) string {\n\tsum := sha256.Sum256(raw)\n\treturn hex.EncodeToString(sum[:])\n}" {
				t.Fatal("actual global layer hash formula changed; review fixture contract")
			}
		}
	}
	catalog, err := parser.ParseFile(set, filepath.Join(root, "internal/deviceprovisioning/layer_catalog.go"), nil, 0)
	if err != nil {
		t.Fatal("cannot inspect actual layer publisher")
	}
	bound := 0
	for _, node := range catalog.Decls {
		function, ok := node.(*ast.FuncDecl)
		if !ok || function.Name.Name != "resolveConfigurationLayers" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			loop, ok := node.(*ast.RangeStmt)
			if !ok || render(t, set, loop.X) != "bundle.Layers" || render(t, set, loop.Value) != "layer" {
				return true
			}
			marshaled, hashed := false, false
			for _, statement := range loop.Body.List {
				assignment, ok := statement.(*ast.AssignStmt)
				if !ok {
					continue
				}
				if render(t, set, assignment) == "body, e := json.Marshal(layer)" {
					marshaled = true
				}
				if len(assignment.Rhs) != 1 {
					continue
				}
				value, ok := assignment.Rhs[0].(*ast.CompositeLit)
				if !ok || render(t, set, value.Type) != "configurationLayerChange" {
					continue
				}
				fields := map[string]string{}
				for _, entry := range value.Elts {
					field, ok := entry.(*ast.KeyValueExpr)
					if ok {
						fields[render(t, set, field.Key)] = render(t, set, field.Value)
					}
				}
				hashed = marshaled && fields["Hash"] == "configurationHash(body)" && fields["Body"] == "body"
			}
			if marshaled && hashed {
				bound++
			}
			return false
		})
	}
	if hashes != 1 || bound != 1 {
		t.Fatal("fixture is no longer bound to the actual json.Marshal layer publisher")
	}
}

func TestLayerFixtureRawMessagesRetainOrderLexemesAndGoEscaping(t *testing.T) {
	value := fixture(t)
	parent := value.Layers[0].LayerWire
	for _, marker := range []string{`"value":1.00`, `"schemaVersion":1e0`, `"timeoutSeconds":30.125`,
		`"final":"direct","balancers":{},"chains":{},"profiles":{}`, `syst\u0065m`, `intern\u0061l`,
		`\u003c\u0026\u003e`, `é\u2028\u2029`} {
		if !strings.Contains(parent, marker) {
			t.Fatal("Go Marshal lost an explicitly required public raw lexeme")
		}
	}
	if strings.ContainsAny(parent, "\n\r\t") || !utf8.ValidString(parent) {
		t.Fatal("insignificant input whitespace was not compacted or UTF-8 changed")
	}
	for index, sample := range fixtureLayers() {
		raw, err := json.Marshal(sample.layer)
		if err != nil || string(raw) != value.Layers[index].LayerWire {
			t.Fatal("fixture is not actual Go Marshal output")
		}
		var decoded configuration.Layer
		if json.Unmarshal(raw, &decoded) != nil {
			t.Fatal("typed layer decode failed")
		}
		roundtrip, err := json.Marshal(decoded)
		if err != nil || !bytes.Equal(raw, roundtrip) {
			t.Fatal("typed RawMessage ownership changed the original layer")
		}
	}
}

func TestLayerFixtureGenericReencodingCannotReplaceAuthoritativeLayerBytes(t *testing.T) {
	value := fixture(t)
	for _, sample := range value.Layers {
		if len(sample.LayerWire) == 0 || len(sample.LayerWire) > layerLimit || len(sample.GlobalLayerHash) != 64 {
			t.Fatal("layer wire/hash bounds changed")
		}
		sum := sha256.Sum256([]byte(sample.LayerWire))
		if sample.GlobalLayerHash != hex.EncodeToString(sum[:]) {
			t.Fatal("global hash does not cover exact layer bytes")
		}
		changed := append([]byte(nil), sample.LayerWire...)
		for index := range changed {
			changed[index] ^= 1
			if globalLayerHash(changed) == sample.GlobalLayerHash {
				t.Fatal("a changed byte retained the old authoritative hash")
			}
			changed[index] ^= 1
		}
	}
	var generic any
	parent := value.Layers[0]
	if json.Unmarshal([]byte(parent.LayerWire), &generic) != nil {
		t.Fatal("generic negative fixture parse failed")
	}
	reencoded, err := json.Marshal(generic)
	if err != nil || bytes.Equal(reencoded, []byte(parent.LayerWire)) || globalLayerHash(reencoded) == parent.GlobalLayerHash {
		t.Fatal("generic map/number/string reconstruction hid the raw-byte hash difference")
	}
}

func TestLayerFixtureEveryScenarioCompilesAndPreservesUneditedParents(t *testing.T) {
	value := fixture(t)
	if len(value.Layers) != 5 || len(value.Scenarios) != 4 {
		t.Fatal("expected parent and device/local edit cases missing")
	}
	inputs := map[string]configuration.Layer{}
	wires := map[string]layerVector{}
	for _, sample := range fixtureLayers() {
		inputs[sample.name] = sample.layer
	}
	for index, sample := range value.Layers {
		wires[sample.Name] = sample
		expectedPaths := [][]string{knownPaths(), {"/activation/timeoutSeconds", "/network/dnsStrategy"},
			{"/activation/timeoutSeconds", "/network/dnsStrategy"}, {"/activation/timeoutSeconds"}, {"/activation/timeoutSeconds"}}
		if !strings.HasPrefix(inputs[sample.Name].ID, "fixture-") || !reflect.DeepEqual(sample.KnownFieldPaths, expectedPaths[index]) {
			t.Fatal("non-synthetic layer or unexpected known field paths")
		}
	}
	for index, sample := range value.Scenarios {
		plan, err := configuration.DecodeNetworkPlan([]byte(sample.EffectiveWire))
		if err != nil || plan.Graph.Final != "direct" || plan.Network.DNSFinal != "system" {
			t.Fatal("final settings are not a real direct-only portable plan")
		}
		expectedStrategy := "prefer_ipv6"
		if index == 0 {
			expectedStrategy = "prefer_ipv4"
		}
		expectedTimeout := []int{30, 30, 45, 60}[index]
		if plan.Network.DNSStrategy != expectedStrategy || plan.Activation.TimeoutSeconds != expectedTimeout || !reflect.DeepEqual(sample.KnownFieldPaths, knownPaths()) {
			t.Fatal("editor field values did not follow device/local order")
		}
		for _, name := range sample.UnchangedParents {
			raw, err := json.Marshal(inputs[name])
			if err != nil || string(raw) != wires[name].LayerWire || globalLayerHash(raw) != wires[name].GlobalLayerHash {
				t.Fatal("an unedited parent was reconstructed")
			}
		}
		ordered := make([]configuration.Layer, len(sample.LayerNames))
		for position, name := range sample.LayerNames {
			ordered[len(ordered)-1-position] = inputs[name]
		}
		effective, err := configuration.Merge(context.Background(), ordered, func(raw json.RawMessage) error {
			_, err := configuration.DecodeNetworkPlan(raw)
			return err
		})
		if err != nil || string(effective.Document) != sample.EffectiveWire {
			t.Fatal("actual merge or input permutation changed final settings")
		}
	}
	// The raw numeric spellings are valid layer values, not valid typed final
	// settings until the child supplies the declared integer overrides.
	_, err := configuration.Merge(context.Background(), []configuration.Layer{inputs["template-parent"]}, func(json.RawMessage) error { return nil })
	if err != nil {
		t.Fatal("parent raw values are not a valid layer shape")
	}
	device := inputs["device-before"]
	device.Changes = append([]configuration.Change(nil), device.Changes[:len(device.Changes)-1]...)
	if _, err := configuration.Merge(context.Background(), []configuration.Layer{inputs["template-parent"], device}, func(raw json.RawMessage) error {
		_, err := configuration.DecodeNetworkPlan(raw)
		return err
	}); err == nil {
		t.Fatal("fractional activation timeout bypassed real final-settings validation")
	}
}

func TestLayerFixtureDeterministicBoundedActionsOutputContainsOnlySyntheticData(t *testing.T) {
	var first, second bytes.Buffer
	owned := func(name string) string {
		if name != "GITHUB_ACTIONS" {
			t.Fatal("fixture consulted an unrelated environment value")
		}
		return "true"
	}
	if run(owned, &first) != nil || run(owned, &second) != nil || !bytes.Equal(first.Bytes(), second.Bytes()) || first.Len() > fixtureLimit || first.Len() == 0 {
		t.Fatal("Actions output is not deterministic and bounded")
	}
	var decoded fixtureDocument
	decoder := json.NewDecoder(bytes.NewReader(first.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(new(any)) != io.EOF || decoded.SchemaVersion != 1 || decoded.HashAlgorithm != "sha256-lowercase-hex" {
		t.Fatal("fixture document wire changed")
	}
	for _, forbidden := range []string{"PRIVATE KEY", "setup_key", "password", "access_token", "refresh_token", "nd4y", "192.168."} {
		if bytes.Contains(first.Bytes(), []byte(forbidden)) {
			t.Fatal("public fixture contains non-synthetic or credential-like material")
		}
	}
	decoded.Layers[0].LayerWire = "mutated"
	decoded.Scenarios[0].KnownFieldPaths[0] = "mutated"
	var fresh bytes.Buffer
	if run(owned, &fresh) != nil || !bytes.Equal(first.Bytes(), fresh.Bytes()) {
		t.Fatal("consumer mutation changed subsequent fixture output")
	}
}

type brokenOutput struct {
	short bool
}

func (w brokenOutput) Write(raw []byte) (int, error) {
	if w.short {
		return len(raw) - 1, nil
	}
	return 0, errors.New("synthetic output failure")
}

func TestLayerFixtureRefusesUnownedExecutionAndFailedWrites(t *testing.T) {
	for _, environment := range []string{"", "false", "TRUE", "1"} {
		var output bytes.Buffer
		if run(func(string) string { return environment }, &output) != errFixture || output.Len() != 0 {
			t.Fatal("non-Actions execution wrote fixture bytes")
		}
	}
	for _, output := range []io.Writer{nil, brokenOutput{}, brokenOutput{short: true}} {
		if run(func(string) string { return "true" }, output) != errFixture {
			t.Fatal("missing, failed or short writer was accepted")
		}
	}
	if run(nil, os.Stdout) != errFixture {
		t.Fatal("missing owner environment was accepted")
	}
}

func projectionFixture(t *testing.T) projectionDocument {
	t.Helper()
	doc, err := makeProjection()
	if err != nil {
		t.Fatal("actual projection fixture generation failed")
	}
	return doc
}
func projectionByName(t *testing.T, doc projectionDocument, name string) projectionVector {
	t.Helper()
	for _, sample := range doc.Projections {
		if sample.Name == name {
			return sample
		}
	}
	t.Fatal("required projection vector absent")
	return projectionVector{}
}
func projectionEffective(t *testing.T, sample projectionVector) (configuration.Effective, map[string]any) {
	t.Helper()
	var effective configuration.Effective
	if sample.ExpectedCode != "ok" || json.Unmarshal([]byte(sample.EffectiveWire), &effective) != nil {
		t.Fatal("not an actual successful merge")
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(effective.Document))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil {
		t.Fatal("invalid actual effective document")
	}
	return effective, document
}
func projectionInputs(t *testing.T, doc projectionDocument, names []string) []configuration.Layer {
	t.Helper()
	byName := map[string]configuration.Layer{}
	for _, sample := range doc.Layers {
		var layer configuration.Layer
		if json.Unmarshal([]byte(sample.LayerWire), &layer) != nil || globalLayerHash([]byte(sample.LayerWire)) != sample.GlobalLayerHash {
			t.Fatal("invalid exact projection layer bytes")
		}
		byName[sample.Name] = layer
	}
	input := []configuration.Layer{}
	for _, name := range names {
		layer, ok := byName[name]
		if !ok {
			t.Fatal("unbound projection reference")
		}
		input = append(input, layer)
	}
	return input
}

func TestLayerProjectionActualMergeHashAndPermutationMatchEveryVector(t *testing.T) {
	doc := projectionFixture(t)
	names := map[string]bool{}
	caseNames := map[string]bool{}
	codes := map[string]bool{}
	for _, sample := range doc.Layers {
		if names[sample.Name] || sample.Name == "" {
			t.Fatal("ambiguous layer catalogue")
		}
		names[sample.Name] = true
		var layer configuration.Layer
		if json.Unmarshal([]byte(sample.LayerWire), &layer) != nil {
			t.Fatal("invalid layer")
		}
		raw, err := json.Marshal(layer)
		if err != nil || string(raw) != sample.LayerWire || globalLayerHash(raw) != sample.GlobalLayerHash {
			t.Fatal("projection hash does not cover actual Go Layer Marshal")
		}
		if (layer.Kind == "device" || layer.Kind == "local") && layer.ID != "synthetic-device" {
			t.Fatal("fixture device identity escaped")
		}
	}
	for _, sample := range doc.Projections {
		if sample.Name == "" || caseNames[sample.Name] {
			t.Fatal("ambiguous projection case")
		}
		caseNames[sample.Name] = true
		input := projectionInputs(t, doc, sample.LayerNames)
		code, wire, _ := projectionResult(input)
		if code != sample.ExpectedCode || wire != sample.EffectiveWire {
			t.Fatal("projection oracle changed")
		}
		codes[code] = true
		for a, b := 0, len(input)-1; a < b; a, b = a+1, b-1 {
			input[a], input[b] = input[b], input[a]
		}
		code, wire, _ = projectionResult(input)
		if code != sample.ExpectedCode || wire != sample.EffectiveWire {
			t.Fatal("input ordering changed actual projection")
		}
	}
	if len(doc.Projections) != 41 || !reflect.DeepEqual(codes, map[string]bool{"ok": true, "configuration_invalid": true, "configuration_conflict": true, "configuration_field_locked": true}) {
		t.Fatal("projection semantic coverage missing")
	}
}

func TestLayerProjectionContainersOriginsGroupsAndPermissionOnlyChangesAreObservable(t *testing.T) {
	doc := projectionFixture(t)
	effective, document := projectionEffective(t, projectionByName(t, doc, "object-replacement-drops-old-leaves"))
	app := document["app"].(map[string]any)
	nested := app["nested"].(map[string]any)
	if len(nested) != 1 || nested["only"].(json.Number).String() != "9" || effective.Fields["/app/nested/only"].Kind != "device" {
		t.Fatal("object replacement was shallow or lost origin")
	}
	if _, ok := effective.Fields["/app/nested/left"]; ok {
		t.Fatal("deleted child retained provenance")
	}
	if _, ok := effective.Fields["/app/nested/right"]; ok {
		t.Fatal("deleted sibling retained provenance")
	}
	for _, name := range []string{"empty-object-is-leaf", "empty-array-is-atomic-leaf", "object-to-scalar", "object-to-array"} {
		e, _ := projectionEffective(t, projectionByName(t, doc, name))
		if e.Fields["/app/nested"].Kind != "device" {
			t.Fatal("atomic value missing field origin")
		}
	}
	e, _ := projectionEffective(t, projectionByName(t, doc, "groups-same-value"))
	if e.Fields["/app/a"].LayerID != "group-b" {
		t.Fatal("explicit same-value claim lost sorted group origin")
	}
	e, _ = projectionEffective(t, projectionByName(t, doc, "nested-shared-siblings"))
	if e.Fields["/app/nested/right"].Kind != "template" || e.Fields["/app/a"].Kind != "device" {
		t.Fatal("shared siblings were overwritten")
	}
	e, _ = projectionEffective(t, projectionByName(t, doc, "permission-only-narrowing"))
	if len(e.Restrictions) != 2 || e.Restrictions[1].Permission.Mode != "locked" || e.Restrictions[1].Origin.Kind != "device" || e.Fields["/app/a"].Kind != "template" {
		t.Fatal("permission-only changes altered document provenance or disappeared")
	}
}

func TestLayerProjectionNullDeleteInheritLexicalNumbersAndUnicodeStayDistinct(t *testing.T) {
	doc := projectionFixture(t)
	inherited, document := projectionEffective(t, projectionByName(t, doc, "inherit-absent-own-change"))
	if document["app"].(map[string]any)["a"].(json.Number).String() != "1.00" || inherited.Fields["/app/a"].Kind != "template" {
		t.Fatal("INHERIT changed numeric spelling or parent origin")
	}
	deleted, document := projectionEffective(t, projectionByName(t, doc, "delete-distinct-from-inherit"))
	if _, ok := document["app"].(map[string]any)["a"]; ok {
		t.Fatal("DELETE was treated as INHERIT")
	}
	if _, ok := deleted.Fields["/app/a"]; ok {
		t.Fatal("DELETE retained missing field origin")
	}
	base := projectionByName(t, doc, "base")
	missing := projectionByName(t, doc, "delete-nonexistent")
	if base.EffectiveWire != missing.EffectiveWire {
		t.Fatal("missing DELETE changed effective values")
	}
	unicode := projectionByName(t, doc, "unicode-and-go-escaping").EffectiveWire
	for _, escaped := range []string{`\u003c`, `\u0026`, `\u003e`, `\u2028`, `\u2029`} {
		if !strings.Contains(unicode, escaped) {
			t.Fatal("actual Go Unicode/HTML escaping disappeared")
		}
	}
	for _, name := range []string{"null-forbidden", "nested-null-forbidden", "delete-value-forbidden", "overlapping-own-writes"} {
		sample := projectionByName(t, doc, name)
		if sample.ExpectedCode != "configuration_invalid" || sample.EffectiveWire != "" {
			t.Fatal("invalid input exposed a partial document")
		}
	}
	if projectionByName(t, doc, "groups-number-spelling-conflict").ExpectedCode != "configuration_conflict" || projectionByName(t, doc, "choice-number-spelling").ExpectedCode != "configuration_field_locked" {
		t.Fatal("Go lexical number restrictions normalized away")
	}
}

func TestLayerProjectionRebaseChosenLayersAreExplicitAndCurrentRestrictionsStillApply(t *testing.T) {
	doc := projectionFixture(t)
	seen := map[string]bool{}
	if len(doc.Rebases) != 11 {
		t.Fatal("rebase case count changed")
	}
	for _, sample := range doc.Rebases {
		if sample.Name == "" || seen[sample.Name] {
			t.Fatal("ambiguous rebase example")
		}
		seen[sample.Name] = true
		for _, names := range [][]string{sample.BaseLayerNames, sample.LocalLayerNames, sample.RemoteLayerNames} {
			code, _, _ := projectionResult(projectionInputs(t, doc, names))
			if code != "ok" {
				t.Fatal("rebase starts from an invalid snapshot")
			}
		}
		if sample.Resolution == "conflict" {
			if len(sample.ChosenLayerNames) != 0 || sample.ExpectedCode != "configuration_conflict" || sample.EffectiveWire != "" {
				t.Fatal("conflict invented a merged result")
			}
			continue
		}
		if sample.Resolution != "merged" || len(sample.ChosenLayerNames) == 0 {
			t.Fatal("unknown rebase oracle outcome")
		}
		code, wire, _ := projectionResult(projectionInputs(t, doc, sample.ChosenLayerNames))
		if code != sample.ExpectedCode || wire != sample.EffectiveWire {
			t.Fatal("chosen rebased projection bypassed actual Go Merge")
		}
		if strings.HasPrefix(sample.Name, "current-") && code != "configuration_field_locked" {
			t.Fatal("new current permission failed to constrain chosen edit")
		}
	}
	for _, name := range []string{"disjoint-own-edits-current-parent-changed", "same-path-different-values", "equal-decimals-retain-current-spelling", "equal-escaped-strings-retain-current-layer", "inherit-removes-own-change", "delete-is-not-inherit", "arrays-conflict-as-ordered-atoms", "equal-array-numbers-retain-current-layer", "current-lock-blocks-chosen-own-edit", "current-range-blocks-chosen-own-edit", "current-choice-blocks-chosen-own-edit"} {
		if !seen[name] {
			t.Fatal("required own-intent rebase example missing")
		}
	}
	// This fixture specifies chosen own-layer expectations; it does not call or
	// claim a production server three-way rebase implementation.
}

func TestLayerProjectionActual4096LeafBoundaryIsSummarizedWithoutLargePayload(t *testing.T) {
	doc := projectionFixture(t)
	if len(doc.Bounds) != 2 {
		t.Fatal("leaf boundary vectors missing")
	}
	seen := map[string]bool{}
	for _, sample := range doc.Bounds {
		if sample.Name == "" || seen[sample.Name] || sample.Name != fmt.Sprintf("leaves-%d", 4096+sample.ExtraLeaves) {
			t.Fatal("ambiguous leaf boundary vector")
		}
		seen[sample.Name] = true
		layer, err := boundLayer(sample.Groups, sample.LeavesPerGroup, sample.ExtraLeaves)
		if err != nil {
			t.Fatal("invalid fixed generator")
		}
		raw, err := json.Marshal(layer)
		if err != nil || globalLayerHash(raw) != sample.GlobalLayerHash {
			t.Fatal("generated boundary input lost exact Go hash")
		}
		code, _, count := projectionResult([]configuration.Layer{layer})
		if code != sample.ExpectedCode || count != sample.ExpectedFieldCount {
			t.Fatal("actual Merge leaf bound drifted")
		}
		if sample.Generator != "leaf-grid-v1" || sample.ExtraLeaves == 0 && (code != "ok" || count != 4096) || sample.ExtraLeaves == 1 && code != "configuration_invalid" {
			t.Fatal("incorrect 4096/4097 expected result")
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil || len(raw)+1 > projectionLimit || bytes.Contains(raw, []byte("/grid/g63/v63")) {
		t.Fatal("boundary summary dumped large effective fields")
	}
	for _, shape := range [][3]int{{0, 64, 0}, {64, 65, 0}, {64, 64, -1}, {64, 64, 2}} {
		if _, err := boundLayer(shape[0], shape[1], shape[2]); err != errFixture {
			t.Fatal("unbounded input generator accepted")
		}
	}
}

func TestLayerProjectionDeterministicActionsOutputAndFailureGuardsStayBounded(t *testing.T) {
	owned := func(name string) string {
		if name != "GITHUB_ACTIONS" {
			t.Fatal("projection consulted private environment")
		}
		return "true"
	}
	var first, second bytes.Buffer
	if runProjection(owned, &first) != nil || runProjection(owned, &second) != nil || !bytes.Equal(first.Bytes(), second.Bytes()) || first.Len() == 0 || first.Len() > projectionLimit || !utf8.Valid(first.Bytes()) {
		t.Fatal("projection evidence is not deterministic bounded UTF8")
	}
	var doc projectionDocument
	decoder := json.NewDecoder(bytes.NewReader(first.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(new(any)) != io.EOF || doc.SchemaVersion != 1 || doc.HashAlgorithm != "sha256-lowercase-hex" {
		t.Fatal("projection wire contract changed")
	}
	for _, forbidden := range []string{"PRIVATE KEY", "setup_key", "password", "access_token", "refresh_token", "nd4y", "192.168."} {
		if bytes.Contains(first.Bytes(), []byte(forbidden)) {
			t.Fatal("projection contains non-synthetic material")
		}
	}
	doc.Layers[0].LayerWire = "mutated"
	doc.Projections[0].LayerNames[0] = "mutated"
	var fresh bytes.Buffer
	if runProjection(owned, &fresh) != nil || !bytes.Equal(first.Bytes(), fresh.Bytes()) {
		t.Fatal("consumer mutation changed producer authority")
	}
	for _, env := range []string{"", "false", "TRUE", "1"} {
		var output bytes.Buffer
		if runProjection(func(string) string { return env }, &output) != errFixture || output.Len() != 0 {
			t.Fatal("unowned projection generation wrote output")
		}
	}
	for _, output := range []io.Writer{nil, brokenOutput{}, brokenOutput{short: true}} {
		if runProjection(owned, output) != errFixture {
			t.Fatal("failed projection writer accepted")
		}
	}
	if runProjection(nil, os.Stdout) != errFixture {
		t.Fatal("missing Actions ownership accepted")
	}
}

func TestLayerProjectionOracleRemainsBoundToActualDecodeMergeAndMarshal(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture source unavailable")
	}
	set := token.NewFileSet()
	source, err := parser.ParseFile(set, filepath.Join(filepath.Dir(current), "main.go"), nil, 0)
	if err != nil {
		t.Fatal("cannot inspect projection producer")
	}
	functions := 0
	calls := map[string]int{}
	for _, node := range source.Decls {
		function, ok := node.(*ast.FuncDecl)
		if !ok || function.Name.Name != "projectionResult" {
			continue
		}
		functions++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok {
				calls[render(t, set, call.Fun)]++
			}
			return true
		})
	}
	if functions != 1 || calls["configuration.DecodeLayers"] != 1 || calls["configuration.Merge"] != 1 || calls["json.Marshal"] != 2 {
		t.Fatal("projection oracle detached from actual server primitives")
	}
}
