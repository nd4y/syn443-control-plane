package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
