// Generates deterministic public layer-byte evidence in disposable Actions only.
// It has no input document, credentials, keys, database or network constructor.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		effective, err := configuration.Merge(context.Background(), input, func(raw json.RawMessage) error {
			_, err := configuration.DecodeNetworkPlan(raw)
			return err
		})
		if err != nil {
			return fixtureDocument{}, errFixture
		}
		plan, err := configuration.DecodeNetworkPlan(effective.Document)
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
	if run(os.Getenv, os.Stdout) != nil {
		os.Stderr.WriteString("layer_fixture_failed\n")
		os.Exit(1)
	}
}
