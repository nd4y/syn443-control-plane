package deviceprovisioning

import (
	"encoding/json"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRuntimeObservationViewContractMatchesUnknownAndReportedShapes(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/control-openapi.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("control contract")
	}
	compiler := jsonschema.NewCompiler()
	base := "https://contracts.example.invalid/control-openapi.json"
	if e = compiler.AddResource(base, doc); e != nil {
		t.Fatal(e)
	}
	schema, e := compiler.Compile(base + "#/components/schemas/ConfigurationRuntimeObservation")
	if e != nil {
		t.Fatal(e)
	}
	report := &RuntimeObservationView{RuntimeObservation: enrollment.RuntimeObservation{Version: 1, Sequence: 1, Build: 74, Phase: "online", PolicyRevision: 1, EngineKnown: true, EngineActive: true, Network: "wifi", SampledAtMs: 1800000000000}, ReceivedAtMs: 1800000000000}
	for _, input := range []ConfigurationRuntimeObservation{{Device: "device-a", ObservedAtMs: 1800000000000, State: "none"}, {Device: "device-a", ObservedAtMs: 1800000000000, State: "recent", Report: report}, {Device: "device-a", ObservedAtMs: 1800000200000, State: "stale", Report: report}} {
		raw, _ := json.Marshal(input)
		var value map[string]any
		json.Unmarshal(raw, &value)
		if e = schema.Validate(value); e != nil {
			t.Fatal("runtime response schema", e)
		}
		value["unexpected"] = "synthetic-private-field"
		if schema.Validate(value) == nil {
			t.Fatal("extra runtime response member accepted")
		}
	}
}
