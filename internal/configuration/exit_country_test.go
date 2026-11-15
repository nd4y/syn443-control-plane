package configuration

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestExitCountryNetworkCompilerKeepsExplicitExpectedClass(t *testing.T) {
	graph := networkGraph(t)
	for _, expected := range []string{"RU", "NON_RU"} {
		for _, target := range []string{"https://country.example.invalid", "https://country.example.invalid/", "https://country.example.invalid:8443/", "https://[2001:db8::9]/"} {
			settings := networkBase()
			settings.RouteChecks = []OutboundCheckPlan{{Outbound: "entry", Checks: []OutboundCheck{{Method: "https_exit_country", Target: target, ExpectedExitClass: expected}}}}
			raw, err := CompileNetwork(graph, cloneNetwork(t, settings))
			if err != nil {
				t.Fatal(err)
			}
			var out struct {
				Checks []OutboundCheckPlan `json:"route_checks"`
			}
			if json.Unmarshal(raw, &out) != nil || !reflect.DeepEqual(out.Checks, settings.RouteChecks) {
				t.Fatal("expected country class or exact candidate check was lost")
			}
		}
	}
}

func TestExitCountryNetworkCompilerRejectsAmbiguousTargetsAndPredicates(t *testing.T) {
	graph := networkGraph(t)
	base := OutboundCheck{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "RU"}
	for _, mutate := range []func(*OutboundCheck){
		func(c *OutboundCheck) { c.ExpectedExitClass = "" },
		func(c *OutboundCheck) { c.ExpectedExitClass = "US" },
		func(c *OutboundCheck) { c.ExpectedExitClass = "ru" },
		func(c *OutboundCheck) { c.ExpectedExitClass = "INTERNAL" },
		func(c *OutboundCheck) { c.ExpectedIP = "192.0.2.9" },
		func(c *OutboundCheck) { c.Target = "http://country.example.invalid/" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid/192.0.2.9" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid/?ip=192.0.2.9" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid/?" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid/#" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid/%2f" },
		func(c *OutboundCheck) { c.Target = "https://user@country.example.invalid/" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid:0/" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid:/" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid:65536/" },
		func(c *OutboundCheck) { c.Target = "https://country.example.invalid/\n" },
		func(c *OutboundCheck) { c.Target = strings.Repeat("a", 2049) },
		func(c *OutboundCheck) { c.Method = "https_204" },
		func(c *OutboundCheck) { c.Method = "tls" },
		func(c *OutboundCheck) { c.Method = "tcp"; c.Target = "country.example.invalid:443" },
		func(c *OutboundCheck) { c.Method = "https_exit_ip"; c.ExpectedIP = "192.0.2.9" },
	} {
		check := base
		mutate(&check)
		settings := networkBase()
		settings.RouteChecks = []OutboundCheckPlan{{Outbound: "entry", Checks: []OutboundCheck{check}}}
		if _, err := CompileNetwork(graph, settings); err == nil {
			t.Fatal("unsupported country predicate or arbitrary-IP lookup compiled")
		}
	}
}

func TestExitCountryDecoderDoesNotDiscardCrossMethodNullOrEmptyFields(t *testing.T) {
	for _, check := range []string{
		`{"method":"https_204","target":"https://country.example.invalid/","expected_exit_class":""}`,
		`{"method":"https_204","target":"https://country.example.invalid/","expected_exit_class":null}`,
		`{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU","expected_ip":""}`,
		`{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU","expected_ip":null}`,
		`{"method":"https_exit_country","target":"https://country.example.invalid/"}`,
		`{"method":"https_exit_ip","target":"https://country.example.invalid/","expected_ip":"192.0.2.9","expected_exit_class":""}`,
	} {
		raw := []byte(`{"schemaVersion":1,"requiredNetworks":["tcp"],"dnsFinal":"system","dnsStrategy":"prefer_ipv4","routeChecks":[{"outbound":"entry","required":false,"checks":[` + check + `]}]}`)
		if _, err := DecodeNetworkSettings(raw); err == nil {
			t.Fatal("decoder discarded a missing or cross-method field")
		}
	}
}

func TestInternalFailoverCannotUsePublicExitCountryAsInternalEvidence(t *testing.T) {
	source := graphBase()
	source.Balancers["internal"] = Balancer{Type: "selector", Members: []string{"entry", "socks"}, Default: "entry"}
	graph, err := CompileGraph(source, defaultGraphResolver())
	if err != nil {
		t.Fatal(err)
	}
	settings := networkBase()
	settings.Rules = []RouteRule{{ID: "home", HostMatch: HostMatch{Domains: []string{"home.example.invalid"}}, Networks: []string{"tcp"}, Action: "route", Outbound: "internal"}}
	settings.RouteFailover = &RouteFailoverPlan{Selector: "internal", NetworkMode: "wifi", Intent: "INTERNAL"}
	for _, tag := range []string{"internal", "entry", "socks"} {
		settings.RouteChecks = append(settings.RouteChecks, OutboundCheckPlan{Outbound: tag, Required: tag == "internal", Checks: []OutboundCheck{{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "NON_RU"}}})
	}
	if _, err := CompileNetwork(graph, settings); err == nil {
		t.Fatal("public country response authorized internal failover")
	}
}

func TestExitCountryOpenAPIClosesMethodSpecificPredicateFields(t *testing.T) {
	raw, err := contracts.Files.ReadFile("v1/control-openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("invalid contract")
	}
	compiler := jsonschema.NewCompiler()
	base := "https://contracts.example.invalid/control-openapi.json"
	if err := compiler.AddResource(base, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(base + "#/components/schemas/PlanOutboundChecks/properties/checks/items")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"RU", "NON_RU"} {
		if err := schema.Validate(map[string]any{"method": "https_exit_country", "target": "https://country.example.invalid/", "expected_exit_class": expected}); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []map[string]any{
		{"method": "https_exit_country", "target": "https://country.example.invalid/"},
		{"method": "https_exit_country", "target": "https://country.example.invalid/", "expected_exit_class": "US"},
		{"method": "https_exit_country", "target": "https://country.example.invalid/", "expected_exit_class": nil},
		{"method": "https_exit_country", "target": "https://country.example.invalid/", "expected_exit_class": "RU", "expected_ip": "192.0.2.9"},
		{"method": "https_204", "target": "https://country.example.invalid/", "expected_exit_class": "RU"},
		{"method": "https_exit_ip", "target": "https://country.example.invalid/", "expected_ip": "192.0.2.9", "expected_exit_class": "RU"},
		{"method": "https_exit_ip", "target": "https://country.example.invalid/"},
		{"method": "https_exit_country", "target": "https://country.example.invalid/", "expected_exit_class": "RU", "country": "RU"},
	} {
		if schema.Validate(value) == nil {
			t.Fatal("contract accepted unknown, missing or cross-method predicate")
		}
	}
}
