package configuration

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func networkGraph(t *testing.T) CompiledGraph {
	t.Helper()
	graph, err := CompileGraph(graphBase(), defaultGraphResolver())
	if err != nil {
		t.Fatal(err)
	}
	return graph
}
func networkBase() NetworkSettings {
	return NetworkSettings{SchemaVersion: 1, RequiredNetworks: []string{"tcp", "udp"}, DNSFinal: "system", DNSStrategy: "prefer_ipv4"}
}
func networkValue(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("invalid output")
	}
	return value
}
func cloneNetwork(t *testing.T, s NetworkSettings) NetworkSettings {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := DecodeNetworkSettings(raw)
	if err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestNetworkPlanEmitsScopedPerOutboundHealthChecks(t *testing.T) {
	graph := networkGraph(t)
	settings := networkBase()
	settings.RouteChecks = []OutboundCheckPlan{
		{Outbound: "entry", Required: true, Checks: []OutboundCheck{{Method: "ssh_banner", Target: "home.example.invalid:22"}, {Method: "tcp", Target: "[2001:db8::5]:443"}}},
		{Outbound: "tunnel", Checks: []OutboundCheck{{Method: "https_204", Target: "https://health.example.invalid/generate_204"}, {Method: "tls", Target: "https://health.example.invalid:443/"},
			{Method: "https_exit_ip", Target: "https://health.example.invalid/address", ExpectedIP: "2001:db8::9"}}},
	}
	raw, err := CompileNetwork(graph, cloneNetwork(t, settings))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Health []OutboundCheckPlan `json:"route_checks"`
	}
	if json.Unmarshal(raw, &out) != nil || !reflect.DeepEqual(out.Health, settings.RouteChecks) {
		t.Fatal("signed engine config lost per-outbound checks")
	}
	cases := []OutboundCheck{
		{Method: "icmp", Target: "node.example.invalid"},
		{Method: "tcp", Target: "node.example.invalid:65536"},
		{Method: "ssh_banner", Target: "user@node.example.invalid:22"},
		{Method: "https_204", Target: "http://health.example.invalid/"},
		{Method: "https_204", Target: "https://user@health.example.invalid/"},
		{Method: "tls", Target: "https://health.example.invalid/#"},
		{Method: "https_exit_ip", Target: "https://health.example.invalid/address"},
		{Method: "https_exit_ip", Target: "https://health.example.invalid/address", ExpectedIP: "::ffff:192.0.2.9"},
		{Method: "https_204", Target: "https://health.example.invalid/", ExpectedIP: "192.0.2.9"},
	}
	for _, item := range cases {
		bad := networkBase()
		bad.RouteChecks = []OutboundCheckPlan{{Outbound: "entry", Checks: []OutboundCheck{item}}}
		if _, err := CompileNetwork(graph, bad); err == nil {
			t.Fatal("unsupported or invalid check compiled", item.Method)
		}
	}
	settings.RouteChecks[0].Outbound = "missing"
	if _, err := CompileNetwork(graph, settings); err == nil {
		t.Fatal("probe can target an unassigned outbound")
	}
	settings.RouteChecks[0].Outbound = "tunnel"
	if _, err := CompileNetwork(graph, settings); err == nil {
		t.Fatal("duplicate outbound plan accepted")
	}
}

func TestInternalWifiFailoverRequiresComparableConcreteAuthorizedPaths(t *testing.T) {
	source := graphBase()
	source.Balancers["internal"] = Balancer{Type: "selector", Members: []string{"entry", "socks"}, Default: "entry"}
	graph, err := CompileGraph(source, defaultGraphResolver())
	if err != nil {
		t.Fatal(err)
	}
	settings := networkBase()
	settings.Rules = []RouteRule{{ID: "home", HostMatch: HostMatch{Domains: []string{"node.home.example.invalid"}},
		Networks: []string{"tcp"}, Action: "route", Outbound: "internal"}}
	settings.RouteFailover = &RouteFailoverPlan{Selector: "internal", NetworkMode: "wifi", Intent: "INTERNAL"}
	for _, tag := range []string{"internal", "entry", "socks"} {
		settings.RouteChecks = append(settings.RouteChecks, OutboundCheckPlan{Outbound: tag, Required: tag == "internal",
			Checks: []OutboundCheck{{Method: "tcp", Target: "node.home.example.invalid:22"}}})
	}
	raw, err := CompileNetwork(graph, settings)
	if err != nil || networkValue(t, raw)["route_failover"] == nil {
		t.Fatal("scoped internal failover was not emitted", err)
	}
	configured := cloneNetwork(t, settings)
	configured.RouteFailover.DecisionRevision = policy.ConfirmedFailoverAlgorithm
	rate := 1250
	configured.RouteFailover.DecisionRollout = &DeviceRollout{ID: "synthetic-variant", BasisPoints: &rate}
	configuredRaw, err := CompileNetwork(graph, configured)
	if err != nil || string(raw) != string(configuredRaw) {
		t.Fatal("algorithm rollout modified the engine configuration", err)
	}
	for _, change := range []func(*NetworkSettings){
		func(v *NetworkSettings) { v.RouteFailover.DecisionRevision = "untrusted-program" },
		func(v *NetworkSettings) {
			rate := 1250
			v.RouteFailover.DecisionRollout = &DeviceRollout{ID: "synthetic-variant", BasisPoints: &rate}
		},
		func(v *NetworkSettings) {
			rate := 10001
			v.RouteFailover.DecisionRevision = policy.ConfirmedFailoverAlgorithm
			v.RouteFailover.DecisionRollout = &DeviceRollout{ID: "synthetic-variant", BasisPoints: &rate}
		},
		func(v *NetworkSettings) { v.RouteFailover.NetworkMode = "cellular" },
		func(v *NetworkSettings) { v.RouteFailover.Intent = "NON_RU" },
		func(v *NetworkSettings) { v.Rules = nil },
		func(v *NetworkSettings) { v.RouteChecks[1].Checks[0].Target = "different.example.invalid:22" },
		func(v *NetworkSettings) { v.RouteChecks[1].Required = true },
		func(v *NetworkSettings) {
			rate := 500
			v.RouteFailover.ProbeCooldownRollout = &DeviceRollout{ID: "fixture", BasisPoints: &rate}
		},
		func(v *NetworkSettings) {
			v.RouteFailover.ProbeCooldown = true
			v.RouteFailover.ProbeCooldownRollout = &DeviceRollout{ID: "fixture"}
		},
	} {
		bad := cloneNetwork(t, settings)
		change(&bad)
		if _, err := CompileNetwork(graph, bad); err == nil {
			t.Fatal("failover widened scope or compared incompatible checks")
		}
	}
}

func TestNetworkCompilerEmitsTypedDNSRoutingAndApplicationRulesDeterministically(t *testing.T) {
	graph := networkGraph(t)
	settings := networkBase()
	settings.DNSServers = map[string]DNSServer{
		"secure":   {Transport: "https", Address: "resolver.example.invalid", Port: 443, ServerName: "resolver.example.invalid", Path: "/dns-query", Outbound: "tunnel"},
		"internal": {Transport: "udp", Address: "192.0.2.53", Port: 53, Outbound: "exit"},
	}
	settings.DNSFinal = "secure"
	settings.DNSRules = []DNSRule{{ID: "internal-domains", HostMatch: HostMatch{DomainSuffixes: []string{"home.example.invalid"}}, Server: "internal"}, {ID: "ipv6", QueryTypes: []string{"AAAA"}, Server: "system"}}
	settings.Rules = []RouteRule{
		{ID: "home", HostMatch: HostMatch{Domains: []string{"node.home.example.invalid"}, DomainSuffixes: []string{".home.example.invalid"}}, IPPrefixes: []string{"192.0.2.0/24", "2001:db8::/32"}, Packages: []string{"io.example.client"}, Ports: []PortRange{{22, 22}, {8000, 8100}}, Networks: []string{"tcp"}, Action: "route", Outbound: "entry"},
		{ID: "foreign", HostMatch: HostMatch{DomainKeywords: []string{"example"}, DomainRegex: []string{`^service[0-9]+\.example\.invalid$`}}, Action: "route", Outbound: "tunnel"},
		{ID: "block", MatchAll: true, Action: "reject"},
	}
	raw, err := CompileNetwork(graph, settings)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, e := CompileNetwork(graph, cloneNetwork(t, settings))
		if e != nil || string(again) != string(raw) {
			t.Fatal("non-deterministic network document", e)
		}
	}
	value := networkValue(t, raw)
	route := value["route"].(map[string]any)
	if route["final"] != "tunnel" || len(route["rules"].([]any)) != 3 {
		t.Fatal("lost ordered rules/final")
	}
	first := route["rules"].([]any)[0].(map[string]any)
	if first["outbound"] != "entry" || first["package_name"].([]any)[0] != "io.example.client" || first["port_range"].([]any)[0] != "8000:8100" {
		t.Fatal("lost portable routing semantics")
	}
	dns := value["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if dns["final"] != "secure" || len(servers) != 3 || servers[0].(map[string]any)["tag"] != "syn443_dns_system" || servers[1].(map[string]any)["tag"] != "internal" {
		t.Fatal("DNS order/final")
	}
	secure := servers[2].(map[string]any)
	if secure["detour"] != "tunnel" || secure["domain_resolver"] != "syn443_dns_system" || secure["tls"].(map[string]any)["server_name"] != "resolver.example.invalid" {
		t.Fatal("DNS transport escaped complete path or bootstrap")
	}
	if strings.Contains(fmt.Sprint(settings), "resolver.example") || strings.Contains(fmt.Sprintf("%#v", settings), "home.example") {
		t.Fatal("settings leaked through diagnostics")
	}
}

func TestNetworkCompilerChecksEveryDNSTransportAndProtocolCapability(t *testing.T) {
	graph := networkGraph(t)
	for _, transport := range []string{"local", "udp", "tcp", "tls", "https", "quic", "h3"} {
		t.Run(transport, func(t *testing.T) {
			settings := networkBase()
			server := DNSServer{Transport: transport}
			if transport != "local" {
				server.Address = "192.0.2.53"
				server.Port = 443
			}
			if transport == "https" || transport == "h3" {
				server.Path = "/dns-query"
			}
			settings.DNSServers = map[string]DNSServer{"resolver": server}
			settings.DNSFinal = "resolver"
			if _, err := CompileNetwork(graph, settings); err != nil {
				t.Fatal("supported DNS rejected", err)
			}
			if transport != "local" {
				raw, err := CompileNetwork(graph, settings)
				if err != nil {
					t.Fatal(err)
				}
				node := networkValue(t, raw)["dns"].(map[string]any)["servers"].([]any)[1].(map[string]any)
				if _, ok := node["detour"]; ok {
					t.Fatal("physical DNS emitted invalid empty-direct detour")
				}
				server.Outbound = "direct"
				settings.DNSServers["resolver"] = server
				again, err := CompileNetwork(graph, settings)
				if err != nil || string(again) != string(raw) {
					t.Fatal("explicit physical DNS changed dialer semantics", err)
				}
			}
			if transport == "udp" || transport == "quic" || transport == "h3" {
				server.Outbound = "entry"
				settings.DNSServers["resolver"] = server
				if _, err := CompileNetwork(graph, settings); err == nil {
					t.Fatal("UDP DNS silently crossed a TCP-only HTTP hop")
				}
			}
		})
	}
	graph.Final = "entry"
	settings := networkBase()
	if _, err := CompileNetwork(graph, settings); err == nil {
		t.Fatal("required UDP admitted by TCP-only graph")
	}
	settings.RequiredNetworks = []string{"tcp"}
	if _, err := CompileNetwork(graph, settings); err != nil {
		t.Fatal("explicit TCP-only profile rejected", err)
	}
}

func TestNetworkSettingsClosedDecodeAndDocumentBounds(t *testing.T) {
	base, _ := json.Marshal(networkBase())
	for _, raw := range []string{"null", "[]", "{", string(base) + "{}", strings.TrimSuffix(string(base), "}") + `,"setup_key":"forbidden"}`, strings.Replace(string(base), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1), strings.TrimSuffix(string(base), "}") + `,"rules":[null]}`, strings.Repeat("x", 262145)} {
		if _, err := DecodeNetworkSettings([]byte(raw)); err == nil {
			t.Fatal("ambiguous/unknown/unbounded settings accepted")
		}
	}
	// Omitted fields decode as empty and are independently validated by compile;
	// explicit null is never a portable value and deletion has its own operation.
	raw := []byte(`{"schemaVersion":1,"requiredNetworks":["tcp"],"dnsFinal":"system","dnsStrategy":"ipv4_only"}`)
	value, err := DecodeNetworkSettings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CompileNetwork(networkGraph(t), value); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkCompilerRejectsUnknownTargetsConflictingRangesAndImplicitCatchAll(t *testing.T) {
	graph := networkGraph(t)
	valid := RouteRule{ID: "rule", HostMatch: HostMatch{Domains: []string{"example.invalid"}}, Action: "route", Outbound: "tunnel"}
	cases := []func(*NetworkSettings){
		func(s *NetworkSettings) { s.SchemaVersion = 2 }, func(s *NetworkSettings) { s.RequiredNetworks = nil }, func(s *NetworkSettings) { s.RequiredNetworks = []string{"icmp"} }, func(s *NetworkSettings) { s.RequiredNetworks = []string{"tcp", "tcp"} },
		func(s *NetworkSettings) { s.DNSFinal = "missing" }, func(s *NetworkSettings) { s.DNSStrategy = "automatic-code" }, func(s *NetworkSettings) { s.Rules[0].ID = "bad/id" }, func(s *NetworkSettings) { s.Rules = append(s.Rules, s.Rules[0]) },
		func(s *NetworkSettings) { s.Rules[0].Outbound = "missing" }, func(s *NetworkSettings) { s.Rules[0].Action = "shell" }, func(s *NetworkSettings) { s.Rules[0].Action = "reject" }, func(s *NetworkSettings) { s.Rules[0].MatchAll = true },
		func(s *NetworkSettings) { s.Rules[0].HostMatch = HostMatch{} }, func(s *NetworkSettings) { s.Rules[0].Domains = []string{"EXAMPLE.invalid"} }, func(s *NetworkSettings) { s.Rules[0].Domains = []string{"127.0.0.1"} }, func(s *NetworkSettings) { s.Rules[0].Domains = []string{"bad..invalid"} },
		func(s *NetworkSettings) { s.Rules[0].DomainSuffixes = []string{"-bad.invalid"} }, func(s *NetworkSettings) { s.Rules[0].DomainKeywords = []string{"UPPER"} }, func(s *NetworkSettings) { s.Rules[0].DomainRegex = []string{"("} },
		func(s *NetworkSettings) { s.Rules[0].Domains = []string{"example.invalid", "example.invalid"} }, func(s *NetworkSettings) { s.Rules[0].IPPrefixes = []string{"192.0.2.1/24"} }, func(s *NetworkSettings) { s.Rules[0].Packages = []string{"not an app"} },
		func(s *NetworkSettings) { s.Rules[0].Networks = []string{"udp"}; s.Rules[0].Outbound = "entry" }, func(s *NetworkSettings) { s.Rules[0].Networks = []string{"icmp"} }, func(s *NetworkSettings) { s.Rules[0].Ports = []PortRange{{0, 1}} },
		func(s *NetworkSettings) { s.Rules[0].Ports = []PortRange{{2, 1}} }, func(s *NetworkSettings) { s.Rules[0].Ports = []PortRange{{1, 65536}} }, func(s *NetworkSettings) { s.Rules[0].Ports = []PortRange{{22, 22}, {22, 22}} }, func(s *NetworkSettings) { s.Rules[0].Ports = []PortRange{{1, 10}, {9, 20}} },
	}
	for index, change := range cases {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			settings := networkBase()
			settings.Rules = []RouteRule{valid}
			change(&settings)
			if _, err := CompileNetwork(graph, settings); err == nil {
				t.Fatal("invalid rule/config accepted")
			}
		})
	}
}

func TestNetworkCompilerRejectsDNSInjectionAndUnsupportedResolution(t *testing.T) {
	graph := networkGraph(t)
	valid := DNSServer{Transport: "https", Address: "dns.example.invalid", Port: 443, Path: "/dns-query"}
	for index, change := range []func(*DNSServer){
		func(s *DNSServer) { s.Transport = "exec" }, func(s *DNSServer) { s.Address = "https://dns.example.invalid/key" }, func(s *DNSServer) { s.Address = "" }, func(s *DNSServer) { s.Port = 0 }, func(s *DNSServer) { s.Port = 65536 },
		func(s *DNSServer) { s.ServerName = "https://bad.invalid" }, func(s *DNSServer) { s.Path = "//foreign.invalid/path" }, func(s *DNSServer) { s.Path = "/dns-query?token=forbidden" }, func(s *DNSServer) { s.Path = "relative" }, func(s *DNSServer) { s.Outbound = "missing" },
		func(s *DNSServer) { s.Transport = "udp"; s.Path = ""; s.ServerName = "dns.example.invalid" }, func(s *DNSServer) { s.Transport = "udp" }, func(s *DNSServer) { s.Transport = "local" },
	} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			s := networkBase()
			server := valid
			change(&server)
			s.DNSServers = map[string]DNSServer{"resolver": server}
			if _, err := CompileNetwork(graph, s); err == nil {
				t.Fatal("DNS injection accepted")
			}
		})
	}
	for _, tag := range []string{"system", "syn443_reserved", "bad/tag"} {
		s := networkBase()
		s.DNSServers = map[string]DNSServer{tag: valid}
		if _, err := CompileNetwork(graph, s); err == nil {
			t.Fatal("reserved DNS ID accepted")
		}
	}
	rule := DNSRule{ID: "dns", HostMatch: HostMatch{Domains: []string{"example.invalid"}}, Server: "system"}
	for _, change := range []func(*DNSRule){func(r *DNSRule) { r.ID = "bad/id" }, func(r *DNSRule) { r.Server = "missing" }, func(r *DNSRule) { r.HostMatch = HostMatch{} }, func(r *DNSRule) { r.QueryTypes = []string{"UNKNOWN"} }, func(r *DNSRule) { r.Domains = []string{"bad..invalid"} }} {
		s := networkBase()
		copy := rule
		change(&copy)
		s.DNSRules = []DNSRule{copy}
		if _, err := CompileNetwork(graph, s); err == nil {
			t.Fatal("invalid DNS rule accepted")
		}
	}
	s := networkBase()
	s.DNSRules = []DNSRule{rule, rule}
	if _, err := CompileNetwork(graph, s); err == nil {
		t.Fatal("duplicate DNS rule accepted")
	}
}

func TestNetworkCompilerBoundsAndDoesNotMutateCallerSettings(t *testing.T) {
	graph := networkGraph(t)
	s := networkBase()
	s.Rules = []RouteRule{{ID: "rule", HostMatch: HostMatch{Domains: []string{"example.invalid"}}, Action: "route", Outbound: "tunnel"}}
	before := cloneNetwork(t, s)
	if _, err := CompileNetwork(graph, s); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s, before) {
		t.Fatal("settings mutated")
	}
	for _, change := range []func(*NetworkSettings){func(s *NetworkSettings) { s.Rules = make([]RouteRule, 129) }, func(s *NetworkSettings) { s.DNSRules = make([]DNSRule, 65) }, func(s *NetworkSettings) {
		s.DNSServers = map[string]DNSServer{}
		for i := range 17 {
			s.DNSServers[fmt.Sprint(i)] = DNSServer{}
		}
	}, func(s *NetworkSettings) { s.Rules[0].Ports = make([]PortRange, 33) }, func(s *NetworkSettings) { s.Rules[0].Domains = make([]string, 65) }} {
		copy := cloneNetwork(t, s)
		change(&copy)
		if _, err := CompileNetwork(graph, copy); err == nil {
			t.Fatal("document bound bypassed")
		}
	}
	bad := graph
	bad.Final = "missing"
	if _, err := CompileNetwork(bad, s); err == nil {
		t.Fatal("missing final accepted")
	}
	bad = graph
	bad.Outbounds = nil
	if _, err := CompileNetwork(bad, s); err == nil {
		t.Fatal("empty graph accepted")
	}
	bad = graph
	bad.Outbounds = []json.RawMessage{json.RawMessage(`{`)}
	if _, err := CompileNetwork(bad, s); err == nil {
		t.Fatal("corrupt graph JSON accepted")
	}
}
