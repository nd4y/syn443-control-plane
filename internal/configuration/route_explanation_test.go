package configuration

import (
	"fmt"
	"strings"
	"testing"
)

func TestManualTrafficExplanationMatchesOrderedDNSAndDestinationGroups(t *testing.T) {
	home := HostMatch{DomainSuffixes: []string{"home.example.invalid"}}
	s := NetworkSettings{SchemaVersion: 1, DNSFinal: "system",
		Rules: []RouteRule{
			{ID: "work", Action: "route", Outbound: "work-chain", HostMatch: home, IPPrefixes: []string{"2001:db8::/32", "192.0.2.0/24"}, Ports: []PortRange{{443, 443}, {8000, 8100}}, Networks: []string{"tcp"}, Packages: []string{"org.example.work"}},
			{ID: "other", Action: "reject", MatchAll: true},
		},
		DNSRules: []DNSRule{{ID: "internal", HostMatch: home, QueryTypes: []string{"A", "AAAA"}, Server: "internal-dns"}},
	}
	q := TrafficQuery{Domain: "NODE.HOME.EXAMPLE.INVALID.", Network: "tcp", Port: 443, Application: "org.example.work", DNSType: "A"}
	assert := func(q TrafficQuery, route, dns RuleDecision) {
		t.Helper()
		got, err := ExplainTraffic(s, "direct", q)
		if err != nil || got.Route != route || got.DNS != dns {
			t.Fatalf("got %#v, %v; want %#v / %#v", got, err, route, dns)
		}
	}
	work := RuleDecision{"matched", "work", "work-chain"}
	deny := RuleDecision{Status: "matched", Rule: "other"}
	internal := RuleDecision{"matched", "internal", "internal-dns"}
	fallback := RuleDecision{Status: "default", Target: "system"}
	assert(q, work, internal)
	q.Domain = "public.example.invalid"
	q.Address = "2001:db8::1"
	q.Port = 8000
	assert(q, work, fallback)
	q.Domain = ""
	q.Address = "192.0.2.1"
	q.Port = 8100
	assert(q, work, RuleDecision{Status: "not_applicable"})
	q.Domain = "public.example.invalid"
	q.Address = ""
	q.Port = 0
	assert(q, RuleDecision{Status: "incomplete", Rule: "work"}, fallback)
	q.Network = "udp"
	assert(q, deny, fallback)
	q.Domain = "home.example.invalid"
	q.DNSType = ""
	assert(q, deny, RuleDecision{Status: "incomplete", Rule: "internal"})
	q.DNSType = "TXT"
	assert(q, deny, fallback)
	q.Domain = ""
	q.DNSType = ""
	assert(q, deny, RuleDecision{Status: "incomplete"})
}

func TestManualTrafficExplanationValidatesAllRulesAndKeepsTargetsPrivate(t *testing.T) {
	s := NetworkSettings{SchemaVersion: 1, DNSFinal: "system", Rules: []RouteRule{
		{ID: "subdomains", Action: "route", Outbound: "proxy", HostMatch: HostMatch{DomainSuffixes: []string{".example.invalid"}}},
		{ID: "exact", Action: "reject", HostMatch: HostMatch{DomainRegex: []string{`^example\.invalid$`}, DomainKeywords: []string{"denied"}}},
	}}
	for host, want := range map[string]string{"sub.example.invalid": "subdomains", "example.invalid": "exact", "denied.example": "exact", "badexample.invalid": ""} {
		got, err := ExplainTraffic(s, "direct", TrafficQuery{Domain: host})
		if err != nil || got.Route.Rule != want || want == "" && got.Route.Target != "direct" {
			t.Fatal(host, got, err)
		}
	}
	for _, q := range []TrafficQuery{{}, {Address: "2001:db8::1%eth0"}, {Domain: "https://example.invalid"}, {Domain: "."}, {Domain: "127.0.0.1"}, {Application: "bad/path"}, {Domain: "x", Port: 65536}, {Domain: "x", Network: "quic"}, {Domain: "x", DNSType: "X"}} {
		if _, err := ExplainTraffic(s, "direct", q); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	q := TrafficQuery{Domain: "private.example.invalid"}
	if strings.Contains(fmt.Sprintf("%v %#v", q, q), "private.example.invalid") {
		t.Fatal("query diagnostic disclosed hostname")
	}
	// Validate even the unreachable tail, after the first rule matched.
	for _, invalid := range []RouteRule{{ID: "wrong", MatchAll: true, Action: "publish"}, {ID: "subdomains", MatchAll: true, Action: "reject"}, {ID: "wrong", HostMatch: HostMatch{DomainRegex: []string{"("}}, Action: "reject"}} {
		test := s
		test.Rules = append(append([]RouteRule(nil), s.Rules...), invalid)
		if _, err := ExplainTraffic(test, "direct", q); err == nil {
			t.Fatal("invalid later rule accepted")
		}
	}
	s.DNSRules = []DNSRule{{ID: "invalid", Server: "system"}}
	if _, err := ExplainTraffic(s, "direct", TrafficQuery{Address: "192.0.2.1"}); err == nil {
		t.Fatal("bad DNS tail ignored for a literal address")
	}
}
