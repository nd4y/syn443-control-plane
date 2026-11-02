package configuration

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func graphRef(kind string) ProfileReference { return ProfileReference{"source-a", "source-a_" + kind} }
func graphNode(kind string) map[string]any {
	node := map[string]any{"type": kind, "tag": graphRef(kind).ProfileID, "server": "proxy.example.invalid", "server_port": 443}
	if kind == "vless" {
		node["uuid"] = "00000000-0000-0000-0000-000000000000"
	}
	if kind == "ssh" {
		node["user"] = "fixture-user"
		node["password"] = "fixture-password"
		node["host_key"] = []string{"ssh-ed25519 synthetic-fixture-host-key"}
	}
	return node
}
func graphResolver(nodes map[string]map[string]any) func(ProfileReference) (subscriptions.Profile, error) {
	return func(ref ProfileReference) (subscriptions.Profile, error) {
		for kind, node := range nodes {
			if ref == graphRef(kind) {
				raw, _ := json.Marshal(node)
				return subscriptions.Profile{ID: ref.ProfileID, Kind: kind, Outbound: raw}, nil
			}
		}
		return subscriptions.Profile{}, ErrInvalid
	}
}
func graphBase() Graph {
	return Graph{Profiles: map[string]ProfileReference{"entry": graphRef("http"), "exit": graphRef("vless"), "socks": graphRef("socks")}, Chains: map[string]Chain{"tunnel": {[]string{"entry", "exit"}}}, Balancers: map[string]Balancer{}, Final: "tunnel"}
}
func defaultGraphResolver() func(ProfileReference) (subscriptions.Profile, error) {
	return graphResolver(map[string]map[string]any{"http": graphNode("http"), "vless": graphNode("vless"), "socks": graphNode("socks")})
}
func graphOutbounds(t *testing.T, g CompiledGraph) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, raw := range g.Outbounds {
		var node map[string]any
		if json.Unmarshal(raw, &node) != nil {
			t.Fatal("compiled JSON")
		}
		tag := node["tag"].(string)
		if out[tag] != nil {
			t.Fatal("duplicate generated tag")
		}
		out[tag] = node
	}
	return out
}
func TestGraphCompilationPreservesWireCredentialsOrdersDetoursAndReportsTransportCapabilities(t *testing.T) {
	g := graphBase()
	nodes := map[string]map[string]any{"http": graphNode("http"), "vless": graphNode("vless"), "socks": graphNode("socks")}
	nodes["http"]["password"] = "fixture-password"
	before, _ := json.Marshal(nodes)
	out, e := CompileGraph(g, graphResolver(nodes))
	if e != nil {
		t.Fatal(e)
	}
	wires := graphOutbounds(t, out)
	if wires["tunnel"]["detour"] != "entry" || wires["tunnel"]["type"] != "vless" || wires["entry"]["password"] != "fixture-password" {
		t.Fatal("actual dial-order/profile parameters changed")
	}
	if got := out.Capabilities["tunnel"]; got != (GraphCapability{TCP: true, UDP: true, Hops: 2}) {
		t.Fatal("VLESS datagrams over TCP detour", got)
	}
	g.Chains["tunnel"] = Chain{[]string{"entry", "socks"}}
	out, e = CompileGraph(g, graphResolver(nodes))
	if e != nil || out.Capabilities["tunnel"].UDP {
		t.Fatal("SOCKS UDP silently assumed over CONNECT", e)
	}
	if after, _ := json.Marshal(nodes); string(after) != string(before) {
		t.Fatal("compiler mutated source profile")
	}
	again, e := CompileGraph(g, graphResolver(nodes))
	if e != nil || !reflect.DeepEqual(again, out) {
		t.Fatal("graph output nondeterministic")
	}
	if !reflect.DeepEqual(out.RequiredEngineFeatures, []string{"http", "socks", "vless"}) {
		t.Fatal("deterministic feature manifest")
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", g, g, out, out), "fixture-password") {
		t.Fatal("configuration diagnostics leaked credentials")
	}
}
func TestGraphDirectSharedReferencesAndFeatureDetails(t *testing.T) {
	out, e := CompileGraph(Graph{Final: "direct"}, nil)
	if e != nil || len(out.Outbounds) != 1 || !out.Capabilities["direct"].UDP {
		t.Fatal("explicit direct graph", e)
	}
	g := Graph{Profiles: map[string]ProfileReference{"one": graphRef("vless"), "two": graphRef("vless")}, Chains: map[string]Chain{"alias": {[]string{"one"}}}, Final: "alias"}
	node := graphNode("vless")
	node["tls"] = map[string]any{"enabled": true, "server_name": "proxy.example.invalid", "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "short_id": ""}}
	node["transport"] = map[string]any{"type": "xhttp", "mode": "auto", "path": "/"}
	base := graphResolver(map[string]map[string]any{"vless": node})
	calls := 0
	out, e = CompileGraph(g, func(ref ProfileReference) (subscriptions.Profile, error) { calls++; return base(ref) })
	if e != nil || calls != 1 {
		t.Fatal("shared immutable profile fetched repeatedly", e)
	}
	if !reflect.DeepEqual(out.RequiredEngineFeatures, []string{"vless", "vless.reality", "vless.tls", "vless.xhttp"}) {
		t.Fatal("TLS/Reality/transport feature requirements missing")
	}
	if graphOutbounds(t, out)["alias"]["type"] != "selector" {
		t.Fatal("single-node alias missing")
	}
	for _, kind := range []string{"ssh", "socks", "http", "vless"} {
		node := graphNode(kind)
		if kind == "socks" {
			node["version"] = "4a"
		}
		if kind == "vless" {
			node["network"] = "udp"
		}
		out, e = CompileGraph(Graph{Profiles: map[string]ProfileReference{"leaf": graphRef(kind)}, Final: "leaf"}, graphResolver(map[string]map[string]any{kind: node}))
		if e != nil {
			t.Fatal(kind, e)
		}
		c := out.Capabilities["leaf"]
		if kind == "vless" {
			if c.TCP || !c.UDP {
				t.Fatal("UDP-only profile widened")
			}
		} else if c.UDP {
			t.Fatal("TCP-only profile widened")
		}
	}
}
func TestGraphEntryBalancersNestedPrefixesAndFourHopBound(t *testing.T) {
	g := graphBase()
	g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"entry", "socks"}, Default: "socks"}
	g.Chains["tunnel"] = Chain{[]string{"pick", "exit"}}
	out, e := CompileGraph(g, defaultGraphResolver())
	if e != nil || out.Capabilities["tunnel"].Hops != 2 || !out.Capabilities["tunnel"].UDP {
		t.Fatal("selector entry chain", e)
	}
	g.Chains["long"] = Chain{[]string{"tunnel", "entry", "exit"}}
	g.Final = "long"
	out, e = CompileGraph(g, defaultGraphResolver())
	if e != nil || out.Capabilities["long"].Hops != 4 {
		t.Fatal("four-hop prefix rejected", e)
	}
	nodes := graphOutbounds(t, out)
	if nodes["long"]["detour"] != "syn443_hop_long_1" || nodes["syn443_hop_long_1"]["detour"] != "tunnel" {
		t.Fatal("nested dial order lost")
	}
	g.Chains["fifth"] = Chain{[]string{"long", "exit"}}
	if _, e = CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
		t.Fatal("fifth hop accepted", e)
	}
	g = graphBase()
	g.Balancers["probe"] = Balancer{Type: "urltest", Members: []string{"entry", "socks"}, URL: "https://health.example.invalid/204", IntervalSeconds: 30, ToleranceMs: 100, InterruptExisting: true}
	g.Final = "probe"
	out, e = CompileGraph(g, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	probe := graphOutbounds(t, out)["probe"]
	if probe["interval"] != "30s" || probe["tolerance"] != float64(100) || probe["interrupt_exist_connections"] != true {
		t.Fatal("URL-test wire options changed")
	}
}
func TestGraphRejectsMalformedGraphsResolverFailuresAndUntrustedProfiles(t *testing.T) {
	for name, change := range map[string]func(*Graph){
		"final": func(g *Graph) { g.Final = "missing" }, "tag": func(g *Graph) { g.Profiles["bad/tag"] = graphRef("http") }, "reserved": func(g *Graph) { g.Profiles["direct"] = graphRef("http") }, "internal": func(g *Graph) { g.Profiles["syn443_hop_private"] = graphRef("http") }, "collision": func(g *Graph) { g.Chains["entry"] = Chain{[]string{"exit"}} }, "source": func(g *Graph) { g.Profiles["entry"] = ProfileReference{"bad/source", "p"} }, "profile": func(g *Graph) { g.Profiles["entry"] = ProfileReference{"source-a", "bad/profile"} },
		"empty-chain": func(g *Graph) { g.Chains["tunnel"] = Chain{} }, "too-long": func(g *Graph) { g.Chains["tunnel"] = Chain{[]string{"entry", "exit", "socks", "direct", "entry"}} }, "duplicate-hop": func(g *Graph) { g.Chains["tunnel"] = Chain{[]string{"entry", "entry"}} }, "self-chain": func(g *Graph) { g.Chains["tunnel"] = Chain{[]string{"tunnel"}} }, "dangling-hop": func(g *Graph) { g.Chains["tunnel"] = Chain{[]string{"missing", "exit"}} }, "chain-cycle": func(g *Graph) {
			g.Chains["other"] = Chain{[]string{"tunnel"}}
			g.Chains["tunnel"] = Chain{[]string{"other"}}
		},
		"later-selector": func(g *Graph) {
			g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"exit"}}
			g.Chains["tunnel"] = Chain{[]string{"entry", "pick"}}
		}, "empty-selector": func(g *Graph) { g.Balancers["pick"] = Balancer{Type: "selector"} }, "duplicate-member": func(g *Graph) { g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"exit", "exit"}} }, "unknown-selector": func(g *Graph) { g.Balancers["pick"] = Balancer{Type: "unknown", Members: []string{"exit"}} }, "selector-cycle": func(g *Graph) {
			g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"other"}}
			g.Balancers["other"] = Balancer{Type: "selector", Members: []string{"pick"}}
		}, "selector-default": func(g *Graph) {
			g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"exit"}, Default: "missing"}
		}, "selector-url": func(g *Graph) {
			g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"exit"}, URL: "https://health.example.invalid/204"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := graphBase()
			change(&g)
			if _, e := CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
				t.Fatal("invalid graph accepted", e)
			}
		})
	}
	if _, e := CompileGraph(graphBase(), nil); !errors.Is(e, ErrInvalid) {
		t.Fatal("missing source resolver accepted")
	}
	denied := errors.New("source_denied")
	if _, e := CompileGraph(graphBase(), func(ProfileReference) (subscriptions.Profile, error) { return subscriptions.Profile{}, denied }); !errors.Is(e, denied) {
		t.Fatal("source denial hidden")
	}
	for _, change := range []func(*subscriptions.Profile){func(p *subscriptions.Profile) { p.ID = "foreign" }, func(p *subscriptions.Profile) { p.Outbound = []byte("{") }, func(p *subscriptions.Profile) { p.Kind = "socks" }, func(p *subscriptions.Profile) { p.Outbound = []byte(`{"type":"direct","tag":"source-a_http"}`) }, func(p *subscriptions.Profile) {
		p.Outbound = []byte(`{"type":"http","tag":"wrong","server":"proxy.example.invalid","server_port":443}`)
	}} {
		base := defaultGraphResolver()
		if _, e := CompileGraph(graphBase(), func(ref ProfileReference) (subscriptions.Profile, error) { p, e := base(ref); change(&p); return p, e }); !errors.Is(e, ErrInvalid) {
			t.Fatal("untrusted profile escaped", e)
		}
	}
	ssh := graphNode("ssh")
	delete(ssh, "host_key")
	if _, e := CompileGraph(Graph{Profiles: map[string]ProfileReference{"ssh": graphRef("ssh")}, Final: "ssh"}, graphResolver(map[string]map[string]any{"ssh": ssh})); !errors.Is(e, ErrInvalid) {
		t.Fatal("unpinned SSH accepted")
	}
}
func TestGraphURLTestBoundsAndUDPOnlyEntryFailures(t *testing.T) {
	valid := Balancer{Type: "urltest", Members: []string{"entry"}, URL: "https://health.example.invalid/204", IntervalSeconds: 30}
	for _, change := range []func(*Balancer){func(b *Balancer) { b.URL = "http://health.example.invalid" }, func(b *Balancer) { b.URL = "https://health.example.invalid/#fragment" }, func(b *Balancer) { b.URL = "https://" }, func(b *Balancer) { b.URL = "https://health.example.invalid/" + strings.Repeat("x", 2048) }, func(b *Balancer) { b.IntervalSeconds = 29 }, func(b *Balancer) { b.IntervalSeconds = 86401 }, func(b *Balancer) { b.ToleranceMs = -1 }, func(b *Balancer) { b.ToleranceMs = 10001 }, func(b *Balancer) { b.Default = "entry" }, func(b *Balancer) { b.Members = make([]string, 17) }} {
		b := valid
		change(&b)
		g := graphBase()
		g.Balancers["probe"] = b
		if _, e := CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid URL-test admitted", e)
		}
	}
	node := graphNode("vless")
	node["network"] = "udp"
	resolver := graphResolver(map[string]map[string]any{"vless": node, "http": graphNode("http")})
	g := Graph{Profiles: map[string]ProfileReference{"udp": graphRef("vless"), "tcp": graphRef("http")}, Chains: map[string]Chain{"bad": {[]string{"udp", "tcp"}}}, Final: "bad"}
	if _, e := CompileGraph(g, resolver); !errors.Is(e, ErrInvalid) {
		t.Fatal("UDP-only outbound carried a proxy control TCP socket")
	}
	g.Chains = nil
	g.Balancers = map[string]Balancer{"bad": {Type: "urltest", Members: []string{"udp"}, URL: valid.URL, IntervalSeconds: 30}}
	if _, e := CompileGraph(g, resolver); !errors.Is(e, ErrInvalid) {
		t.Fatal("URL-test used a UDP-only branch")
	}
}
func TestGraphSchemaAndResourceBudgets(t *testing.T) {
	good := `{"profiles":{},"chains":{},"balancers":{},"final":"direct"}`
	g, e := DecodeGraph([]byte(good))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = CompileGraph(g, nil); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{`{"final":"direct","unknown":true}`, `{"final":"direct","final":"direct"}`, `{"profiles":null,"final":"direct"}`, strings.Repeat(" ", 262145)} {
		if _, e = DecodeGraph([]byte(raw)); !errors.Is(e, ErrInvalid) {
			t.Fatal("nonportable graph admitted", e)
		}
	}
	for _, kind := range []string{"profiles", "chains", "balancers"} {
		g = graphBase()
		switch kind {
		case "profiles":
			for i := 0; i < 33; i++ {
				g.Profiles[fmt.Sprintf("node%d", i)] = graphRef("http")
			}
		case "chains":
			for i := 0; i < 17; i++ {
				g.Chains[fmt.Sprintf("chain%d", i)] = Chain{[]string{"entry"}}
			}
		case "balancers":
			for i := 0; i < 17; i++ {
				g.Balancers[fmt.Sprintf("pick%d", i)] = Balancer{Type: "selector", Members: []string{"entry"}}
			}
		}
		if _, e = CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
			t.Fatal("graph count budget bypassed")
		}
	}
	g = graphBase()
	g.Chains = map[string]Chain{}
	for i := 0; i < 16; i++ {
		g.Chains[fmt.Sprintf("chain%d", i)] = Chain{[]string{"entry", "exit", "socks", "exit"}}
	}
	// Use distinct aliases for repeated physical profiles to test wire-node count
	// independently of the duplicate logical-hop rejection.
	g.Profiles["last"] = graphRef("vless")
	g.Final = "chain0"
	for i := 0; i < 13; i++ {
		g.Profiles[fmt.Sprintf("extra%d", i)] = graphRef("http")
	}

	for tag := range g.Chains {
		g.Chains[tag] = Chain{[]string{"entry", "exit", "socks", "last"}}
	}
	if _, e = CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
		t.Fatal("64 outbound budget bypassed")
	}
	g = Graph{Profiles: map[string]ProfileReference{}, Final: "direct"}
	for i := 0; i < 32; i++ {
		g.Profiles[fmt.Sprintf("p%d", i)] = graphRef("http")
	}
	node := graphNode("http")
	node["username"] = strings.Repeat("u", 8192)
	node["password"] = strings.Repeat("p", 8192)
	if _, e = CompileGraph(g, graphResolver(map[string]map[string]any{"http": node})); !errors.Is(e, ErrInvalid) {
		t.Fatal("compiled credential memory budget bypassed")
	}
}
