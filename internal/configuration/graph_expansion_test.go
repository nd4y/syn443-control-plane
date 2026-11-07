package configuration

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func branchTags(t *testing.T, node map[string]any) []string {
	t.Helper()
	raw, e := json.Marshal(node["outbounds"])
	if e != nil {
		t.Fatal(e)
	}
	var tags []string
	if json.Unmarshal(raw, &tags) != nil {
		t.Fatal("compiled group members")
	}
	return tags
}
func TestGraphLaterSelectorExpandsEveryExitThroughTheActualEntry(t *testing.T) {
	g := graphBase()
	g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"exit", "socks"}, Default: "socks", InterruptExisting: true}
	g.Chains["tunnel"] = Chain{[]string{"entry", "pick"}}
	out, e := CompileGraph(g, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	nodes := graphOutbounds(t, out)
	group := nodes["tunnel"]
	members := branchTags(t, group)
	if group["type"] != "selector" || group["interrupt_exist_connections"] != true || len(members) != 2 || group["default"] != members[1] {
		t.Fatal("later selector's ordered/default semantics lost")
	}
	for _, tag := range members {
		if nodes[tag]["detour"] != "entry" || !strings.HasPrefix(tag, "syn443_expanded_") {
			t.Fatal("selected exit bypassed incoming entry")
		}
	}
	if nodes[members[0]]["type"] != "vless" || nodes[members[1]]["type"] != "socks" {
		t.Fatal("wrong selected exit types")
	}
	// HTTP cannot carry SOCKS's physical UDP. An all-branches capability must not
	// borrow the other VLESS branch's UDP-over-TCP capability.
	if out.Capabilities["tunnel"].UDP || !out.Capabilities["tunnel"].TCP || out.Capabilities["tunnel"].Hops != 2 {
		t.Fatal("later group widened transport capability")
	}
	again, e := CompileGraph(g, defaultGraphResolver())
	if e != nil || !reflect.DeepEqual(out, again) {
		t.Fatal("context expansion is nondeterministic")
	}
}
func TestGraphNestedLaterChainAndURLTestMeasureTheCompletePrefix(t *testing.T) {
	g := graphBase()
	g.Chains["tail"] = Chain{[]string{"socks", "exit"}}
	g.Balancers["pick"] = Balancer{Type: "urltest", Members: []string{"tail", "exit"}, URL: "https://health.example.invalid/204", IntervalSeconds: 30, ToleranceMs: 50, InterruptExisting: true}
	g.Chains["tunnel"] = Chain{[]string{"entry", "pick"}}
	out, e := CompileGraph(g, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	nodes := graphOutbounds(t, out)
	group := nodes["tunnel"]
	members := branchTags(t, group)
	if group["type"] != "urltest" || group["url"] != "https://health.example.invalid/204" || group["interval"] != "30s" || group["tolerance"] != float64(50) {
		t.Fatal("cloned URL-test lost probe configuration")
	}
	tail := nodes[members[0]]
	middle, ok := tail["detour"].(string)
	if !ok || nodes[middle]["detour"] != "entry" || nodes[middle]["type"] != "socks" || tail["type"] != "vless" {
		t.Fatal("later chain failed to prepend entry to every physical hop")
	}
	if nodes[members[1]]["detour"] != "entry" || out.Capabilities["tunnel"].Hops != 3 || !out.Capabilities["tunnel"].UDP {
		t.Fatal("complete selected path capabilities lost")
	}
	// Nested selectors must preserve their own default after clone renaming.
	g.Balancers["inner"] = Balancer{Type: "selector", Members: []string{"exit", "tail"}, Default: "tail"}
	g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"inner"}, Default: "inner"}
	out, e = CompileGraph(g, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	nodes = graphOutbounds(t, out)
	outer := nodes["tunnel"]
	inner := nodes[branchTags(t, outer)[0]]
	innerMembers := branchTags(t, inner)
	if inner["default"] != innerMembers[1] || outer["default"] != branchTags(t, outer)[0] {
		t.Fatal("nested selected defaults leaked standalone tags")
	}
}
func TestGraphLaterDirectIsAnAliasOfItsPrefixAndNeverPhysicalEscape(t *testing.T) {
	g := graphBase()
	g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"direct", "exit"}, Default: "direct"}
	g.Chains["tunnel"] = Chain{[]string{"entry", "pick"}}
	out, e := CompileGraph(g, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	nodes := graphOutbounds(t, out)
	members := branchTags(t, nodes["tunnel"])
	alias := nodes[members[0]]
	if alias["type"] != "selector" || !reflect.DeepEqual(branchTags(t, alias), []string{"entry"}) || alias["default"] != "entry" {
		t.Fatal("later direct dropped an explicitly required entry")
	}
	if out.Capabilities["tunnel"].UDP {
		t.Fatal("direct alias widened TCP-only prefix to physical UDP")
	}
	g.Chains["tunnel"] = Chain{[]string{"entry", "direct"}}
	out, e = CompileGraph(g, defaultGraphResolver())
	if e != nil {
		t.Fatal(e)
	}
	if out.Capabilities["tunnel"].Hops != 1 {
		t.Fatal("identity alias counted as another proxy")
	}
}
func TestGraphContextExpansionEnforcesPhysicalHopAndNodeBudgets(t *testing.T) {
	g := graphBase()
	g.Chains["prefix"] = Chain{[]string{"entry", "exit", "socks"}}
	g.Chains["tail"] = Chain{[]string{"entry", "exit"}}
	g.Chains["tunnel"] = Chain{[]string{"prefix", "tail"}}
	if _, e := CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
		t.Fatal("later nested fifth physical hop admitted", e)
	}
	g = graphBase()
	g.Chains["prefix"] = Chain{[]string{"entry", "exit", "socks"}}
	g.Balancers["pick"] = Balancer{Type: "selector", Members: []string{"exit"}}
	g.Chains["tunnel"] = Chain{[]string{"prefix", "pick"}}
	out, e := CompileGraph(g, defaultGraphResolver())
	if e != nil || out.Capabilities["tunnel"].Hops != 4 {
		t.Fatal("valid expanded fourth hop rejected", e)
	}
	g = graphBase()
	g.Balancers["fan"] = Balancer{Type: "selector", Members: []string{"entry", "socks", "exit"}}
	for _, tag := range []string{"one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen"} {
		g.Chains[tag] = Chain{[]string{"entry", "fan"}}
	}
	if _, e = CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
		t.Fatal("expanded native node budget bypassed", e)
	}
}

func TestGraphCachedDependencyDepthCannotHideNestedSelectorHeight(t *testing.T) {
	g := Graph{Profiles: map[string]ProfileReference{"leaf": graphRef("vless")}, Balancers: map[string]Balancer{}, Chains: map[string]Chain{}, Final: "leaf"}
	previous := "leaf"
	for i := 0; i < 16; i++ {
		tag := fmt.Sprintf("group_%02d", i)
		g.Balancers[tag] = Balancer{Type: "selector", Members: []string{previous}}
		previous = tag
	}
	g.Final = previous
	if _, e := CompileGraph(g, defaultGraphResolver()); e != nil {
		t.Fatal("valid16-level graph rejected", e)
	}
	g.Chains["zz_alias"] = Chain{[]string{previous}}
	g.Final = "zz_alias"
	if _, e := CompileGraph(g, defaultGraphResolver()); !errors.Is(e, ErrInvalid) {
		t.Fatal("cached subtree hid seventeenth dependency level", e)
	}
}
