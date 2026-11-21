package configuration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func adaptiveCompilerFixture(t *testing.T, count int, intent string) (NetworkPlan, map[ProfileReference]subscriptions.Profile) {
	t.Helper()
	metadata, refs, profiles := adaptiveSnapshotInput(t, count)
	var graph map[string]any
	if json.Unmarshal(metadata, &graph) != nil {
		t.Fatal("invalid fixture")
	}
	for _, hop := range graph["hops"].([]any) {
		hop.(map[string]any)["exitClass"] = intent
	}
	graph["groups"].([]any)[0].(map[string]any)["intent"] = intent
	metadata, _ = json.Marshal(graph)
	plan := planBase()
	plan.Graph = Graph{Profiles: map[string]ProfileReference{}, Chains: map[string]Chain{}, Balancers: map[string]Balancer{}, Final: "adaptive-foreign"}
	plan.Adaptive = &AdaptivePlan{MetadataB64: base64.RawURLEncoding.EncodeToString(metadata), BindingsB64: canonicalAdaptivePlanBindings(t, refs), Groups: map[string]string{"foreign": "adaptive-foreign"}}
	plan.Network.RequiredNetworks = []string{"tcp"}
	check := OutboundCheck{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: intent}
	if intent == "INTERNAL" {
		check = OutboundCheck{Method: "ssh_banner", Target: "home.example.invalid:22"}
	}
	plan.Network.RouteChecks = []OutboundCheckPlan{{Outbound: "adaptive-foreign", Checks: []OutboundCheck{check}}}
	return plan, profiles
}

func adaptiveCompilerResolver(profiles map[ProfileReference]subscriptions.Profile) func(ProfileReference) (subscriptions.Profile, error) {
	return func(ref ProfileReference) (subscriptions.Profile, error) {
		profile, ok := profiles[ref]
		if !ok {
			return subscriptions.Profile{}, ErrInvalid
		}
		return profile, nil
	}
}

func adaptiveCompilerOutput(t *testing.T, compiled CompiledNetworkPlan) (map[string]json.RawMessage, map[string]any, map[string]map[string]any) {
	t.Helper()
	var root map[string]json.RawMessage
	var wire map[string]any
	if json.Unmarshal(compiled.EngineConfig, &root) != nil || json.Unmarshal(root["adaptive_routes"], &wire) != nil || len(wire) != 4 {
		t.Fatal("closed adaptive wire missing")
	}
	for _, name := range []string{"schemaVersion", "graphB64", "catalogueB64", "groups"} {
		if _, ok := wire[name]; !ok {
			t.Fatal("missing closed wire field")
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire["catalogueB64"].(string))
	var catalogue map[string]map[string]any
	if err != nil || json.Unmarshal(raw, &catalogue) != nil {
		t.Fatal("invalid materialized catalogue")
	}
	return root, wire, catalogue
}

func TestAdaptiveCompilerEmitsRealOwnedClosedWireAndResolvesSharedSourcesOnce(t *testing.T) {
	plan, profiles := adaptiveCompilerFixture(t, 3, "NON_RU")
	shared := ProfileReference{SourceID: "source-a", ProfileID: "source-a_profile-000"}
	plan.Graph.Profiles["mirror"] = shared
	profile := profiles[shared]
	var node map[string]any
	if json.Unmarshal(profile.Outbound, &node) != nil {
		t.Fatal("invalid fixture")
	}
	node["password"] = "fixture-password"
	profile.Outbound, _ = json.Marshal(node)
	profiles[shared] = profile
	calls := map[ProfileReference]int{}
	resolve := func(ref ProfileReference) (subscriptions.Profile, error) {
		calls[ref]++
		return adaptiveCompilerResolver(profiles)(ref)
	}
	compiled, err := CompileNetworkPlan(context.Background(), plan, resolve)
	if err != nil || compiled.AlgorithmRevision != AdaptiveTCPAlgorithm || !slices.Contains(compiled.RequiredEngineFeatures, "adaptive-tcp") || len(calls) != 3 {
		t.Fatal("real adaptive compilation or algorithm handoff missing", err)
	}
	for _, count := range calls {
		if count != 1 {
			t.Fatal("same source reference re-read between static/adaptive compilers")
		}
	}
	sum := sha256.Sum256(compiled.EngineConfig)
	if compiled.ContentHash != hex.EncodeToString(sum[:]) {
		t.Fatal("materialized engine bytes are not hash-bound")
	}
	root, wire, catalogue := adaptiveCompilerOutput(t, compiled)
	if len(catalogue) != 3 || catalogue["hop-000"]["tag"] != "hop-000" || catalogue["hop-000"]["password"] != "fixture-password" || catalogue["hop-000"]["detour"] != nil {
		t.Fatal("normalized private profile was lost, leaked its source tag or borrowed a detour")
	}
	if bytes.Contains(root["adaptive_routes"], []byte("source-a_profile")) || bytes.Contains(root["adaptive_routes"], []byte("synthetic-provider-name")) {
		t.Fatal("source references entered the device wire")
	}
	graphRaw, err := base64.RawURLEncoding.Strict().DecodeString(wire["graphB64"].(string))
	if err != nil || len(graphRaw) == 0 || len(root["adaptive_routes"]) > MaxAdaptivePlanBytes {
		t.Fatal("closed bounded graph missing")
	}
	var outbounds []map[string]any
	if json.Unmarshal(root["outbounds"], &outbounds) != nil || len(outbounds) != 3 {
		t.Fatal("graph hops were flattened into standalone engine outbounds")
	}
	managed := 0
	for _, outbound := range outbounds {
		if outbound["type"] == "syn443-adaptive" {
			managed++
			if len(outbound) != 3 || outbound["tag"] != "adaptive-foreign" || outbound["group"] != "foreign" {
				t.Fatal("managed outbound is not exact group binding")
			}
		}
	}
	if managed != 1 {
		t.Fatal("managed group was omitted or duplicated")
	}
	again, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles))
	if err != nil || !bytes.Equal(compiled.EngineConfig, again.EngineConfig) {
		t.Fatal("same owned inputs produce different engine bytes", err)
	}
	before := append([]byte(nil), compiled.EngineConfig...)
	plan.Adaptive.Groups["foreign"] = "changed-tag"
	plan.Activation.Checks[0].Target = "https://changed.example.invalid/"
	copy(profile.Outbound, bytes.Repeat([]byte{'!'}, len(profile.Outbound)))
	if !bytes.Equal(before, compiled.EngineConfig) || compiled.Activation.Checks[0].Target == plan.Activation.Checks[0].Target {
		t.Fatal("source or draft mutation changed the compiled policy")
	}
}

func TestAdaptiveCompilerSamePublicCandidateCanServeTwoMatchingExitClasses(t *testing.T) {
	plan, profiles := adaptiveCompilerFixture(t, 1, "NON_RU")
	raw, _ := base64.RawURLEncoding.DecodeString(plan.Adaptive.MetadataB64)
	var graph map[string]any
	if json.Unmarshal(raw, &graph) != nil {
		t.Fatal("fixture")
	}
	graph["hops"].([]any)[0].(map[string]any)["exitClass"] = "PUBLIC"
	graph["groups"] = []any{
		map[string]any{"id": "foreign", "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"simple"}},
		map[string]any{"id": "ru", "intent": "RU", "features": []string{"TCP"}, "templates": []string{"simple"}},
	}
	raw, _ = json.Marshal(graph)
	plan.Adaptive.MetadataB64 = base64.RawURLEncoding.EncodeToString(raw)
	plan.Adaptive.Groups["ru"] = "adaptive-ru"
	plan.Network.RouteChecks = append(plan.Network.RouteChecks, OutboundCheckPlan{Outbound: "adaptive-ru", Checks: []OutboundCheck{{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "RU"}}})
	calls := 0
	compiled, err := CompileNetworkPlan(context.Background(), plan, func(ref ProfileReference) (subscriptions.Profile, error) {
		calls++
		return adaptiveCompilerResolver(profiles)(ref)
	})
	if err != nil || calls != 1 {
		t.Fatal("one public candidate was duplicated or unavailable to two public intents", err)
	}
	_, wire, catalogue := adaptiveCompilerOutput(t, compiled)
	if len(catalogue) != 1 || len(wire["groups"].(map[string]any)) != 2 {
		t.Fatal("public eligibility silently cloned credentials or lost group bindings")
	}
	plan.Network.RouteChecks[1].Checks[0].ExpectedExitClass = "NON_RU"
	if _, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles)); err == nil {
		t.Fatal("PUBLIC metadata bypassed independent per-group country evidence")
	}
}

func TestAdaptiveCompilerKeepsAllNormalizedProtocolTLSAndTransportRequirements(t *testing.T) {
	plan, profiles := adaptiveCompilerFixture(t, 4, "NON_RU")
	for i, kind := range []string{"http", "socks", "vless", "ssh"} {
		ref := ProfileReference{SourceID: "source-a", ProfileID: fmt.Sprintf("source-a_profile-%03d", i)}
		node := graphNode(kind)
		node["tag"] = ref.ProfileID
		if kind == "vless" {
			node["network"] = "tcp"
			node["tls"] = map[string]any{"enabled": true, "server_name": "cover.example.invalid", "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "short_id": ""}}
			node["transport"] = map[string]any{"type": "xhttp", "mode": "stream-one", "path": "/transport"}
		}
		if kind == "ssh" {
			public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
			wire := append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...)
			wire = append(wire, 0, 0, 0, 32)
			wire = append(wire, public...)
			node["host_key"] = []string{"ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire)}
		}
		raw, _ := json.Marshal(node)
		profiles[ref] = subscriptions.Profile{ID: ref.ProfileID, Kind: kind, Outbound: raw}
	}
	compiled, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles))
	if err != nil {
		t.Fatal("supported normalized protocol/TLS options were rejected", err)
	}
	_, _, catalogue := adaptiveCompilerOutput(t, compiled)
	for i, kind := range []string{"http", "socks", "vless", "ssh"} {
		if catalogue[fmt.Sprintf("hop-%03d", i)]["type"] != kind || !slices.Contains(compiled.RequiredEngineFeatures, kind) {
			t.Fatal("private protocol requirements were lost")
		}
	}
	for _, feature := range []string{"vless.tls", "vless.reality", "vless.xhttp", "adaptive-tcp"} {
		if !slices.Contains(compiled.RequiredEngineFeatures, feature) {
			t.Fatal("actual private transport was omitted from required engine features")
		}
	}
	if catalogue["hop-002"]["transport"].(map[string]any)["mode"] != "stream-one" || len(catalogue["hop-003"]["host_key"].([]any)) != 1 {
		t.Fatal("transport options or mandatory host-key pins changed")
	}
}

func TestAdaptiveCompilerRejectsMissingCrossBoundUnsupportedAndConflictingChecks(t *testing.T) {
	for _, mutate := range []func(*NetworkPlan){
		func(p *NetworkPlan) { p.Network.RouteChecks = nil },
		func(p *NetworkPlan) { p.Network.RouteChecks[0].Outbound = "direct" },
		func(p *NetworkPlan) { p.Network.RouteChecks = append(p.Network.RouteChecks, p.Network.RouteChecks[0]) },
		func(p *NetworkPlan) { p.Network.RouteChecks[0].Checks = nil },
		func(p *NetworkPlan) { p.Network.RouteChecks[0].Checks[0].ExpectedExitClass = "RU" },
		func(p *NetworkPlan) {
			p.Network.RouteChecks[0].Checks = []OutboundCheck{{Method: "https_exit_ip", Target: "https://health.example.invalid/address", ExpectedIP: "192.0.2.9"}}
		},
		func(p *NetworkPlan) {
			p.Network.RouteChecks[0].Checks = append(p.Network.RouteChecks[0].Checks, OutboundCheck{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "RU"})
		},
		func(p *NetworkPlan) {
			p.Network.RouteChecks[0].Checks = append(p.Network.RouteChecks[0].Checks, OutboundCheck{Method: "icmp", Target: "host.example.invalid"})
		},
		func(p *NetworkPlan) {
			p.Network.RouteFailover = &RouteFailoverPlan{Selector: "adaptive-foreign", Intent: "INTERNAL", NetworkMode: "wifi"}
		},
		func(p *NetworkPlan) {
			p.Graph.Balancers["measure"] = Balancer{Type: "urltest", Members: []string{"adaptive-foreign"}, URL: "https://health.example.invalid/", IntervalSeconds: 60}
		},
	} {
		plan, profiles := adaptiveCompilerFixture(t, 1, "NON_RU")
		mutate(&plan)
		calls := 0
		compiled, err := CompileNetworkPlan(context.Background(), plan, func(ref ProfileReference) (subscriptions.Profile, error) {
			calls++
			return adaptiveCompilerResolver(profiles)(ref)
		})
		if err == nil || len(compiled.EngineConfig) != 0 || calls != 0 {
			t.Fatal("invalid managed plan reached source resolution or publication")
		}
	}
	for _, feature := range []string{"UDP", "ICMP"} {
		plan, profiles := adaptiveCompilerFixture(t, 1, "NON_RU")
		raw, _ := base64.RawURLEncoding.DecodeString(plan.Adaptive.MetadataB64)
		var graph map[string]any
		json.Unmarshal(raw, &graph)
		graph["groups"].([]any)[0].(map[string]any)["features"] = []string{"TCP", feature}
		raw, _ = json.Marshal(graph)
		plan.Adaptive.MetadataB64 = base64.RawURLEncoding.EncodeToString(raw)
		if _, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles)); err == nil {
			t.Fatal("TCP-only evaluator advertised datagram/ICMP support")
		}
	}
	plan, profiles := adaptiveCompilerFixture(t, 1, "INTERNAL")
	if _, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles)); err != nil {
		t.Fatal("internal destination-specific check rejected", err)
	}
	plan.Network.RouteChecks[0].Checks = []OutboundCheck{{Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "RU"}}
	if _, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles)); err == nil {
		t.Fatal("country observation treated as internal destination evidence")
	}
	plan, _ = adaptiveCompilerFixture(t, 1, "INTERNAL")
	raw, _ := json.Marshal(plan)
	raw = bytes.Replace(raw, []byte(`"method":"ssh_banner"`), []byte(`"method":"ssh_banner","expected_exit_class":""`), 1)
	if _, err := DecodeNetworkPlan(raw); err == nil {
		t.Fatal("nested plan erased an explicit wrong-method empty predicate")
	}
}

func TestAdaptiveCompilerRejectsNativeInvalidProfilesAndPreservesOwnedCancellation(t *testing.T) {
	for _, mutate := range []func(map[string]any, *subscriptions.Profile){
		func(n map[string]any, _ *subscriptions.Profile) { n["detour"] = "direct" },
		func(n map[string]any, _ *subscriptions.Profile) { n["username"] = nil },
		func(n map[string]any, _ *subscriptions.Profile) {
			n["tls"] = map[string]any{"enabled": true, "insecure": true}
		},
		func(n map[string]any, _ *subscriptions.Profile) {
			n["tls"] = map[string]any{"enabled": true, "certificate_path": "/untrusted.pem"}
		},
		func(n map[string]any, _ *subscriptions.Profile) {
			n["tls"] = map[string]any{"enabled": true, "utls": map[string]any{"enabled": false, "fingerprint": "chrome"}}
		},
		func(n map[string]any, p *subscriptions.Profile) {
			n["type"], n["network"], n["uuid"] = "vless", "udp", "00000000-0000-0000-0000-000000000000"
			p.Kind = "vless"
		},
		func(n map[string]any, p *subscriptions.Profile) {
			n["type"], n["user"], n["password"], n["host_key"] = "ssh", "fixture", "fixture-password", "ssh-ed25519 synthetic-key"
			p.Kind = "ssh"
		},
		func(n map[string]any, p *subscriptions.Profile) {
			n["type"], n["user"], n["private_key"], n["host_key"] = "ssh", "fixture", strings.Repeat("p", 65536), []string{"ssh-ed25519 synthetic-key"}
			p.Kind = "ssh"
		},
	} {
		plan, profiles := adaptiveCompilerFixture(t, 1, "NON_RU")
		for ref, p := range profiles {
			var node map[string]any
			json.Unmarshal(p.Outbound, &node)
			mutate(node, &p)
			p.Outbound, _ = json.Marshal(node)
			profiles[ref] = p
		}
		if compiled, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles)); err == nil || len(compiled.EngineConfig) != 0 {
			t.Fatal("unsafe or native-incompatible profile reached materialized output")
		}
	}
	plan, profiles := adaptiveCompilerFixture(t, 2, "NON_RU")
	first := ProfileReference{SourceID: "source-a", ProfileID: "source-a_profile-000"}
	second := ProfileReference{SourceID: "source-a", ProfileID: "source-a_profile-001"}
	firstBytes := profiles[first].Outbound
	compiled, err := CompileNetworkPlan(context.Background(), plan, func(ref ProfileReference) (subscriptions.Profile, error) {
		if ref == second {
			copy(firstBytes, bytes.Repeat([]byte{'!'}, len(firstBytes)))
		}
		return adaptiveCompilerResolver(profiles)(ref)
	})
	if err != nil {
		t.Fatal("resolver-retained buffers changed an earlier owned profile", err)
	}
	_, _, catalogue := adaptiveCompilerOutput(t, compiled)
	if catalogue["hop-000"]["server"] != "proxy-000.example.invalid" {
		t.Fatal("earlier source changed during further resolution")
	}
	plan, profiles = adaptiveCompilerFixture(t, 1, "NON_RU")
	ctx, cancel := context.WithCancel(context.Background())
	compiled, err = CompileNetworkPlan(ctx, plan, func(ref ProfileReference) (subscriptions.Profile, error) {
		cancel()
		return adaptiveCompilerResolver(profiles)(ref)
	})
	if !errors.Is(err, context.Canceled) || len(compiled.EngineConfig) != 0 {
		t.Fatal("late cancelled source result produced a policy", err)
	}
	if compiled, err := CompileNetworkPlan(context.Background(), plan, func(ProfileReference) (subscriptions.Profile, error) { return subscriptions.Profile{}, ErrInvalid }); err == nil || len(compiled.EngineConfig) != 0 {
		t.Fatal("missing independently authorized source silently fell back")
	}
}

func TestAdaptiveCompilerRetains500CandidatesAndRejectsWireAndWholeEngineOverflow(t *testing.T) {
	plan, profiles := adaptiveCompilerFixture(t, 500, "NON_RU")
	compiled, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles))
	if err != nil {
		t.Fatal("500 candidates did not fit the bounded real wire", err)
	}
	root, _, catalogue := adaptiveCompilerOutput(t, compiled)
	if len(catalogue) != 500 || catalogue["hop-499"] == nil || len(root["adaptive_routes"]) > MaxAdaptivePlanBytes {
		t.Fatal("large catalogue was silently truncated")
	}
	var outbounds []any
	json.Unmarshal(root["outbounds"], &outbounds)
	if len(outbounds) != 2 {
		t.Fatal("500 candidates became500 parent-manager outbounds")
	}
	for ref, p := range profiles {
		var n map[string]any
		json.Unmarshal(p.Outbound, &n)
		n["password"] = strings.Repeat("p", 100)
		p.Outbound, _ = json.Marshal(n)
		profiles[ref] = p
	}
	decoded, err := DecodeAdaptivePlan(*plan.Adaptive, plan.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileAdaptiveSnapshot(context.Background(), decoded.Metadata(), decoded.Bindings(), adaptiveCompilerResolver(profiles)); err != nil {
		t.Fatal("wire overflow fixture must still fit the protected source snapshot", err)
	}
	if compiled, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles)); err == nil || len(compiled.EngineConfig) != 0 {
		t.Fatal("encoded adaptive block escaped196608 bytes")
	}
	plan, profiles = adaptiveCompilerFixture(t, 500, "NON_RU")
	for i := 0; i < 32; i++ {
		ref := ProfileReference{SourceID: "static-source", ProfileID: fmt.Sprintf("static-profile-%02d", i)}
		tag := fmt.Sprintf("static-%02d", i)
		plan.Graph.Profiles[tag] = ref
		raw, _ := json.Marshal(map[string]any{"type": "http", "tag": ref.ProfileID, "server": fmt.Sprintf("static-%02d.example.invalid", i), "server_port": 443, "password": strings.Repeat("p", 6000)})
		profiles[ref] = subscriptions.Profile{ID: ref.ProfileID, Kind: "http", Outbound: raw}
	}
	staticOnly := plan.Graph
	staticOnly.Final = "direct"
	if _, err := CompileGraph(staticOnly, adaptiveCompilerResolver(profiles)); err != nil {
		t.Fatal("whole-engine overflow fixture must fit the ordinary static graph alone", err)
	}
	if compiled, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles)); err == nil || len(compiled.EngineConfig) != 0 {
		t.Fatal("separately bounded static/adaptive components escaped whole-engine262144 limit")
	}
}

func TestAdaptiveGraphKeepsOwnedPrefixesHopNodeAndNetBirdUnderlayBoundaries(t *testing.T) {
	declarations := map[string]adaptiveGroupDeclaration{"foreign": {Tag: "managed", MaxHops: 2}}
	g := graphBase()
	g.Chains = map[string]Chain{"via": {DialOrder: []string{"managed", "exit"}}}
	g.Final = "via"
	compiled, err := compileGraphWithAdaptive(g, defaultGraphResolver(), declarations)
	if err != nil || compiled.Capabilities["managed"] != (GraphCapability{TCP: true, Hops: 2}) || compiled.Capabilities["via"].Hops != 3 {
		t.Fatal("complete managed TCP prefix was not used in dial order", err)
	}
	nodes := graphOutbounds(t, compiled)
	if nodes["via"]["type"] != "vless" || nodes["via"]["detour"] != "managed" || nodes["managed"]["type"] != "syn443-adaptive" {
		t.Fatal("outer leaf bypassed or cloned the complete managed prefix")
	}
	for _, order := range [][]string{{"entry", "managed"}, {"managed", "managed"}, {"entry", "alias"}} {
		bad := g
		bad.Chains = map[string]Chain{"via": {DialOrder: order}, "alias": {DialOrder: []string{"managed"}}}
		if _, err := compileGraphWithAdaptive(bad, defaultGraphResolver(), declarations); err == nil {
			t.Fatal("managed group was cloned behind a foreign detour or repeated")
		}
	}
	declarations["foreign"] = adaptiveGroupDeclaration{Tag: "managed", MaxHops: 4}
	if _, err := compileGraphWithAdaptive(g, defaultGraphResolver(), declarations); err == nil {
		t.Fatal("private4-hop prefix gained a fifth outer hop")
	}
	declarations["foreign"] = adaptiveGroupDeclaration{Tag: "managed", MaxHops: 2}
	g.NetBird = managedNetBird()
	if _, err := compileGraphWithAdaptive(g, defaultGraphResolver(), declarations); err != nil {
		t.Fatal("independent direct NetBird cannot coexist with managed groups", err)
	}
	g.NetBird.Mode, g.NetBird.Detour = "vless", "via"
	if _, err := compileGraphWithAdaptive(g, defaultGraphResolver(), declarations); err == nil {
		t.Fatal("terminal VLESS concealed an unsupported managed NetBird underlay")
	}
	g.NetBird.Detour = "managed"
	if _, err := compileGraphWithAdaptive(g, defaultGraphResolver(), declarations); err == nil {
		t.Fatal("SDK directly borrowed a managed route")
	}
	g.NetBird = nil
	ordinary, err := CompileGraph(graphBase(), defaultGraphResolver())
	unchanged, otherErr := compileGraphWithAdaptive(graphBase(), defaultGraphResolver(), nil)
	if err != nil || otherErr != nil || !reflect.DeepEqual(ordinary, unchanged) {
		t.Fatal("ordinary wrapper changed graph behavior", err, otherErr)
	}
	legacy, err := CompileNetworkPlan(context.Background(), planBase(), defaultGraphResolver())
	if err != nil || legacy.AlgorithmRevision != "" || slices.Contains(legacy.RequiredEngineFeatures, "adaptive-tcp") || bytes.Contains(legacy.EngineConfig, []byte("adaptive_routes")) {
		t.Fatal("ordinary policy inherited adaptive activation metadata", err)
	}
	nodeGraph := Graph{Profiles: map[string]ProfileReference{}, Chains: map[string]Chain{}, Final: "profile-00"}
	nodeDeclarations := map[string]adaptiveGroupDeclaration{}
	for i := 0; i < 32; i++ {
		tag := fmt.Sprintf("profile-%02d", i)
		nodeGraph.Profiles[tag] = ProfileReference{SourceID: "source-a", ProfileID: tag}
	}
	for i := 0; i < 16; i++ {
		nodeDeclarations[fmt.Sprintf("group-%02d", i)] = adaptiveGroupDeclaration{Tag: fmt.Sprintf("managed-%02d", i), MaxHops: 1}
		if i < 15 {
			nodeGraph.Chains[fmt.Sprintf("alias-%02d", i)] = Chain{DialOrder: []string{"profile-00"}}
		}
	}
	resolver := func(ref ProfileReference) (subscriptions.Profile, error) {
		raw, _ := json.Marshal(map[string]any{"type": "http", "tag": ref.ProfileID, "server": ref.ProfileID + ".example.invalid", "server_port": 443})
		return subscriptions.Profile{ID: ref.ProfileID, Kind: "http", Outbound: raw}, nil
	}
	boundary, err := compileGraphWithAdaptive(nodeGraph, resolver, nodeDeclarations)
	if err != nil || len(boundary.Outbounds) != 64 {
		t.Fatal("ordinary64-node budget no longer includes managed groups", err)
	}
	nodeGraph.Chains["alias-15"] = Chain{DialOrder: []string{"profile-00"}}
	if _, err := compileGraphWithAdaptive(nodeGraph, resolver, nodeDeclarations); err == nil {
		t.Fatal("managed groups escaped the existing64-parent-outbound hard limit")
	}
}

func TestCompileHomeProofPreservesAssignedPrivateTLSServiceAndRequiresAdaptivePolicy(t *testing.T) {
	plan, profiles := adaptiveCompilerFixture(t, 2, "NON_RU")
	pin := sha256.Sum256([]byte("public test certificate"))
	address := netip.AddrFrom4([4]byte{10, 55, 1, 67})
	plan.Network.HomeProof = &policy.HomeProof{Hostname: "gateway.example.invalid", Address: address.String(), Port: 443, SPKISHA256: base64.RawURLEncoding.EncodeToString(pin[:])}
	resolver := adaptiveCompilerResolver(profiles)
	compiled, err := CompileNetworkPlan(context.Background(), plan, resolver)
	if err != nil {
		t.Fatal(err)
	}
	var declared struct {
		Proof *policy.HomeProof `json:"home_proof"`
	}
	if json.Unmarshal(compiled.EngineConfig, &declared) != nil || declared.Proof == nil || *declared.Proof != *plan.Network.HomeProof {
		t.Fatal("assigned TLS endpoint lost")
	}
	plan.Adaptive = nil
	if _, err := CompileNetworkPlan(context.Background(), plan, resolver); err == nil {
		t.Fatal("accepted static graph with home proof")
	}
	if _, err := DecodeNetworkSettings([]byte(`{"schemaVersion":1,"homeProof":null}`)); err == nil {
		t.Fatal("silently discarded explicit null proof")
	}
}
