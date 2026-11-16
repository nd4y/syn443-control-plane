package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func adaptiveIssuedFixture(t *testing.T, count int, intent string) []byte {
	t.Helper()
	plan, profiles := adaptiveCompilerFixture(t, count, intent)
	compiled, e := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles))
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(compiled.EngineConfig)
	if compiled.ContentHash != hex.EncodeToString(hash[:]) {
		t.Fatal("fixture hash did not bind exact compiler bytes")
	}
	return append([]byte(nil), compiled.EngineConfig...)
}
func adaptiveIssuedMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func adaptiveIssuedDecode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var root map[string]any
	if e := d.Decode(&root); e != nil {
		t.Fatal(e)
	}
	return root
}
func adaptiveIssuedParts(t *testing.T, root map[string]any) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	wire := root["adaptive_routes"].(map[string]any)
	catalogue, e := base64.RawURLEncoding.Strict().DecodeString(wire["catalogueB64"].(string))
	if e != nil {
		t.Fatal(e)
	}
	graph, e := base64.RawURLEncoding.Strict().DecodeString(wire["graphB64"].(string))
	if e != nil {
		t.Fatal(e)
	}
	return wire, adaptiveIssuedDecode(t, catalogue), adaptiveIssuedDecode(t, graph)
}
func adaptiveIssuedRewrap(t *testing.T, root, wire, catalogue, graph map[string]any) []byte {
	t.Helper()
	wire["catalogueB64"] = base64.RawURLEncoding.EncodeToString(adaptiveIssuedMarshal(t, catalogue))
	wire["graphB64"] = base64.RawURLEncoding.EncodeToString(adaptiveIssuedMarshal(t, graph))
	root["adaptive_routes"] = wire
	return adaptiveIssuedMarshal(t, root)
}
func rejectAdaptiveIssued(t *testing.T, raw []byte) {
	t.Helper()
	if e := ValidateAdaptiveIssuedEngine(raw); e != ErrInvalid {
		t.Fatal("forged issued engine was accepted or disclosed a lower-level error")
	}
}

func TestAdaptiveIssuedVerifierAcceptsActualCompilerAndAllFiveHundredBindings(t *testing.T) {
	for _, intent := range []string{"INTERNAL", "RU", "NON_RU"} {
		raw := adaptiveIssuedFixture(t, 1, intent)
		if e := ValidateAdaptiveIssuedEngine(raw); e != nil {
			t.Fatal("actual compiler output rejected", intent, e)
		}
	}
	raw := adaptiveIssuedFixture(t, 500, "NON_RU")
	if e := ValidateAdaptiveIssuedEngine(raw); e != nil {
		t.Fatal("actual500-profile compiler output rejected", e)
	}
	root := adaptiveIssuedDecode(t, raw)
	wire, catalogue, _ := adaptiveIssuedParts(t, root)
	if len(catalogue) != 500 || catalogue["hop-499"] == nil {
		t.Fatal("fixture lost its last profile")
	}
	var ordinary map[string]json.RawMessage
	if identity.DecodeConfiguration(adaptiveIssuedMarshal(t, catalogue), &ordinary) == nil {
		t.Fatal("adaptive validation widened the generic128-member decoder")
	}
	if len(adaptiveIssuedMarshal(t, wire)) > MaxAdaptivePlanBytes || len(raw) > 262144 {
		t.Fatal("fixture escaped declared assigned bounds")
	}
	plan, profiles := adaptiveCompilerFixture(t, 1, "NON_RU")
	plan.Graph.NetBird = &NetBirdNode{Tag: "overlay", OverlayID: "overlay-a", ResourceID: "resource-a", NetworkID: "network-a", IdentityEpoch: 1, ManagementURL: "https://management.example.invalid", Mode: "direct"}
	plan.Network.DNSServers = map[string]DNSServer{"secure": {Transport: "https", Address: "192.0.2.2", Port: 443, ServerName: "resolver.example.invalid", Path: "/dns-query", Outbound: "adaptive-foreign"}, "overlay-dns": {Transport: "netbird", Outbound: "overlay"}}
	plan.Network.DNSFinal = "secure"
	plan.Network.DNSRules = []DNSRule{{ID: "fixture-dns", HostMatch: HostMatch{Domains: []string{"fixture.example.invalid"}}, QueryTypes: []string{"A", "AAAA"}, Server: "secure"}}
	plan.Network.Rules = []RouteRule{{ID: "public-tcp", Networks: []string{"tcp"}, Action: "route", Outbound: "adaptive-foreign"}, {ID: "overlay-route", IPPrefixes: []string{"192.0.2.0/24"}, Networks: []string{"tcp", "udp"}, Action: "route", Outbound: "overlay"}}
	compiled, e := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles))
	if e != nil || ValidateAdaptiveIssuedEngine(compiled.EngineConfig) != nil {
		t.Fatal("actual compiled TLS/DNS/NetBird destination rules were rejected", e)
	}
}

func TestAdaptiveIssuedVerifierRejectsClosedWireAndUnsafeProfileForgeries(t *testing.T) {
	raw := adaptiveIssuedFixture(t, 2, "NON_RU")
	for _, forged := range [][]byte{nil, []byte("null"), []byte("{}"), append(append([]byte(nil), raw...), []byte("null")...),
		bytes.Replace(raw, []byte(`"outbounds":`), []byte(`"outbounds":null,"\u006futbounds":`), 1),
		bytes.Replace(raw, []byte(`"outbounds":`), []byte(`"Outbounds":`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"\u0073chemaVersion":1`), 1),
	} {
		rejectAdaptiveIssued(t, forged)
	}
	for _, name := range []string{"wire-null", "wire-schema-string", "wire-case", "wire-unknown", "catalogue-null", "catalogue-noncanonical", "catalogue-duplicate", "graph-duplicate", "base64-pad", "base64-newline", "extra-catalogue", "missing-catalogue", "mismatched-tag", "alias", "insecure-tls", "tls-file", "ssh-no-pin", "ssh-string-pin", "null-option", "foreign-detour", "UDP-only", "graph-group-UDP"} {
		t.Run(name, func(t *testing.T) {
			root := adaptiveIssuedDecode(t, raw)
			wire, catalogue, graph := adaptiveIssuedParts(t, root)
			node := catalogue["hop-000"].(map[string]any)
			switch name {
			case "wire-null":
				root["adaptive_routes"] = nil
				rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
				return
			case "wire-schema-string":
				wire["schemaVersion"] = "1"
			case "wire-case":
				wire["SchemaVersion"] = wire["schemaVersion"]
				delete(wire, "schemaVersion")
			case "wire-unknown":
				wire["contentHash"] = strings.Repeat("a", 64)
			case "catalogue-null":
				wire["catalogueB64"] = base64.RawURLEncoding.EncodeToString([]byte("null"))
				rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
				return
			case "catalogue-noncanonical":
				wire["catalogueB64"] = base64.RawURLEncoding.EncodeToString(append([]byte{' '}, adaptiveIssuedMarshal(t, catalogue)...))
				rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
				return
			case "catalogue-duplicate":
				profile := adaptiveIssuedMarshal(t, node)
				wire["catalogueB64"] = base64.RawURLEncoding.EncodeToString([]byte(`{"hop-000":` + string(profile) + `,"\u0068op-000":` + string(profile) + `}`))
				rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
				return
			case "graph-duplicate":
				body := bytes.Replace(adaptiveIssuedMarshal(t, graph), []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
				wire["graphB64"] = base64.RawURLEncoding.EncodeToString(body)
				rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
				return
			case "base64-pad":
				wire["graphB64"] = wire["graphB64"].(string) + "="
				rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
				return
			case "base64-newline":
				wire["catalogueB64"] = wire["catalogueB64"].(string) + "\n"
				rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
				return
			case "extra-catalogue":
				clone := adaptiveIssuedDecode(t, adaptiveIssuedMarshal(t, node))
				clone["tag"], clone["server_port"] = "hop-002", 2002
				catalogue["hop-002"] = clone
			case "missing-catalogue":
				delete(catalogue, "hop-001")
			case "mismatched-tag":
				node["tag"] = "other-hop"
			case "alias":
				clone := adaptiveIssuedDecode(t, adaptiveIssuedMarshal(t, node))
				clone["tag"] = "hop-001"
				catalogue["hop-001"] = clone
			case "insecure-tls":
				node["tls"] = map[string]any{"enabled": true, "insecure": true}
			case "tls-file":
				node["tls"] = map[string]any{"enabled": true, "certificate_path": "/fixture/file"}
			case "ssh-no-pin":
				node["type"] = "ssh"
				node["user"] = "fixture-user"
				node["password"] = "fixture-password"
				delete(node, "host_key")
			case "ssh-string-pin":
				node["type"], node["user"], node["password"], node["host_key"] = "ssh", "fixture-user", "fixture-password", "fixture-key"
			case "null-option":
				node["password"] = nil
			case "foreign-detour":
				node["detour"] = "direct"
			case "UDP-only":
				node["type"], node["uuid"], node["network"] = "vless", "00000000-0000-4000-8000-000000000001", "udp"
			case "graph-group-UDP":
				graph["groups"].([]any)[0].(map[string]any)["features"] = []string{"TCP", "UDP"}
			}
			rejectAdaptiveIssued(t, adaptiveIssuedRewrap(t, root, wire, catalogue, graph))
		})
	}
	for _, key := range []string{"log", "inbounds", "route_failover"} {
		root := adaptiveIssuedDecode(t, raw)
		root[key] = nil
		rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
	}
}

func TestAdaptiveIssuedVerifierFencesActualGroupsChecksAndDependencies(t *testing.T) {
	raw := adaptiveIssuedFixture(t, 1, "NON_RU")
	for _, name := range []string{"missing-mapping", "foreign-mapping", "direct-mapping", "managed-extra", "managed-missing", "managed-foreign-group", "static-collision", "urltest", "checks-null", "checks-missing", "checks-duplicate", "wrong-country", "country-missing", "foreign-predicate", "required-null", "unknown-check", "UDP-route", "default-route-UDP", "route-unknown", "dns-UDP-detour", "dns-insecure", "selector-cycle", "selector-depth", "netbird-hidden-managed"} {
		t.Run(name, func(t *testing.T) {
			root := adaptiveIssuedDecode(t, raw)
			wire, _, _ := adaptiveIssuedParts(t, root)
			outbounds := root["outbounds"].([]any)
			managed := outbounds[1].(map[string]any)
			plan := root["route_checks"].([]any)[0].(map[string]any)
			check := plan["checks"].([]any)[0].(map[string]any)
			switch name {
			case "missing-mapping":
				wire["groups"] = map[string]string{}
			case "foreign-mapping":
				wire["groups"] = map[string]string{"another": "adaptive-foreign"}
			case "direct-mapping":
				wire["groups"] = map[string]string{"foreign": "direct"}
			case "managed-extra":
				managed["detour"] = "direct"
			case "managed-missing":
				root["outbounds"] = outbounds[:1]
			case "managed-foreign-group":
				managed["group"] = "another"
			case "static-collision":
				root["outbounds"] = append(outbounds, map[string]any{"type": "http", "tag": "adaptive-foreign", "server": "192.0.2.1", "server_port": 443})
			case "urltest":
				root["outbounds"] = append(outbounds, map[string]any{"type": "urltest", "tag": "automatic", "outbounds": []string{"direct"}})
			case "checks-null":
				root["route_checks"] = nil
			case "checks-missing":
				root["route_checks"] = []any{}
			case "checks-duplicate":
				root["route_checks"] = append(root["route_checks"].([]any), plan)
			case "wrong-country":
				check["expected_exit_class"] = "RU"
			case "country-missing":
				plan["checks"] = []any{map[string]any{"method": "https_204", "target": "https://health.example.invalid/"}}
			case "foreign-predicate":
				check["expected_ip"] = nil
			case "required-null":
				plan["required"] = nil
			case "unknown-check":
				check["unknown"] = "ignored"
			case "UDP-route":
				root["route"].(map[string]any)["rules"] = []any{map[string]any{"action": "route", "outbound": "adaptive-foreign", "network": []string{"udp"}}}
			case "default-route-UDP":
				root["route"].(map[string]any)["rules"] = []any{map[string]any{"action": "route", "outbound": "adaptive-foreign"}}
			case "route-unknown":
				root["route"].(map[string]any)["auto_detect_interface"] = true
			case "dns-UDP-detour":
				dns := root["dns"].(map[string]any)
				dns["servers"] = append(dns["servers"].([]any), map[string]any{"type": "udp", "tag": "alternative", "server": "192.0.2.1", "server_port": 53, "detour": "adaptive-foreign"})
			case "dns-insecure":
				dns := root["dns"].(map[string]any)
				dns["servers"] = append(dns["servers"].([]any), map[string]any{"type": "tls", "tag": "alternative", "server": "192.0.2.1", "server_port": 853, "tls": map[string]any{"enabled": true, "insecure": true}})
			case "selector-cycle":
				root["outbounds"] = append(outbounds, map[string]any{"type": "selector", "tag": "cycle-a", "outbounds": []string{"cycle-b"}}, map[string]any{"type": "selector", "tag": "cycle-b", "outbounds": []string{"cycle-a"}})
			case "selector-depth":
				previous := "direct"
				for i := 0; i < 17; i++ {
					tag := fmt.Sprintf("nested-%02d", i)
					outbounds = append(outbounds, map[string]any{"type": "selector", "tag": tag, "outbounds": []string{previous}})
					previous = tag
				}
				root["outbounds"] = outbounds
			case "netbird-hidden-managed":
				root["outbounds"] = append(outbounds, map[string]any{"type": "vless", "tag": "underlay", "server": "192.0.2.1", "server_port": 443, "uuid": "00000000-0000-4000-8000-000000000001", "detour": "adaptive-foreign"}, (NetBirdNode{Tag: "overlay", OverlayID: "overlay-a", ResourceID: "resource-a", NetworkID: "network-a", IdentityEpoch: 1, ManagementURL: "https://management.example.invalid", Mode: "vless", Detour: "underlay"}).outbound())
			}
			rejectAdaptiveIssued(t, adaptiveIssuedMarshal(t, root))
		})
	}
	// Ordinary static chains/selectors are still valid, and their separate
	// checks may use a different country class than the managed group.
	root := adaptiveIssuedDecode(t, raw)
	outbounds := root["outbounds"].([]any)
	root["outbounds"] = append(outbounds, map[string]any{"type": "http", "tag": "first", "server": "192.0.2.1", "server_port": 443}, map[string]any{"type": "socks", "tag": "second", "server": "192.0.2.2", "server_port": 1080, "version": "5", "detour": "first"}, map[string]any{"type": "selector", "tag": "selection", "outbounds": []string{"second", "direct"}, "default": "second", "interrupt_exist_connections": false})
	root["route_checks"] = append(root["route_checks"].([]any), map[string]any{"outbound": "selection", "required": false, "checks": []any{map[string]any{"method": "https_exit_country", "target": "https://country.example.invalid/", "expected_exit_class": "RU"}}})
	if e := ValidateAdaptiveIssuedEngine(adaptiveIssuedMarshal(t, root)); e != nil {
		t.Fatal("valid unrelated static chain/check was rejected", e)
	}
}

func TestAdaptiveIssuedVerifierEnforcesIndependentByteAndParserLimits(t *testing.T) {
	raw := adaptiveIssuedFixture(t, 1, "NON_RU")
	max := append(append([]byte(nil), raw...), bytes.Repeat([]byte{' '}, 262144-len(raw))...)
	if e := ValidateAdaptiveIssuedEngine(max); e != nil {
		t.Fatal("exact full-engine byte boundary rejected", e)
	}
	rejectAdaptiveIssued(t, append(max, ' '))
	root := adaptiveIssuedDecode(t, raw)
	wire, _, _ := adaptiveIssuedParts(t, root)
	wireRaw := adaptiveIssuedMarshal(t, wire)
	maxWire := append(append([]byte(nil), wireRaw...), bytes.Repeat([]byte{' '}, MaxAdaptivePlanBytes-len(wireRaw))...)
	if _, _, e := decodeAdaptiveIssuedWire(maxWire); e != nil {
		t.Fatal("exact adaptive block boundary rejected", e)
	}
	if _, _, e := decodeAdaptiveIssuedWire(append(maxWire, ' ')); e != ErrInvalid {
		t.Fatal("adaptive block exceeded196608 bytes")
	}
	for _, text := range []string{"Zg==", "Zh", "Zg\n", "Zg+", "Zg/"} {
		if _, ok := adaptiveIssuedB64(text); ok {
			t.Fatal("noncanonical base64 accepted")
		}
	}
	for _, count := range []int{262144, 262145} {
		if _, ok := adaptiveIssuedB64(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, count))); ok != (count == 262144) {
			t.Fatal("decoded payload byte boundary changed")
		}
	}
	limits := adaptiveIssuedJSONLimits{500, 256, false}
	for _, depth := range []int{16, 17} {
		remaining := 32768
		if _, ok := readAdaptiveIssuedJSON([]byte(strings.Repeat("[", depth)+"0"+strings.Repeat("]", depth)), &remaining, limits); ok != (depth == 16) {
			t.Fatal("dedicated depth fence changed")
		}
	}
	for _, width := range []int{125, 126} {
		inner := "[" + strings.Repeat("0,", width-1) + "0]"
		body := "[" + strings.Repeat(inner+",", 255) + inner + "]"
		remaining := 32768
		if _, ok := readAdaptiveIssuedJSON([]byte(body), &remaining, limits); ok != (width == 125) {
			t.Fatal("combined32768-token budget changed")
		}
	}
	for _, body := range []string{`{"a":null}`, `{"a":1,"\u0061":2}`, "{\"a\":\"\xff\"}"} {
		remaining := 32768
		if _, ok := readAdaptiveIssuedJSON([]byte(body), &remaining, limits); ok {
			t.Fatal("null/duplicate/invalid UTF8 survived strict parser")
		}
	}
}
