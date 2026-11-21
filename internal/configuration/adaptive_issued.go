package configuration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/routecheck"
	"github.com/nd4y/syn443-control-plane/internal/routegraph"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

// This is the independent issuer boundary, including callers that bypass the
// ordinary compiler. It performs no source resolution, signing, SQL or I/O and
// cannot turn declared graph metadata into current native probe authority.
func ValidateAdaptiveIssuedEngine(raw []byte) error {
	var root struct {
		Outbounds     []json.RawMessage `json:"outbounds"`
		Route         json.RawMessage   `json:"route"`
		DNS           json.RawMessage   `json:"dns"`
		Checks        json.RawMessage   `json:"route_checks"`
		Adaptive      json.RawMessage   `json:"adaptive_routes"`
		ModeSelection json.RawMessage   `json:"network_mode"`
		HomeProof     json.RawMessage   `json:"home_proof"`
	}
	if len(raw) < 1 || len(raw) > 262144 || identity.DecodeConfiguration(raw, &root) != nil || len(root.Outbounds) < 1 || len(root.Outbounds) > 64 {
		return ErrInvalid
	}
	if root.ModeSelection != nil && !policy.ValidNetworkModeJSON(root.ModeSelection, root.HomeProof != nil) {
		return ErrInvalid
	}
	if root.HomeProof != nil && !policy.ValidHomeProofJSON(root.HomeProof) {
		return ErrInvalid
	}
	graph, groups, err := decodeAdaptiveIssuedWire(root.Adaptive)
	if err != nil {
		return ErrInvalid
	}
	nodes, caps, err := adaptiveIssuedOutbounds(root.Outbounds, graph, groups)
	if err != nil {
		return ErrInvalid
	}
	compiled := CompiledGraph{Outbounds: root.Outbounds, Capabilities: caps}
	if adaptiveIssuedChecks(root.Checks, nodes, caps, graph, groups) != nil || adaptiveIssuedRoute(root.Route, compiled) != nil || adaptiveIssuedDNS(root.DNS, compiled) != nil {
		return ErrInvalid
	}
	return nil
}

type adaptiveIssuedJSONLimits struct {
	rootMembers, arrayItems int
	allowNull               bool
}

// Unlike a map unmarshal, this preserves duplicate/escaped keys and exact JSON
// number lexemes. Only this opaque catalogue can opt into500 root members.
func readAdaptiveIssuedJSON(raw []byte, remaining *int, limits adaptiveIssuedJSONLimits) (any, bool) {
	if len(raw) == 0 || len(raw) > 262144 || !utf8.Valid(raw) || remaining == nil {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token := func() (json.Token, bool) {
		if *remaining <= 0 {
			return nil, false
		}
		*remaining -= 1
		v, e := d.Token()
		return v, e == nil
	}
	var read func(int) (any, bool)
	read = func(depth int) (any, bool) {
		if depth > 16 {
			return nil, false
		}
		v, ok := token()
		if !ok || v == nil && !limits.allowNull {
			return nil, false
		}
		delim, container := v.(json.Delim)
		if !container {
			return v, true
		}
		switch delim {
		case '{':
			max := 128
			if depth == 0 {
				max = limits.rootMembers
			}
			out := map[string]any{}
			for d.More() {
				if len(out) >= max {
					return nil, false
				}
				k, ok := token()
				key, s := k.(string)
				if !ok || !s {
					return nil, false
				}
				if _, dup := out[key]; dup {
					return nil, false
				}
				value, ok := read(depth + 1)
				if !ok {
					return nil, false
				}
				out[key] = value
			}
			end, ok := token()
			return out, ok && end == json.Delim('}')
		case '[':
			out := []any{}
			for d.More() {
				if len(out) >= limits.arrayItems {
					return nil, false
				}
				value, ok := read(depth + 1)
				if !ok {
					return nil, false
				}
				out = append(out, value)
			}
			end, ok := token()
			return out, ok && end == json.Delim(']')
		default:
			return nil, false
		}
	}
	value, ok := read(0)
	if !ok {
		return nil, false
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, false
	}
	return value, true
}

func adaptiveIssuedB64(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || len(s) == 0 || base64.RawURLEncoding.DecodedLen(len(s)) > 262144 {
		return nil, false
	}
	r, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return r, e == nil && len(r) > 0 && len(r) <= 262144 && base64.RawURLEncoding.EncodeToString(r) == s
}

func decodeAdaptiveIssuedWire(raw []byte) (*routegraph.Graph, map[string]string, error) {
	bad := func() (*routegraph.Graph, map[string]string, error) { return nil, nil, ErrInvalid }
	if len(raw) < 1 || len(raw) > MaxAdaptivePlanBytes {
		return bad()
	}
	remaining := 32768
	value, ok := readAdaptiveIssuedJSON(raw, &remaining, adaptiveIssuedJSONLimits{4, 256, false})
	root, obj := value.(map[string]any)
	if !ok || !obj || len(root) != 4 || root["schemaVersion"] != json.Number("1") {
		return bad()
	}
	for _, key := range []string{"schemaVersion", "graphB64", "catalogueB64", "groups"} {
		if _, present := root[key]; !present {
			return bad()
		}
	}
	metadata, ok := adaptiveIssuedB64(root["graphB64"])
	if !ok {
		return bad()
	}
	catalogueRaw, ok := adaptiveIssuedB64(root["catalogueB64"])
	if !ok {
		return bad()
	}
	value, ok = readAdaptiveIssuedJSON(catalogueRaw, &remaining, adaptiveIssuedJSONLimits{500, 256, false})
	catalogue, obj := value.(map[string]any)
	if !ok || !obj || len(catalogue) < 1 || len(catalogue) > 500 {
		return bad()
	}
	canonical, e := json.Marshal(catalogue)
	if e != nil || !bytes.Equal(canonical, catalogueRaw) {
		return bad()
	}
	ids := make([]string, 0, len(catalogue))
	aliases := map[[32]byte]bool{}
	size := 0
	for hop, value := range catalogue {
		if !adaptiveHopID.MatchString(hop) {
			return bad()
		}
		profile, e := json.Marshal(value)
		if e != nil {
			return bad()
		}
		size += len(hop) + len(profile)
		if size > 262144 {
			return bad()
		}
		node, e := adaptiveCompiledNode(hop, profile)
		if e != nil || !graphProfile(node, map[string]bool{}).TCP {
			return bad()
		}
		delete(node, "tag")
		fingerprintRaw, e := json.Marshal(node)
		if e != nil {
			return bad()
		}
		fingerprint := sha256.Sum256(fingerprintRaw)
		if aliases[fingerprint] {
			return bad()
		}
		aliases[fingerprint] = true
		ids = append(ids, hop)
	}
	if _, ok = readAdaptiveIssuedJSON(metadata, &remaining, adaptiveIssuedJSONLimits{128, 4096, true}); !ok {
		return bad()
	}
	graph, e := routegraph.Decode(metadata, ids)
	if e != nil {
		return bad()
	}
	values, obj := root["groups"].(map[string]any)
	groupIDs := graph.GroupIDs()
	if !obj || len(groupIDs) < 1 || len(groupIDs) > 16 || len(values) != len(groupIDs) {
		return bad()
	}
	groups, tags := map[string]string{}, map[string]bool{}
	for _, id := range groupIDs {
		tag, ok := values[id].(string)
		if !ok || !adaptivePlanTag(tag) || tags[tag] {
			return bad()
		}
		tags[tag] = true
		groups[id] = tag
		info, _ := graph.GroupInfo(id)
		tcp := false
		for _, feature := range info.Features {
			if feature == "UDP" || feature == "ICMP" {
				return bad()
			}
			tcp = tcp || feature == "TCP"
		}
		if !tcp || info.MaxHops < 1 || info.MaxHops > 4 {
			return bad()
		}
	}
	return graph, groups, nil
}

func adaptiveIssuedFields(node map[string]any, names string) bool {
	allowed := map[string]bool{}
	for _, name := range strings.Fields(names) {
		allowed[name] = true
	}
	for key, value := range node {
		if !allowed[key] || value == nil {
			return false
		}
	}
	return true
}
func adaptiveIssuedString(node map[string]any, key string, required bool) (string, bool) {
	v, present := node[key]
	if !present {
		return "", !required
	}
	s, ok := v.(string)
	return s, ok && (!required || len(s) > 0)
}
func adaptiveIssuedStrings(v any, min, max int) ([]string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) < min || len(a) > max {
		return nil, false
	}
	out := make([]string, len(a))
	for i, item := range a {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}
func adaptiveIssuedInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := n.Int64()
	return i, e == nil
}
func adaptiveIssuedEqual(a, b any) bool {
	first, e := json.Marshal(a)
	second, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(first, second)
}
func adaptiveIssuedObject(raw []byte) (map[string]any, bool) {
	v, e := subscriptions.DecodeJSON(raw)
	m, ok := v.(map[string]any)
	return m, e == nil && ok
}

func adaptiveIssuedOutbounds(raws []json.RawMessage, graph *routegraph.Graph, groups map[string]string) (map[string]map[string]any, map[string]GraphCapability, error) {
	bad := func() (map[string]map[string]any, map[string]GraphCapability, error) { return nil, nil, ErrInvalid }
	nodes := map[string]map[string]any{}
	managed := map[string]string{}
	for group, tag := range groups {
		managed[tag] = group
	}
	seenManaged := map[string]bool{}
	netbirds := 0
	for _, raw := range raws {
		node, ok := adaptiveIssuedObject(raw)
		tag, t := adaptiveIssuedString(node, "tag", true)
		kind, k := adaptiveIssuedString(node, "type", true)
		if !ok || !t || !k || len(tag) > 256 || strings.Trim(tag, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != "" || nodes[tag] != nil {
			return bad()
		}
		switch kind {
		case "syn443-adaptive":
			group, g := adaptiveIssuedString(node, "group", true)
			if !g || len(node) != 3 || managed[tag] != group || seenManaged[group] {
				return bad()
			}
			seenManaged[group] = true
		case "direct":
			if len(node) != 2 || tag != "direct" {
				return bad()
			}
		case "selector":
			if !adaptiveIssuedFields(node, "type tag outbounds default interrupt_exist_connections") {
				return bad()
			}
			members, m := adaptiveIssuedStrings(node["outbounds"], 1, 16)
			if !m {
				return bad()
			}
			seen := map[string]bool{}
			for _, member := range members {
				if seen[member] {
					return bad()
				}
				seen[member] = true
			}
			if v, exists := node["interrupt_exist_connections"]; exists {
				if _, b := v.(bool); !b {
					return bad()
				}
			}
			if _, exists := node["default"]; exists {
				def, b := adaptiveIssuedString(node, "default", true)
				if !b || !seen[def] {
					return bad()
				}
			}
		case "http", "socks", "vless", "ssh":
			clone := map[string]any{}
			for key, value := range node {
				if key != "detour" {
					clone[key] = value
				}
			}
			if subscriptions.ValidateOutbound(clone) != nil {
				return bad()
			}
			if _, present := node["detour"]; present {
				if _, ok := adaptiveIssuedString(node, "detour", true); !ok {
					return bad()
				}
			}
		case "netbird":
			netbirds++
			if netbirds > 1 || adaptiveIssuedNetBird(node) != nil {
				return bad()
			}
		default:
			return bad()
		}
		if group, expected := managed[tag]; expected && (kind != "syn443-adaptive" || node["group"] != group) {
			return bad()
		}
		nodes[tag] = node
	}
	if len(seenManaged) != len(groups) || nodes["direct"] == nil {
		return bad()
	}
	caps := map[string]GraphCapability{}
	visiting := map[string]bool{}
	levels := map[string]int{}
	var visit func(string, int) (GraphCapability, error)
	visit = func(tag string, depth int) (GraphCapability, error) {
		n := nodes[tag]
		if n == nil || depth > 16 || visiting[tag] {
			return GraphCapability{}, ErrInvalid
		}
		if v, ok := caps[tag]; ok {
			if depth+levels[tag] > 16 {
				return GraphCapability{}, ErrInvalid
			}
			return v, nil
		}
		visiting[tag] = true
		defer delete(visiting, tag)
		kind := n["type"].(string)
		var result GraphCapability
		level := 0
		switch kind {
		case "direct":
			result = GraphCapability{TCP: true, UDP: true}
		case "syn443-adaptive":
			info, _ := graph.GroupInfo(n["group"].(string))
			result = GraphCapability{TCP: true, Hops: info.MaxHops}
		case "selector":
			result = GraphCapability{TCP: true, UDP: true}
			members, _ := adaptiveIssuedStrings(n["outbounds"], 1, 16)
			for _, member := range members {
				child, e := visit(member, depth+1)
				if e != nil {
					return result, e
				}
				result.TCP = result.TCP && child.TCP
				result.UDP = result.UDP && child.UDP
				result.Hops = max(result.Hops, child.Hops)
				level = max(level, levels[member]+1)
			}
		case "netbird":
			result = GraphCapability{TCP: true, UDP: true, Hops: 1}
			if n["connection_mode"] == "vless" {
				detour := n["detour"].(string)
				child, e := visit(detour, depth+1)
				if e != nil || !child.TCP || child.Hops >= 4 || netbirdVLESSDetour(raws, detour) != nil || adaptiveGraphDependency(raws, detour) {
					return result, ErrInvalid
				}
				result.Hops += child.Hops
				level = levels[detour] + 1
			}
		default:
			result = graphProfile(n, map[string]bool{})
			if detour, exists := n["detour"]; exists {
				child, e := visit(detour.(string), depth+1)
				if e != nil || !child.TCP {
					return result, ErrInvalid
				}
				result.Hops += child.Hops
				result.UDP = result.UDP && (kind == "vless" || child.UDP)
				level = levels[detour.(string)] + 1
			}
		}
		if result.Hops > 4 || depth+level > 16 {
			return result, ErrInvalid
		}
		caps[tag] = result
		levels[tag] = level
		return result, nil
	}
	for tag := range nodes {
		if _, e := visit(tag, 0); e != nil {
			return bad()
		}
	}
	return nodes, caps, nil
}

func adaptiveIssuedNetBird(node map[string]any) error {
	if !adaptiveIssuedFields(node, "type tag connection_mode management_url managed hostname detour") {
		return ErrInvalid
	}
	managed, ok := node["managed"].(map[string]any)
	if !ok || len(managed) != 6 || !adaptiveIssuedFields(managed, "overlayId resourceId networkId identityEpoch setupReference setupVersion") {
		return ErrInvalid
	}
	n := NetBirdNode{}
	var valid bool
	for key, dst := range map[string]*string{"tag": &n.Tag, "connection_mode": &n.Mode, "management_url": &n.ManagementURL, "hostname": &n.Hostname, "detour": &n.Detour} {
		*dst, valid = adaptiveIssuedString(node, key, key != "hostname" && key != "detour")
		if !valid {
			return ErrInvalid
		}
	}
	for key, dst := range map[string]*string{"overlayId": &n.OverlayID, "resourceId": &n.ResourceID, "networkId": &n.NetworkID} {
		*dst, valid = adaptiveIssuedString(managed, key, true)
		if !valid {
			return ErrInvalid
		}
	}
	n.IdentityEpoch, valid = adaptiveIssuedInt(managed["identityEpoch"])
	if !valid {
		return ErrInvalid
	}
	reference, valid := adaptiveIssuedString(managed, "setupReference", false)
	version, numeric := adaptiveIssuedInt(managed["setupVersion"])
	if !valid || !numeric || version < 0 || version > 9007199254740991 || len(reference) > 1024 || (reference == "") != (version == 0) || strings.ContainsAny(reference, "\x00\r\n") {
		return ErrInvalid
	}
	if n.validate() != nil {
		return ErrInvalid
	}
	expected := n.outbound()
	expected["managed"] = managed
	if !adaptiveIssuedEqual(node, expected) {
		return ErrInvalid
	}
	return nil
}

func adaptiveIssuedChecks(raw []byte, nodes map[string]map[string]any, caps map[string]GraphCapability, graph *routegraph.Graph, groups map[string]string) error {
	plans, e := routecheck.DecodePlans(raw)
	if e != nil {
		return ErrInvalid
	}
	// Adaptive issuance has always required an explicit boolean required field.
	// The general legacy policy decoder's omission compatibility is not an
	// authority to weaken this independent raw-engine envelope boundary.
	value, e := subscriptions.DecodeJSON(raw)
	rows, ok := value.([]any)
	if e != nil || !ok || len(rows) != len(plans) {
		return ErrInvalid
	}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || len(row) != 3 || !adaptiveIssuedFields(row, "outbound required checks profile") {
			return ErrInvalid
		}
		if _, ok := row["required"].(bool); !ok {
			return ErrInvalid
		}
		_, legacy := row["checks"]
		_, composed := row["profile"]
		if legacy == composed {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	intents := map[string]string{}
	for group, tag := range groups {
		info, _ := graph.GroupInfo(group)
		intents[tag] = info.Intent
	}
	for _, plan := range plans {
		tag := plan.Outbound
		if nodes[tag] == nil || !caps[tag].TCP || seen[tag] {
			return ErrInvalid
		}
		seen[tag] = true
		if intent, managed := intents[tag]; managed && plan.ValidateIntent(intent) != nil {
			return ErrInvalid
		}
	}
	for _, tag := range groups {
		if !seen[tag] {
			return ErrInvalid
		}
	}
	rawNodes := make([]json.RawMessage, 0, len(nodes))
	for _, node := range nodes {
		raw, e := json.Marshal(node)
		if e != nil {
			return ErrInvalid
		}
		rawNodes = append(rawNodes, raw)
	}
	managed := map[string]bool{}
	for _, tag := range groups {
		managed[tag] = true
	}
	return validateConcreteCheckPaths(rawNodes, plans, managed)
}

func adaptiveIssuedList(node map[string]any, key string, max int) ([]string, bool) {
	v, exists := node[key]
	if !exists {
		return nil, true
	}
	return adaptiveIssuedStrings(v, 1, max)
}
func adaptiveIssuedMatch(node map[string]any) (HostMatch, bool) {
	match := HostMatch{}
	for key, field := range map[string]*[]string{"domain": &match.Domains, "domain_suffix": &match.DomainSuffixes, "domain_keyword": &match.DomainKeywords, "domain_regex": &match.DomainRegex} {
		var ok bool
		*field, ok = adaptiveIssuedList(node, key, 64)
		if !ok {
			return HostMatch{}, false
		}
	}
	return match, true
}

func adaptiveIssuedRoute(raw []byte, compiled CompiledGraph) error {
	root, ok := adaptiveIssuedObject(raw)
	if !ok || len(root) != 2 || !adaptiveIssuedFields(root, "rules final") {
		return ErrInvalid
	}
	final, ok := adaptiveIssuedString(root, "final", true)
	if !ok {
		return ErrInvalid
	}
	if _, exists := compiled.Capabilities[final]; !exists {
		return ErrInvalid
	}
	rules, ok := root["rules"].([]any)
	if !ok || len(rules) > 128 {
		return ErrInvalid
	}
	for i, value := range rules {
		node, ok := value.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		rule := RouteRule{ID: "issued-" + strconv.Itoa(i)}
		rule.HostMatch, ok = adaptiveIssuedMatch(node)
		if !ok {
			return ErrInvalid
		}
		for key, field := range map[string]*[]string{"ip_cidr": &rule.IPPrefixes, "package_name": &rule.Packages, "network": &rule.Networks} {
			*field, ok = adaptiveIssuedList(node, key, 64)
			if !ok {
				return ErrInvalid
			}
		}
		rule.Action, ok = adaptiveIssuedString(node, "action", true)
		if !ok {
			return ErrInvalid
		}
		rule.Outbound, ok = adaptiveIssuedString(node, "outbound", false)
		if !ok {
			return ErrInvalid
		}
		if ports, exists := node["port"]; exists {
			a, ok := ports.([]any)
			if !ok || len(a) < 1 || len(a) > 32 {
				return ErrInvalid
			}
			for _, p := range a {
				n, ok := adaptiveIssuedInt(p)
				if !ok || n < 1 || n > 65535 {
					return ErrInvalid
				}
				rule.Ports = append(rule.Ports, PortRange{int(n), int(n)})
			}
		}
		if ranges, exists := node["port_range"]; exists {
			a, ok := adaptiveIssuedStrings(ranges, 1, 32)
			if !ok {
				return ErrInvalid
			}
			for _, value := range a {
				parts := strings.Split(value, ":")
				if len(parts) != 2 {
					return ErrInvalid
				}
				first, e := strconv.Atoi(parts[0])
				last, f := strconv.Atoi(parts[1])
				if e != nil || f != nil {
					return ErrInvalid
				}
				rule.Ports = append(rule.Ports, PortRange{first, last})
			}
		}
		matches := len(node)
		for _, key := range []string{"action", "outbound", "method"} {
			if _, exists := node[key]; exists {
				matches--
			}
		}
		rule.MatchAll = matches == 0
		emitted, e := emitRouteRule(rule, compiled)
		if e != nil || !adaptiveIssuedEqual(node, emitted) {
			return ErrInvalid
		}
	}
	return nil
}

func adaptiveIssuedDNS(raw []byte, compiled CompiledGraph) error {
	root, ok := adaptiveIssuedObject(raw)
	if !ok || len(root) != 4 || !adaptiveIssuedFields(root, "servers rules final strategy") {
		return ErrInvalid
	}
	strategy, ok := adaptiveIssuedString(root, "strategy", true)
	if !ok || (strategy != "prefer_ipv4" && strategy != "prefer_ipv6" && strategy != "ipv4_only" && strategy != "ipv6_only") {
		return ErrInvalid
	}
	servers, ok := root["servers"].([]any)
	if !ok || len(servers) < 1 || len(servers) > 17 {
		return ErrInvalid
	}
	known := map[string]bool{}
	for _, value := range servers {
		node, ok := value.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		tag, ok := adaptiveIssuedString(node, "tag", true)
		if !ok || known[tag] {
			return ErrInvalid
		}
		known[tag] = true
		if tag == "syn443_dns_system" {
			if len(node) != 2 || node["type"] != "local" {
				return ErrInvalid
			}
			continue
		}
		server := DNSServer{}
		server.Transport, ok = adaptiveIssuedString(node, "type", true)
		if !ok {
			return ErrInvalid
		}
		for key, field := range map[string]*string{"server": &server.Address, "path": &server.Path} {
			*field, ok = adaptiveIssuedString(node, key, false)
			if !ok {
				return ErrInvalid
			}
		}
		if value, exists := node["server_port"]; exists {
			port, ok := adaptiveIssuedInt(value)
			if !ok || port < 1 || port > 65535 {
				return ErrInvalid
			}
			server.Port = int(port)
		}
		if tls, exists := node["tls"]; exists {
			object, ok := tls.(map[string]any)
			if !ok {
				return ErrInvalid
			}
			server.ServerName, ok = adaptiveIssuedString(object, "server_name", false)
			if !ok {
				return ErrInvalid
			}
		}
		key := "detour"
		if server.Transport == "netbird" {
			key = "outbound"
		}
		server.Outbound, ok = adaptiveIssuedString(node, key, false)
		if !ok {
			return ErrInvalid
		}
		emitted, e := emitDNSServer(tag, server, compiled)
		if e != nil || !adaptiveIssuedEqual(node, emitted) {
			return ErrInvalid
		}
	}
	final, ok := adaptiveIssuedString(root, "final", true)
	if !ok || !known[final] || !known["syn443_dns_system"] {
		return ErrInvalid
	}
	rules, ok := root["rules"].([]any)
	if !ok || len(rules) > 64 {
		return ErrInvalid
	}
	for _, value := range rules {
		node, ok := value.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		match, ok := adaptiveIssuedMatch(node)
		if !ok {
			return ErrInvalid
		}
		emitted, e := emitHostMatch(match)
		if e != nil {
			return ErrInvalid
		}
		queries, ok := adaptiveIssuedList(node, "query_type", 16)
		if !ok || !networkStrings(queries, 16, func(s string) bool {
			return s == "A" || s == "AAAA" || s == "CNAME" || s == "MX" || s == "TXT" || s == "PTR" || s == "SRV" || s == "HTTPS" || s == "SVCB" || s == "NS" || s == "SOA"
		}) {
			return ErrInvalid
		}
		if len(queries) > 0 {
			emitted["query_type"] = queries
		}
		if len(emitted) == 0 {
			return ErrInvalid
		}
		server, ok := adaptiveIssuedString(node, "server", true)
		if !ok || !known[server] {
			return ErrInvalid
		}
		emitted["action"], emitted["server"] = "route", server
		if !adaptiveIssuedEqual(node, emitted) {
			return ErrInvalid
		}
	}
	return nil
}
