package configuration

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

// Portable network settings, not raw native options. Compiling does not grant
// publication authority: the caller must still fence layer/source permissions.
type HostMatch struct {
	Domains        []string `json:"domains,omitempty"`
	DomainSuffixes []string `json:"domainSuffixes,omitempty"`
	DomainKeywords []string `json:"domainKeywords,omitempty"`
	DomainRegex    []string `json:"domainRegex,omitempty"`
}
type PortRange struct {
	First int `json:"first"`
	Last  int `json:"last"`
}
type RouteRule struct {
	HostMatch  `json:"match"`
	ID         string      `json:"id"`
	IPPrefixes []string    `json:"ipPrefixes,omitempty"`
	Packages   []string    `json:"packages,omitempty"`
	Networks   []string    `json:"networks,omitempty"`
	Ports      []PortRange `json:"ports,omitempty"`
	MatchAll   bool        `json:"matchAll"`
	Action     string      `json:"action"`
	Outbound   string      `json:"outbound"`
}
type DNSServer struct {
	Transport  string `json:"transport"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"serverName"`
	Path       string `json:"path"`
	Outbound   string `json:"outbound"`
}
type DNSRule struct {
	HostMatch  `json:"match"`
	ID         string   `json:"id"`
	QueryTypes []string `json:"queryTypes,omitempty"`
	Server     string   `json:"server"`
}
type OutboundCheck struct {
	Method string `json:"method"`
	Target string `json:"target"`
}
type OutboundCheckPlan struct {
	Outbound string          `json:"outbound"`
	Required bool            `json:"required"`
	Checks   []OutboundCheck `json:"checks"`
}

// Initial failover is explicit and scoped to an internal destination rule.
// Public exit classes require independent exit evidence before adoption.
type RouteFailoverPlan struct {
	Selector             string                `json:"selector"`
	NetworkMode          string                `json:"networkMode"`
	Intent               string                `json:"intent"`
	ProbeCooldown        bool                  `json:"probeCooldown,omitempty"`
	ProbeCooldownRollout *ProbeCooldownRollout `json:"probeCooldownRollout,omitempty"`
}
type NetworkSettings struct {
	SchemaVersion    int                  `json:"schemaVersion"`
	RequiredNetworks []string             `json:"requiredNetworks"`
	Rules            []RouteRule          `json:"rules,omitempty"`
	DNSServers       map[string]DNSServer `json:"dnsServers,omitempty"`
	DNSRules         []DNSRule            `json:"dnsRules,omitempty"`
	DNSFinal         string               `json:"dnsFinal"`
	DNSStrategy      string               `json:"dnsStrategy"`
	RouteChecks      []OutboundCheckPlan  `json:"routeChecks,omitempty"`
	RouteFailover    *RouteFailoverPlan   `json:"routeFailover,omitempty"`
}

func (NetworkSettings) String() string     { return "NetworkSettings([redacted])" }
func (NetworkSettings) GoString() string   { return "NetworkSettings([redacted])" }
func (RouteRule) String() string           { return "RouteRule([redacted])" }
func (RouteRule) GoString() string         { return "RouteRule([redacted])" }
func (DNSServer) String() string           { return "DNSServer([redacted])" }
func (DNSServer) GoString() string         { return "DNSServer([redacted])" }
func (DNSRule) String() string             { return "DNSRule([redacted])" }
func (DNSRule) GoString() string           { return "DNSRule([redacted])" }
func (OutboundCheck) String() string       { return "OutboundCheck([redacted])" }
func (OutboundCheck) GoString() string     { return "OutboundCheck([redacted])" }
func (OutboundCheckPlan) String() string   { return "OutboundCheckPlan([redacted])" }
func (OutboundCheckPlan) GoString() string { return "OutboundCheckPlan([redacted])" }

func DecodeNetworkSettings(raw []byte) (NetworkSettings, error) {
	var value NetworkSettings
	if len(raw) > 262144 || identity.DecodeConfiguration(raw, &value) != nil {
		return NetworkSettings{}, ErrInvalid
	}
	parsed, err := subscriptions.DecodeJSON(raw)
	if err != nil || !boundedNumbers(parsed) {
		return NetworkSettings{}, ErrInvalid
	}
	return value, nil
}

func networkHost(value string, suffix bool) bool {
	if suffix {
		value = strings.TrimPrefix(value, ".")
	}
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}
func networkStrings(values []string, limit int, valid func(string) bool) bool {
	if len(values) > limit {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] || !valid(value) {
			return false
		}
		seen[value] = true
	}
	return true
}
func emitHostMatch(value HostMatch) (map[string]any, error) {
	result := map[string]any{}
	if !networkStrings(value.Domains, 64, func(s string) bool { return networkHost(s, false) }) || !networkStrings(value.DomainSuffixes, 64, func(s string) bool { return networkHost(s, true) }) || !networkStrings(value.DomainKeywords, 32, func(s string) bool {
		return len(s) > 0 && len(s) <= 128 && strings.ToLower(s) == s && !strings.ContainsAny(s, "\x00\r\n")
	}) || !networkStrings(value.DomainRegex, 16, func(s string) bool { _, err := regexp.Compile(s); return len(s) > 0 && len(s) <= 512 && err == nil }) {
		return nil, ErrInvalid
	}
	for name, list := range map[string][]string{"domain": value.Domains, "domain_suffix": value.DomainSuffixes, "domain_keyword": value.DomainKeywords, "domain_regex": value.DomainRegex} {
		if len(list) > 0 {
			result[name] = list
		}
	}
	return result, nil
}
func requireNetwork(capability GraphCapability, values []string) error {
	if len(values) < 1 || !networkStrings(values, 2, func(s string) bool { return s == "tcp" || s == "udp" }) {
		return ErrInvalid
	}
	for _, network := range values {
		if network == "tcp" && !capability.TCP || network == "udp" && !capability.UDP {
			return ErrInvalid
		}
	}
	return nil
}

var androidPackage = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

func emitRouteRule(rule RouteRule, graph CompiledGraph) (map[string]any, error) {
	result, err := emitHostMatch(rule.HostMatch)
	if err != nil || !id.MatchString(rule.ID) || !networkStrings(rule.IPPrefixes, 64, func(s string) bool { p, e := netip.ParsePrefix(s); return e == nil && p.Masked().String() == s }) || !networkStrings(rule.Packages, 64, func(s string) bool { return len(s) <= 255 && androidPackage.MatchString(s) }) || !networkStrings(rule.Networks, 2, func(s string) bool { return s == "tcp" || s == "udp" }) || len(rule.Ports) > 32 {
		return nil, ErrInvalid
	}
	for name, list := range map[string][]string{"ip_cidr": rule.IPPrefixes, "package_name": rule.Packages, "network": rule.Networks} {
		if len(list) > 0 {
			result[name] = list
		}
	}
	ports := []int{}
	ranges := []string{}
	for index, p := range rule.Ports {
		if p.First < 1 || p.Last < p.First || p.Last > 65535 {
			return nil, ErrInvalid
		}
		for _, other := range rule.Ports[:index] {
			if max(p.First, other.First) <= min(p.Last, other.Last) {
				return nil, ErrInvalid
			}
		}
		if p.First == p.Last {
			ports = append(ports, p.First)
		} else {
			ranges = append(ranges, strconv.Itoa(p.First)+":"+strconv.Itoa(p.Last))
		}
	}
	if len(ports) > 0 {
		result["port"] = ports
	}
	if len(ranges) > 0 {
		result["port_range"] = ranges
	}
	if rule.MatchAll != (len(result) == 0) {
		return nil, ErrInvalid
	}
	switch rule.Action {
	case "route":
		capability, ok := graph.Capabilities[rule.Outbound]
		networks := rule.Networks
		if len(networks) == 0 {
			networks = []string{"tcp", "udp"}
		}
		if !ok || requireNetwork(capability, networks) != nil {
			return nil, ErrInvalid
		}
		result["action"], result["outbound"] = "route", rule.Outbound
	case "reject":
		if rule.Outbound != "" {
			return nil, ErrInvalid
		}
		result["action"], result["method"] = "reject", "drop"
	default:
		return nil, ErrInvalid
	}
	return result, nil
}

func emitDNSServer(tag string, server DNSServer, graph CompiledGraph) (map[string]any, error) {
	if !graphTag(tag) || tag == "system" {
		return nil, ErrInvalid
	}
	result := map[string]any{"tag": tag, "type": server.Transport}
	if server.Transport == "netbird" {
		if server.Address != "" || server.Port != 0 || server.ServerName != "" || server.Path != "" || server.Outbound == "" {
			return nil, ErrInvalid
		}
		for _, raw := range graph.Outbounds {
			var node struct {
				Type string `json:"type"`
				Tag  string `json:"tag"`
			}
			if json.Unmarshal(raw, &node) != nil {
				return nil, ErrInvalid
			}
			if node.Tag == server.Outbound && node.Type == "netbird" {
				result["outbound"] = server.Outbound
				return result, nil
			}
		}
		return nil, ErrInvalid
	}
	if server.Transport == "local" {
		if server.Address != "" || server.Port != 0 || server.ServerName != "" || server.Path != "" || server.Outbound != "" {
			return nil, ErrInvalid
		}
		return result, nil
	}
	network := "tcp"
	switch server.Transport {
	case "udp", "quic", "h3":
		network = "udp"
	case "tcp", "tls", "https":
	default:
		return nil, ErrInvalid
	}
	if server.Address == "" || net.ParseIP(server.Address) == nil && !networkHost(server.Address, false) || server.Port < 1 || server.Port > 65535 {
		return nil, ErrInvalid
	}
	secured := server.Transport == "tls" || server.Transport == "https" || server.Transport == "quic" || server.Transport == "h3"
	if !secured && server.ServerName != "" || server.ServerName != "" && !networkHost(server.ServerName, false) {
		return nil, ErrInvalid
	}
	if server.Transport != "https" && server.Transport != "h3" {
		if server.Path != "" {
			return nil, ErrInvalid
		}
	} else if !strings.HasPrefix(server.Path, "/") || strings.HasPrefix(server.Path, "//") || len(server.Path) > 512 || strings.ContainsAny(server.Path, "?#\x00\r\n") {
		return nil, ErrInvalid
	}
	result["server"], result["server_port"] = server.Address, server.Port
	if net.ParseIP(server.Address) == nil {
		result["domain_resolver"] = "syn443_dns_system"
	}
	if secured {
		tls := map[string]any{"enabled": true}
		if server.ServerName != "" {
			tls["server_name"] = server.ServerName
		}
		result["tls"] = tls
	}
	if server.Path != "" {
		result["path"] = server.Path
	}
	via := server.Outbound
	if via == "" {
		via = "direct"
	}
	capability, ok := graph.Capabilities[via]
	if !ok || requireNetwork(capability, []string{network}) != nil {
		return nil, ErrInvalid
	}
	// Native DNS rejects a detour to an empty direct outbound. Omitting it uses
	// the protected physical dialer; only actual proxy paths carry a detour tag.
	if via != "direct" {
		result["detour"] = via
	}
	return result, nil
}

// CompileNetwork produces the narrow engine network document. It neither
// flattens source-layer provenance nor exports subscription URLs or SDK keys.
func outboundCheckHost(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" || networkHost(host, false)
}

func outboundCheckPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && len(port) <= 5 &&
		strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func outboundCheckTarget(check OutboundCheck) bool {
	raw := check.Target
	if len(raw) < 1 || len(raw) > 2048 || strings.IndexFunc(raw, func(r rune) bool { return r <= 32 || r > 126 }) >= 0 {
		return false
	}
	switch check.Method {
	case "tcp", "ssh_banner":
		host, port, err := net.SplitHostPort(raw)
		return err == nil && outboundCheckHost(host) && outboundCheckPort(port)
	case "tls", "https_204":
		target, err := url.Parse(raw)
		return err == nil && target.Scheme == "https" && target.User == nil && target.Opaque == "" &&
			!strings.Contains(raw, "#") && !strings.HasSuffix(target.Host, ":") && outboundCheckHost(target.Hostname()) &&
			(target.Port() == "" || outboundCheckPort(target.Port()))
	default:
		return false
	}
}

func routeChecks(graph CompiledGraph, plans []OutboundCheckPlan) (json.RawMessage, error) {
	if len(plans) == 0 {
		return nil, nil
	}
	if len(plans) > 16 {
		return nil, ErrInvalid
	}
	seen := make(map[string]bool, len(plans))
	for _, plan := range plans {
		path, ok := graph.Capabilities[plan.Outbound]
		if !ok || !path.TCP || seen[plan.Outbound] || len(plan.Checks) < 1 || len(plan.Checks) > 4 {
			return nil, ErrInvalid
		}
		seen[plan.Outbound] = true
		for _, check := range plan.Checks {
			if !outboundCheckTarget(check) {
				return nil, ErrInvalid
			}
		}
	}
	encoded, err := json.Marshal(plans)
	if err != nil || len(encoded) > 24000 {
		return nil, ErrInvalid
	}
	return encoded, nil
}

type routeSelectorNode struct {
	Tag       string   `json:"tag"`
	Kind      string   `json:"type"`
	Detour    string   `json:"detour"`
	Members   []string `json:"outbounds"`
	Interrupt bool     `json:"interrupt_exist_connections"`
}

var failoverTag = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func routeFailover(graph CompiledGraph, settings NetworkSettings) (map[string]any, error) {
	plan := settings.RouteFailover
	if plan == nil {
		return nil, nil
	}
	if plan.ProbeCooldownRollout != nil && (!plan.ProbeCooldown || !plan.ProbeCooldownRollout.valid()) {
		return nil, ErrInvalid
	}
	if plan.NetworkMode != "wifi" || plan.Intent != "INTERNAL" || plan.Selector == graph.Final || !failoverTag.MatchString(plan.Selector) {
		return nil, ErrInvalid
	}
	nodes := make(map[string]routeSelectorNode, len(graph.Outbounds))
	for _, raw := range graph.Outbounds {
		var node routeSelectorNode
		if json.Unmarshal(raw, &node) != nil || node.Tag == "" || node.Detour == plan.Selector ||
			slices.Contains(node.Members, plan.Selector) {
			return nil, ErrInvalid
		}
		nodes[node.Tag] = node
	}
	selector := nodes[plan.Selector]
	if selector.Kind != "selector" || selector.Interrupt || len(selector.Members) < 2 || len(selector.Members) > 8 {
		return nil, ErrInvalid
	}
	rules := 0
	for _, rule := range settings.Rules {
		if rule.Action != "route" || rule.Outbound != plan.Selector {
			continue
		}
		if rule.MatchAll || len(rule.Domains)+len(rule.DomainSuffixes)+len(rule.IPPrefixes) == 0 ||
			len(rule.DomainKeywords)+len(rule.DomainRegex) != 0 {
			return nil, ErrInvalid
		}
		rules++
	}
	for _, server := range settings.DNSServers {
		if server.Outbound == plan.Selector {
			return nil, ErrInvalid
		}
	}
	if rules != 1 {
		return nil, ErrInvalid
	}
	byOutbound := map[string]OutboundCheckPlan{}
	for _, check := range settings.RouteChecks {
		byOutbound[check.Outbound] = check
	}
	base := byOutbound[plan.Selector]
	if !base.Required || len(base.Checks) == 0 {
		return nil, ErrInvalid
	}
	for _, member := range selector.Members {
		check := byOutbound[member]
		if !failoverTag.MatchString(member) || check.Required || !slices.Equal(base.Checks, check.Checks) {
			return nil, ErrInvalid
		}
		visited := map[string]bool{}
		for tag := member; tag != ""; tag = nodes[tag].Detour {
			if visited[tag] || len(visited) == 4 {
				return nil, ErrInvalid
			}
			visited[tag] = true
			switch nodes[tag].Kind {
			case "http", "socks", "vless", "ssh":
			default:
				return nil, ErrInvalid
			}
		}
	}
	return map[string]any{"selector": plan.Selector, "network_mode": plan.NetworkMode, "intent": plan.Intent,
		"members": selector.Members}, nil
}

func CompileNetwork(graph CompiledGraph, settings NetworkSettings) (json.RawMessage, error) {
	if settings.SchemaVersion != 1 || len(graph.Outbounds) < 1 || len(graph.Outbounds) > 64 || len(settings.Rules) > 128 || len(settings.DNSServers) > 16 || len(settings.DNSRules) > 64 {
		return nil, ErrInvalid
	}
	capability, ok := graph.Capabilities[graph.Final]
	if !ok || requireNetwork(capability, settings.RequiredNetworks) != nil {
		return nil, ErrInvalid
	}
	if !networkStrings([]string{settings.DNSStrategy}, 1, func(s string) bool {
		return s == "prefer_ipv4" || s == "prefer_ipv6" || s == "ipv4_only" || s == "ipv6_only"
	}) {
		return nil, ErrInvalid
	}
	rules := []any{}
	ids := map[string]bool{}
	for _, rule := range settings.Rules {
		if ids[rule.ID] {
			return nil, ErrInvalid
		}
		ids[rule.ID] = true
		node, err := emitRouteRule(rule, graph)
		if err != nil {
			return nil, err
		}
		rules = append(rules, node)
	}
	dnsServers := []any{map[string]any{"type": "local", "tag": "syn443_dns_system"}}
	dnsIDs := map[string]bool{"system": true}
	tags := []string{}
	for tag := range settings.DNSServers {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		node, err := emitDNSServer(tag, settings.DNSServers[tag], graph)
		if err != nil {
			return nil, err
		}
		dnsServers = append(dnsServers, node)
		dnsIDs[tag] = true
	}
	if !dnsIDs[settings.DNSFinal] {
		return nil, ErrInvalid
	}
	dnsTag := func(tag string) string {
		if tag == "system" {
			return "syn443_dns_system"
		}
		return tag
	}
	dnsRules := []any{}
	ids = map[string]bool{}
	for _, rule := range settings.DNSRules {
		node, err := emitHostMatch(rule.HostMatch)
		if err != nil || !id.MatchString(rule.ID) || ids[rule.ID] || !dnsIDs[rule.Server] || !networkStrings(rule.QueryTypes, 16, func(s string) bool {
			return s == "A" || s == "AAAA" || s == "CNAME" || s == "MX" || s == "TXT" || s == "PTR" || s == "SRV" || s == "HTTPS" || s == "SVCB" || s == "NS" || s == "SOA"
		}) {
			return nil, ErrInvalid
		}
		ids[rule.ID] = true
		if len(rule.QueryTypes) > 0 {
			node["query_type"] = rule.QueryTypes
		}
		if len(node) == 0 {
			return nil, ErrInvalid
		}
		node["action"], node["server"] = "route", dnsTag(rule.Server)
		dnsRules = append(dnsRules, node)
	}
	metadata, err := routeChecks(graph, settings.RouteChecks)
	if err != nil {
		return nil, err
	}
	output := map[string]any{"outbounds": graph.Outbounds, "route": map[string]any{"rules": rules, "final": graph.Final}, "dns": map[string]any{"servers": dnsServers, "rules": dnsRules, "final": dnsTag(settings.DNSFinal), "strategy": settings.DNSStrategy}}
	if metadata != nil {
		output["route_checks"] = metadata
	}
	failover, err := routeFailover(graph, settings)
	if err != nil {
		return nil, err
	}
	if failover != nil {
		output["route_failover"] = failover
	}
	result, err := json.Marshal(output)
	if err != nil || len(result) > 262144 {
		return nil, ErrInvalid
	}
	return result, nil
}
