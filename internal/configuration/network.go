package configuration

import (
	"encoding/json"
	"net"
	"net/netip"
	"regexp"
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
type NetworkSettings struct {
	SchemaVersion    int                  `json:"schemaVersion"`
	RequiredNetworks []string             `json:"requiredNetworks"`
	Rules            []RouteRule          `json:"rules,omitempty"`
	DNSServers       map[string]DNSServer `json:"dnsServers,omitempty"`
	DNSRules         []DNSRule            `json:"dnsRules,omitempty"`
	DNSFinal         string               `json:"dnsFinal"`
	DNSStrategy      string               `json:"dnsStrategy"`
}

func (NetworkSettings) String() string   { return "NetworkSettings([redacted])" }
func (NetworkSettings) GoString() string { return "NetworkSettings([redacted])" }
func (RouteRule) String() string         { return "RouteRule([redacted])" }
func (RouteRule) GoString() string       { return "RouteRule([redacted])" }
func (DNSServer) String() string         { return "DNSServer([redacted])" }
func (DNSServer) GoString() string       { return "DNSServer([redacted])" }
func (DNSRule) String() string           { return "DNSRule([redacted])" }
func (DNSRule) GoString() string         { return "DNSRule([redacted])" }

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
	result, err := json.Marshal(map[string]any{"outbounds": graph.Outbounds, "route": map[string]any{"rules": rules, "final": graph.Final}, "dns": map[string]any{"servers": dnsServers, "rules": dnsRules, "final": dnsTag(settings.DNSFinal), "strategy": settings.DNSStrategy}})
	if err != nil || len(result) > 262144 {
		return nil, ErrInvalid
	}
	return result, nil
}
