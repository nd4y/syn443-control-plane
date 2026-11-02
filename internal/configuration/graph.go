package configuration

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

type ProfileReference struct {
	SourceID  string `json:"sourceId"`
	ProfileID string `json:"profileId"`
}
type Chain struct {
	DialOrder []string `json:"dialOrder"`
}
type Balancer struct {
	Type              string   `json:"type"`
	Members           []string `json:"members"`
	Default           string   `json:"default,omitempty"`
	URL               string   `json:"url,omitempty"`
	IntervalSeconds   int      `json:"intervalSeconds,omitempty"`
	ToleranceMs       int      `json:"toleranceMs,omitempty"`
	InterruptExisting bool     `json:"interruptExisting"`
}

// Graph is portable control data. Profile credentials come only from an
// independently authorized immutable source selection, not arbitrary JSON.
type Graph struct {
	Profiles  map[string]ProfileReference `json:"profiles"`
	Chains    map[string]Chain            `json:"chains"`
	Balancers map[string]Balancer         `json:"balancers"`
	Final     string                      `json:"final"`
}
type GraphCapability struct {
	TCP  bool `json:"tcp"`
	UDP  bool `json:"udp"`
	Hops int  `json:"hops"`
}
type CompiledGraph struct {
	Outbounds              []json.RawMessage
	Final                  string
	Capabilities           map[string]GraphCapability
	RequiredEngineFeatures []string
}

func (Graph) String() string           { return "ConfigurationGraph([redacted])" }
func (Graph) GoString() string         { return "ConfigurationGraph([redacted])" }
func (CompiledGraph) String() string   { return "CompiledGraph([redacted])" }
func (CompiledGraph) GoString() string { return "CompiledGraph([redacted])" }
func DecodeGraph(raw []byte) (Graph, error) {
	var graph Graph
	if len(raw) > 262144 || identity.DecodeConfiguration(raw, &graph) != nil {
		return graph, ErrInvalid
	}
	return graph, nil
}

var graphProfileID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func graphTag(tag string) bool {
	return id.MatchString(tag) && tag != "direct" && !strings.HasPrefix(tag, "syn443_")
}
func graphProfile(m map[string]any, features map[string]bool) GraphCapability {
	kind, _ := m["type"].(string)
	features[kind] = true
	if tls, ok := m["tls"].(map[string]any); ok {
		features[kind+".tls"] = true
		if _, ok = tls["reality"]; ok {
			features[kind+".reality"] = true
		}
	}
	if transport, ok := m["transport"].(map[string]any); ok {
		if kind, ok := transport["type"].(string); ok {
			features["vless."+kind] = true
		}
	}
	result := GraphCapability{TCP: true, Hops: 1}
	switch kind {
	case "vless":
		result.UDP = m["network"] != "tcp"
		result.TCP = m["network"] != "udp"
	case "socks":
		result.UDP = m["version"] == nil || m["version"] == "" || m["version"] == "5"
	}
	return result
}

// CompileGraph has no signing, network or SQL authority. resolve must read from
// a signer-owned source selection whose final SQL fence will still be checked.
func CompileGraph(g Graph, resolve func(ProfileReference) (subscriptions.Profile, error)) (CompiledGraph, error) {
	result := CompiledGraph{Final: g.Final, Capabilities: map[string]GraphCapability{"direct": {TCP: true, UDP: true}}, Outbounds: []json.RawMessage{json.RawMessage(`{"type":"direct","tag":"direct"}`)}}
	if len(g.Profiles) > 32 || len(g.Chains) > 16 || len(g.Balancers) > 16 || !id.MatchString(g.Final) {
		return CompiledGraph{}, ErrInvalid
	}
	features := map[string]bool{}
	defined := map[string]bool{"direct": true}
	keys := []string{}
	add := func(tag string) bool {
		if !graphTag(tag) || defined[tag] {
			return false
		}
		defined[tag] = true
		keys = append(keys, tag)
		return true
	}
	for tag := range g.Profiles {
		if !add(tag) {
			return CompiledGraph{}, ErrInvalid
		}
	}
	for tag := range g.Chains {
		if !add(tag) {
			return CompiledGraph{}, ErrInvalid
		}
	}
	for tag := range g.Balancers {
		if !add(tag) {
			return CompiledGraph{}, ErrInvalid
		}
	}
	if !defined[g.Final] {
		return CompiledGraph{}, ErrInvalid
	}
	sort.Strings(keys)
	leaves := map[string]map[string]any{}
	cache := map[ProfileReference]subscriptions.Profile{}
	emit := func(node any) error {
		if len(result.Outbounds) >= 64 {
			return ErrInvalid
		}
		raw, e := json.Marshal(node)
		if e != nil || len(raw) > 262144 {
			return ErrInvalid
		}
		result.Outbounds = append(result.Outbounds, raw)
		return nil
	}
	for _, tag := range keys {
		ref, ok := g.Profiles[tag]
		if !ok {
			continue
		}
		if len(ref.SourceID) < 1 || len(ref.SourceID) > 48 || !id.MatchString(ref.SourceID) || !graphProfileID.MatchString(ref.ProfileID) {
			return CompiledGraph{}, ErrInvalid
		}
		if resolve == nil {
			return CompiledGraph{}, ErrInvalid
		}
		profile, found := cache[ref]
		if !found {
			var e error
			profile, e = resolve(ref)
			if e != nil {
				return CompiledGraph{}, e
			}
			cache[ref] = profile
		}
		value, e := subscriptions.DecodeJSON(profile.Outbound)
		node, ok := value.(map[string]any)
		if e != nil || !ok || profile.ID != ref.ProfileID || node["tag"] != profile.ID || node["type"] != profile.Kind || subscriptions.ValidateOutbound(node) != nil {
			return CompiledGraph{}, ErrInvalid
		}
		node["tag"] = tag
		leaves[tag] = node
		result.Capabilities[tag] = graphProfile(node, features)
		if e = emit(node); e != nil {
			return CompiledGraph{}, e
		}
	}
	colors := map[string]int{}
	var visit func(string, int) (GraphCapability, error)
	visit = func(tag string, depth int) (GraphCapability, error) {
		if depth > 16 || !defined[tag] || colors[tag] == 1 {
			return GraphCapability{}, ErrInvalid
		}
		if c, ok := result.Capabilities[tag]; ok {
			return c, nil
		}
		colors[tag] = 1
		var capability GraphCapability
		if chain, ok := g.Chains[tag]; ok {
			if len(chain.DialOrder) < 1 || len(chain.DialOrder) > 4 {
				return capability, ErrInvalid
			}
			seen := map[string]bool{}
			previous := ""
			for i, member := range chain.DialOrder {
				if seen[member] {
					return capability, ErrInvalid
				}
				seen[member] = true
				child, e := visit(member, depth+1)
				if e != nil {
					return capability, e
				}
				if i == 0 {
					capability = child
					previous = member
					continue
				}
				// A selector may be an entry. A later selector needs branch expansion and
				// is rejected instead of silently dropping its incoming detour.
				leaf, ok := leaves[member]
				if !ok || !capability.TCP {
					return capability, ErrInvalid
				}
				capability = GraphCapability{TCP: child.TCP, UDP: child.UDP && (leaf["type"] == "vless" || capability.UDP), Hops: capability.Hops + 1}
				if capability.Hops > 4 {
					return capability, ErrInvalid
				}
				clone := map[string]any{}
				for k, v := range leaf {
					clone[k] = v
				}
				next := "syn443_hop_" + tag + "_" + strconv.Itoa(i)
				if i == len(chain.DialOrder)-1 {
					next = tag
				}
				clone["tag"] = next
				clone["detour"] = previous
				if e = emit(clone); e != nil {
					return capability, e
				}
				previous = next
			}
			if len(chain.DialOrder) == 1 {
				if e := emit(map[string]any{"type": "selector", "tag": tag, "outbounds": []string{previous}, "default": previous}); e != nil {
					return capability, e
				}
			}
		} else if balancer, ok := g.Balancers[tag]; ok {
			if len(balancer.Members) < 1 || len(balancer.Members) > 16 {
				return capability, ErrInvalid
			}
			if balancer.Type != "selector" && balancer.Type != "urltest" {
				return capability, ErrInvalid
			}
			capability = GraphCapability{TCP: true, UDP: true}
			seen := map[string]bool{}
			for _, member := range balancer.Members {
				if seen[member] {
					return capability, ErrInvalid
				}
				seen[member] = true
				child, e := visit(member, depth+1)
				if e != nil {
					return capability, e
				}
				if balancer.Type == "urltest" && !child.TCP {
					return capability, ErrInvalid
				}
				capability.TCP = capability.TCP && child.TCP
				capability.UDP = capability.UDP && child.UDP
				capability.Hops = max(capability.Hops, child.Hops)
			}
			node := map[string]any{"type": balancer.Type, "tag": tag, "outbounds": balancer.Members, "interrupt_exist_connections": balancer.InterruptExisting}
			if balancer.Type == "selector" {
				if balancer.URL != "" || balancer.IntervalSeconds != 0 || balancer.ToleranceMs != 0 || balancer.Default != "" && !seen[balancer.Default] {
					return capability, ErrInvalid
				}
				if balancer.Default != "" {
					node["default"] = balancer.Default
				}
			} else {
				u, e := url.Parse(balancer.URL)
				if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(balancer.URL) > 2048 || balancer.IntervalSeconds < 30 || balancer.IntervalSeconds > 86400 || balancer.ToleranceMs < 0 || balancer.ToleranceMs > 10000 || balancer.Default != "" {
					return capability, ErrInvalid
				}
				node["url"] = balancer.URL
				node["interval"] = strconv.Itoa(balancer.IntervalSeconds) + "s"
				node["tolerance"] = balancer.ToleranceMs
			}
			features[balancer.Type] = true
			if e := emit(node); e != nil {
				return capability, e
			}
		} else {
			return capability, ErrInvalid
		}
		colors[tag] = 2
		result.Capabilities[tag] = capability
		return capability, nil
	}
	for _, tag := range keys {
		if _, e := visit(tag, 0); e != nil {
			return CompiledGraph{}, e
		}
	}
	for feature := range features {
		result.RequiredEngineFeatures = append(result.RequiredEngineFeatures, feature)
	}
	sort.Strings(result.RequiredEngineFeatures)
	raw, e := json.Marshal(result.Outbounds)
	if e != nil || len(raw) > 262144 {
		return CompiledGraph{}, ErrInvalid
	}
	return result, nil
}
