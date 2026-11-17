package configuration

import (
	"encoding/json"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/routecheck"
)

// validateConcreteCheckPaths derives path stability from actual engine nodes,
// not a profile flag. Managed roots are admitted only at the adaptive boundary;
// a static prefix cannot hide a variable managed detour.
func validateConcreteCheckPaths(outbounds []json.RawMessage, plans []OutboundCheckPlan, managed map[string]bool) error {
	type node struct {
		Type    string `json:"type"`
		Tag     string `json:"tag"`
		Detour  string `json:"detour"`
		Network string `json:"network"`
	}
	nodes := map[string]node{}
	for _, raw := range outbounds {
		var n node
		if json.Unmarshal(raw, &n) != nil || n.Tag == "" {
			return ErrInvalid
		}
		if _, ok := nodes[n.Tag]; ok {
			return ErrInvalid
		}
		nodes[n.Tag] = n
	}
	for _, p := range plans {
		if p.Profile == nil {
			continue
		}
		if n, ok := nodes[p.Outbound]; ok && n.Type == "syn443-adaptive" && managed[p.Outbound] {
			continue
		}
		seen := map[string]bool{}
		hops := 0
		for tag := p.Outbound; tag != ""; {
			n, ok := nodes[tag]
			if !ok || seen[tag] {
				return ErrInvalid
			}
			seen[tag] = true
			if len(seen) > 4 {
				return ErrInvalid
			}
			switch n.Type {
			case "direct":
				if n.Detour != "" {
					return ErrInvalid
				}
			case "http", "socks", "ssh":
				hops++
			case "vless":
				if n.Network == "udp" {
					return ErrInvalid
				}
				hops++
			default:
				return ErrInvalid
			}
			if hops > 4 {
				return ErrInvalid
			}
			tag = n.Detour
		}
	}
	return nil
}

// ValidateIssuedCheckPlans independently checks the raw issued-engine boundary
// even for a forged PreparedConfiguration that never called the compiler.
// Adaptive graph/intent checks remain in ValidateAdaptiveIssuedEngine.
func ValidateIssuedCheckPlans(raw []byte) error {
	var root map[string]json.RawMessage
	if len(raw) < 1 || len(raw) > 262144 || identity.DecodeConfiguration(raw, &root) != nil || root == nil {
		return ErrInvalid
	}
	checks, present := root["route_checks"]
	if !present {
		return nil
	}
	plans, e := routecheck.DecodePlans(checks)
	if e != nil {
		return ErrInvalid
	}
	var outbounds []json.RawMessage
	if json.Unmarshal(root["outbounds"], &outbounds) != nil || len(outbounds) < 1 || len(outbounds) > 64 {
		return ErrInvalid
	}
	seen, tags := map[string]bool{}, map[string]bool{}
	for _, raw := range outbounds {
		var node struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(raw, &node) != nil || node.Tag == "" || tags[node.Tag] {
			return ErrInvalid
		}
		tags[node.Tag] = true
	}
	managed := map[string]bool{}
	if _, adaptive := root["adaptive_routes"]; adaptive {
		if ValidateAdaptiveIssuedEngine(raw) != nil {
			return ErrInvalid
		}
		for _, raw := range outbounds {
			var node struct {
				Type string `json:"type"`
				Tag  string `json:"tag"`
			}
			if json.Unmarshal(raw, &node) != nil {
				return ErrInvalid
			}
			if node.Type == "syn443-adaptive" {
				managed[node.Tag] = true
			}
		}
	}
	for _, p := range plans {
		if _, failover := root["route_failover"]; failover && p.Profile != nil {
			return ErrInvalid
		}
	}
	for _, p := range plans {
		if !tags[p.Outbound] || seen[p.Outbound] {
			return ErrInvalid
		}
		seen[p.Outbound] = true
	}
	return validateConcreteCheckPaths(outbounds, plans, managed)
}
