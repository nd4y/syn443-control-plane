package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

const AdaptiveTCPAlgorithm = "m4-graph-tcp-v1"

// A static chain may use a managed group as its first complete prefix, but the
// NetBird SDK underlay cannot yet borrow that ownership, even behind VLESS.
func adaptiveGraphDependency(outbounds []json.RawMessage, start string) bool {
	type node struct {
		Type    string   `json:"type"`
		Tag     string   `json:"tag"`
		Detour  string   `json:"detour"`
		Members []string `json:"outbounds"`
	}
	nodes := make(map[string]node, len(outbounds))
	for _, raw := range outbounds {
		var n node
		if json.Unmarshal(raw, &n) != nil || n.Tag == "" {
			return true
		}
		nodes[n.Tag] = n
	}
	seen := map[string]bool{}
	var visit func(string) bool
	visit = func(tag string) bool {
		if tag == "" {
			return false
		}
		n, ok := nodes[tag]
		if !ok || seen[tag] {
			return !ok
		}
		seen[tag] = true
		if n.Type == "syn443-adaptive" || visit(n.Detour) {
			return true
		}
		for _, child := range n.Members {
			if visit(child) {
				return true
			}
		}
		return false
	}
	return visit(start)
}

// This validates the same extra structural fences as the native catalogue.
// Deep protocol/TLS/transport validity is still checked by ValidateOutbound;
// optional nulls and string SSH host keys cannot survive the native wire.
func adaptiveCompiledNode(hop string, raw json.RawMessage) (map[string]any, error) {
	if len(raw) < 1 || len(raw) > 65536 {
		return nil, ErrInvalid
	}
	value, err := subscriptions.DecodeJSON(raw)
	node, ok := value.(map[string]any)
	if err != nil || !ok || node["tag"] != hop || subscriptions.ValidateOutbound(node) != nil {
		return nil, ErrInvalid
	}
	if kind, _ := node["type"].(string); kind == "ssh" {
		keys, ok := node["host_key"].([]any)
		if !ok || len(keys) < 1 {
			return nil, ErrInvalid
		}
	}
	if node["type"] == "vless" && node["network"] == "udp" {
		return nil, ErrInvalid
	}
	return node, nil
}

// Mirrors the native wire's combined token/depth/member/array budget over the
// already owned parsed values. This does not broaden any request decoder.
func adaptiveWireTokens(value any, remaining *int, depth, rootMembers, arrayItems int, allowNull bool) bool {
	if remaining == nil || depth > 16 || *remaining <= 0 || value == nil && !allowNull {
		return false
	}
	*remaining -= 1
	switch v := value.(type) {
	case map[string]any:
		limit := 128
		if depth == 0 {
			limit = rootMembers
		}
		if len(v) > limit {
			return false
		}
		for _, child := range v {
			if *remaining <= 0 {
				return false
			}
			*remaining -= 1 // member name
			if !adaptiveWireTokens(child, remaining, depth+1, rootMembers, arrayItems, allowNull) {
				return false
			}
		}
		*remaining -= 1 // closing delimiter
	case []any:
		if len(v) > arrayItems {
			return false
		}
		for _, child := range v {
			if !adaptiveWireTokens(child, remaining, depth+1, rootMembers, arrayItems, allowNull) {
				return false
			}
		}
		*remaining -= 1
	case nil, string, bool, json.Number:
	default:
		return false
	}
	return *remaining >= 0
}

func compileAdaptiveNetworkPlan(ctx context.Context, plan NetworkPlan, resolve func(ProfileReference) (subscriptions.Profile, error)) (CompiledNetworkPlan, error) {
	bad := func() (CompiledNetworkPlan, error) { return CompiledNetworkPlan{}, ErrInvalid }
	if plan.Adaptive == nil || len(plan.Graph.Profiles) > 32 || plan.Network.RouteFailover != nil {
		return bad()
	}
	for _, group := range plan.Graph.Balancers {
		if group.Type == "urltest" {
			return bad()
		}
	}
	decoded, err := DecodeAdaptivePlan(*plan.Adaptive, plan.Graph)
	if err != nil {
		return bad()
	}
	declarations := make(map[string]adaptiveGroupDeclaration, len(decoded.groups))
	for group, tag := range decoded.groups {
		info, ok := decoded.graph.GroupInfo(group)
		if !ok || info.MaxHops < 1 || info.MaxHops > 4 {
			return bad()
		}
		tcp := false
		for _, feature := range info.Features {
			if feature == "UDP" || feature == "ICMP" {
				return bad()
			}
			tcp = tcp || feature == "TCP"
		}
		if !tcp {
			return bad()
		}
		var checks *OutboundCheckPlan
		for i := range plan.Network.RouteChecks {
			if plan.Network.RouteChecks[i].Outbound == tag {
				if checks != nil {
					return bad()
				}
				checks = &plan.Network.RouteChecks[i]
			}
		}
		if checks == nil || len(checks.Checks) < 1 || len(checks.Checks) > 4 {
			return bad()
		}
		country := false
		for _, check := range checks.Checks {
			if !outboundCheckTarget(check) {
				return bad()
			}
			if check.Method == "https_exit_country" {
				if info.Intent == "INTERNAL" || check.ExpectedExitClass != info.Intent {
					return bad()
				}
				country = true
			}
		}
		if info.Intent != "INTERNAL" && !country {
			return bad()
		}
		declarations[group] = adaptiveGroupDeclaration{Tag: tag, MaxHops: info.MaxHops}
	}
	allowed := make(map[ProfileReference]bool, len(decoded.bindings)+len(plan.Graph.Profiles))
	for _, ref := range decoded.bindings {
		allowed[ref] = true
	}
	for _, ref := range plan.Graph.Profiles {
		allowed[ref] = true
	}
	if len(allowed) > 532 {
		return bad()
	}
	cache := make(map[ProfileReference]subscriptions.Profile, len(allowed))
	ownedResolve := func(ref ProfileReference) (subscriptions.Profile, error) {
		if err := ctx.Err(); err != nil {
			return subscriptions.Profile{}, err
		}
		if !allowed[ref] {
			return subscriptions.Profile{}, ErrInvalid
		}
		profile, found := cache[ref]
		if !found {
			if len(cache) >= 532 {
				return subscriptions.Profile{}, ErrInvalid
			}
			var err error
			profile, err = resolve(ref)
			if cancelled := ctx.Err(); cancelled != nil {
				return subscriptions.Profile{}, cancelled
			}
			if err != nil {
				return subscriptions.Profile{}, err
			}
			if len(profile.Outbound) < 1 || len(profile.Outbound) > 262144 {
				return subscriptions.Profile{}, ErrInvalid
			}
			profile.Outbound = append(json.RawMessage(nil), profile.Outbound...)
			cache[ref] = profile
		}
		profile.Outbound = append(json.RawMessage(nil), profile.Outbound...)
		return profile, nil
	}
	snapshot, err := CompileAdaptiveSnapshot(ctx, decoded.metadata, decoded.bindings, ownedResolve)
	if err != nil {
		return CompiledNetworkPlan{}, err
	}
	catalogue := make(map[string]any, len(decoded.bindings))
	catalogueFeatures := map[string]bool{}
	ids := make([]string, 0, len(decoded.bindings))
	for hop := range decoded.bindings {
		ids = append(ids, hop)
	}
	sort.Strings(ids)
	for _, hop := range ids {
		if err := ctx.Err(); err != nil {
			return CompiledNetworkPlan{}, err
		}
		profile, err := snapshot.Profile(hop)
		if err != nil {
			return bad()
		}
		node, err := adaptiveCompiledNode(hop, profile.Outbound)
		if err != nil {
			return bad()
		}
		if !graphProfile(node, catalogueFeatures).TCP {
			return bad()
		}
		catalogue[hop] = node
	}
	graphValue, err := subscriptions.DecodeJSON(decoded.metadata)
	if err != nil {
		return bad()
	}
	metadata, err := json.Marshal(graphValue)
	if err != nil {
		return bad()
	}
	catalogueRaw, err := json.Marshal(catalogue)
	if err != nil {
		return bad()
	}
	groupValues := make(map[string]any, len(decoded.groups))
	for group, tag := range decoded.groups {
		groupValues[group] = tag
	}
	wire := map[string]any{"schemaVersion": json.Number("1"), "graphB64": base64.RawURLEncoding.EncodeToString(metadata), "catalogueB64": base64.RawURLEncoding.EncodeToString(catalogueRaw), "groups": groupValues}
	wireRaw, err := json.Marshal(wire)
	if err != nil || len(wireRaw) > MaxAdaptivePlanBytes {
		return bad()
	}
	remaining := 32768
	if !adaptiveWireTokens(wire, &remaining, 0, 4, 256, false) || !adaptiveWireTokens(catalogue, &remaining, 0, 500, 256, false) || !adaptiveWireTokens(graphValue, &remaining, 0, 128, 4096, true) {
		return bad()
	}
	graph, err := compileGraphWithAdaptive(plan.Graph, ownedResolve, declarations)
	if err != nil {
		return CompiledNetworkPlan{}, err
	}
	for _, feature := range graph.RequiredEngineFeatures {
		catalogueFeatures[feature] = true
	}
	engineFeatures := make([]string, 0, len(catalogueFeatures))
	for feature := range catalogueFeatures {
		engineFeatures = append(engineFeatures, feature)
	}
	sort.Strings(engineFeatures)
	network, err := CompileNetwork(graph, plan.Network)
	if err != nil {
		return CompiledNetworkPlan{}, err
	}
	var output map[string]json.RawMessage
	if json.Unmarshal(network, &output) != nil {
		return bad()
	}
	output["adaptive_routes"] = wireRaw
	network, err = json.Marshal(output)
	if err != nil || len(network) < 1 || len(network) > 262144 {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return CompiledNetworkPlan{}, err
	}
	hash := sha256.Sum256(network)
	return CompiledNetworkPlan{EngineConfig: append(json.RawMessage(nil), network...), ContentHash: hex.EncodeToString(hash[:]), Activation: plan.Activation,
		RequiredEngineFeatures: engineFeatures, AlgorithmRevision: AdaptiveTCPAlgorithm}, nil
}
