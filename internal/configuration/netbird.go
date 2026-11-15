package configuration

import (
	"encoding/json"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/overlay"
)

// NetBirdNode names an administratively assigned resource, never credentials or
// SDK state. The independent broker still validates the live account/resource
// grants and replaces its own addressed reference before signing a policy.
// Direct describes the underlay; peer P2P/relay choice remains SDK fallback.
type NetBirdNode struct {
	Tag           string `json:"tag"`
	OverlayID     string `json:"overlayId"`
	ResourceID    string `json:"resourceId"`
	NetworkID     string `json:"networkId"`
	IdentityEpoch int64  `json:"identityEpoch"`
	ManagementURL string `json:"managementUrl"`
	Hostname      string `json:"hostname,omitempty"`
	Mode          string `json:"mode"`
	Detour        string `json:"detour,omitempty"`
}

func (NetBirdNode) String() string   { return "ConfigurationNetBird([redacted])" }
func (NetBirdNode) GoString() string { return "ConfigurationNetBird([redacted])" }

func (n NetBirdNode) validate() error {
	origin, e := overlay.ManagementOrigin(n.ManagementURL)
	if e != nil || origin != n.ManagementURL || !graphTag(n.Tag) || !id.MatchString(n.OverlayID) || !id.MatchString(n.ResourceID) || !id.MatchString(n.NetworkID) || n.IdentityEpoch < 1 || n.IdentityEpoch > 9007199254740991 {
		return ErrInvalid
	}
	if n.Hostname != "" && (len(n.Hostname) > 63 || strings.Contains(n.Hostname, ".") || !networkHost(n.Hostname, false)) {
		return ErrInvalid
	}
	if n.Mode != "direct" && n.Mode != "vless" || n.Mode == "direct" && n.Detour != "" || n.Mode == "vless" && (!graphTag(n.Detour) || n.Detour == n.Tag) {
		return ErrInvalid
	}
	return nil
}

func (n NetBirdNode) outbound() map[string]any {
	result := map[string]any{"type": "netbird", "tag": n.Tag, "connection_mode": n.Mode, "management_url": n.ManagementURL,
		"managed": map[string]any{"overlayId": n.OverlayID, "resourceId": n.ResourceID, "networkId": n.NetworkID, "identityEpoch": n.IdentityEpoch, "setupReference": "", "setupVersion": 0}}
	if n.Hostname != "" {
		result["hostname"] = n.Hostname
	}
	if n.Mode == "vless" {
		result["detour"] = n.Detour
	}
	return result
}

// Match the native adapter: every selectable branch of an emergency underlay
// must end at VLESS. A direct/HTTP/SSH branch or a cycle must never create an
// implicit physical escape. Inspect emitted nodes, including expanded chains.
func netbirdVLESSDetour(outbounds []json.RawMessage, tag string) error {
	nodes := map[string]map[string]json.RawMessage{}
	for _, raw := range outbounds {
		var node map[string]json.RawMessage
		var name string
		if json.Unmarshal(raw, &node) != nil || json.Unmarshal(node["tag"], &name) != nil {
			return ErrInvalid
		}
		nodes[name] = node
	}
	visiting, checked := map[string]bool{}, map[string]bool{}
	var visit func(string, int) error
	visit = func(name string, depth int) error {
		node, ok := nodes[name]
		var kind string
		if !ok || depth > 16 || visiting[name] || json.Unmarshal(node["type"], &kind) != nil {
			return ErrInvalid
		}
		if kind == "vless" || checked[name] {
			return nil
		}
		if kind != "selector" && kind != "urltest" {
			return ErrInvalid
		}
		var members []string
		if json.Unmarshal(node["outbounds"], &members) != nil || len(members) < 1 || len(members) > 16 {
			return ErrInvalid
		}
		visiting[name] = true
		for _, member := range members {
			if e := visit(member, depth+1); e != nil {
				return e
			}
		}
		delete(visiting, name)
		checked[name] = true
		return nil
	}
	return visit(tag, 0)
}
