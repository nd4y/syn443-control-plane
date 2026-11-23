package configuration

import (
	"context"

	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type LayerBundle struct {
	Device       string  `json:"device"`
	BaseRevision int64   `json:"baseRevision"`
	BaseHash     string  `json:"baseHash"`
	Layers       []Layer `json:"layers"`
}

func (LayerBundle) String() string   { return "ConfigurationLayerBundle([redacted])" }
func (LayerBundle) GoString() string { return "ConfigurationLayerBundle([redacted])" }

func effectiveDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func EffectiveNetworkPlanHash(ctx context.Context, bundles []LayerBundle) (string, error) {
	return inspectEffectivePlans(ctx, bundles, nil)
}

func inspectEffectivePlans(ctx context.Context, bundles []LayerBundle, inspect func(string, NetworkPlan)) (string, error) {
	if ctx == nil || len(bundles) < 1 || len(bundles) > 64 {
		return "", ErrInvalid
	}
	type value struct{ Device, Hash string }
	values := make([]value, 0, len(bundles))
	seen := map[string]bool{}
	for _, bundle := range bundles {
		if bundle.Device == "" || seen[bundle.Device] {
			return "", ErrInvalid
		}
		seen[bundle.Device] = true
		effective, plan, err := MergeNetworkPlan(ctx, bundle.Layers)
		if err != nil {
			return "", err
		}
		values = append(values, value{bundle.Device, effectiveDigest(effective.Document)})
		if inspect != nil {
			inspect(bundle.Device, plan)
		}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return effectiveDigest(raw), nil
}

// GroupNetworkImpact contains categories only. It is derived from the effective
// documents presented by the caller. It cannot grant access to any resource.
type GroupNetworkImpact struct {
	Device     string `json:"device"`
	NetBird    bool   `json:"netbird"`
	OverlayDNS bool   `json:"overlayDns"`
	HomeProof  bool   `json:"homeProof"`
}

// ReviewGroupNetworkImpact compares the review to the effective hash from the
// user's current signed preview. It never fetches a source or takes a DB lock.
func ReviewGroupNetworkImpact(ctx context.Context, bundles []LayerBundle, expected string) ([]GroupNetworkImpact, error) {
	if !previewDigest.MatchString(expected) || len(bundles) > 64 {
		return nil, ErrInvalid
	}
	for _, bundle := range bundles {
		if !id.MatchString(bundle.Device) {
			return nil, ErrInvalid
		}
	}
	var impacts []GroupNetworkImpact
	digest, err := inspectEffectivePlans(ctx, bundles, func(device string, plan NetworkPlan) {
		impact := GroupNetworkImpact{Device: device, NetBird: plan.Graph.NetBird != nil, HomeProof: plan.Network.HomeProof != nil}
		for _, server := range plan.Network.DNSServers {
			if server.Transport == "netbird" {
				impact.OverlayDNS = true
				break
			}
		}
		impacts = append(impacts, impact)
	})
	if err != nil || digest != expected {
		return nil, ErrInvalid
	}
	return impacts, nil
}
