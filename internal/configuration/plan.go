package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

// NetworkPlan is the versioned portable input for currently supported proxy,
// DNS/routing and activation settings. It is not raw native JSON, publication
// authority, application settings, or an executable routing algorithm.
type NetworkPlan struct {
	SchemaVersion int             `json:"schemaVersion"`
	Graph         Graph           `json:"graph"`
	Network       NetworkSettings `json:"network"`
	Activation    policy.Gate     `json:"activation"`
	Adaptive      *AdaptivePlan   `json:"adaptive,omitempty"`
}

type CompiledNetworkPlan struct {
	EngineConfig           json.RawMessage
	ContentHash            string
	Activation             policy.Gate
	RequiredEngineFeatures []string
	AlgorithmRevision      string
}

func (NetworkPlan) String() string           { return "NetworkPlan([redacted])" }
func (NetworkPlan) GoString() string         { return "NetworkPlan([redacted])" }
func (CompiledNetworkPlan) String() string   { return "CompiledNetworkPlan([redacted])" }
func (CompiledNetworkPlan) GoString() string { return "CompiledNetworkPlan([redacted])" }

func DecodeNetworkPlan(raw []byte) (NetworkPlan, error) {
	var plan NetworkPlan
	if len(raw) < 1 || len(raw) > 262144 || identity.DecodeConfiguration(raw, &plan) != nil || plan.SchemaVersion != 1 || plan.Activation.Validate() != nil {
		return NetworkPlan{}, ErrInvalid
	}
	value, e := subscriptions.DecodeJSON(raw)
	if e != nil || !boundedNumbers(value) {
		return NetworkPlan{}, ErrInvalid
	}
	// Preserve method-specific member presence before an omitempty roundtrip
	// could discard an explicit empty foreign predicate in nested settings.
	root, ok := value.(map[string]any)
	if !ok {
		return NetworkPlan{}, ErrInvalid
	}
	networkRaw, e := json.Marshal(root["network"])
	if e != nil {
		return NetworkPlan{}, ErrInvalid
	}
	if _, e = DecodeNetworkSettings(networkRaw); e != nil {
		return NetworkPlan{}, ErrInvalid
	}
	if plan.Adaptive != nil {
		if _, e := DecodeAdaptivePlan(*plan.Adaptive, plan.Graph); e != nil {
			return NetworkPlan{}, ErrInvalid
		}
	}
	return plan, nil
}

// CompileNetworkPlan resolves only references from the caller's independently
// authorized source selection. Neither this function nor its resolver may fetch
// networks or sign. The publisher still needs actual target/capability checks and
// both initial and final source/layer/recipient/approval SQL fences.
func CompileNetworkPlan(ctx context.Context, plan NetworkPlan, resolve func(ProfileReference) (subscriptions.Profile, error)) (CompiledNetworkPlan, error) {
	if ctx == nil || resolve == nil {
		return CompiledNetworkPlan{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return CompiledNetworkPlan{}, e
	}
	// Own all maps/slices and apply the same closed, bounded decode to direct Go
	// callers. Later caller mutation cannot alter activation or compiled bytes.
	raw, e := json.Marshal(plan)
	if e != nil {
		return CompiledNetworkPlan{}, ErrInvalid
	}
	owned, e := DecodeNetworkPlan(raw)
	if e != nil {
		return CompiledNetworkPlan{}, e
	}
	if owned.Adaptive != nil {
		return compileAdaptiveNetworkPlan(ctx, owned, resolve)
	}
	graph, e := CompileGraph(owned.Graph, func(ref ProfileReference) (subscriptions.Profile, error) {
		if e := ctx.Err(); e != nil {
			return subscriptions.Profile{}, e
		}
		profile, err := resolve(ref)
		if e := ctx.Err(); e != nil {
			return subscriptions.Profile{}, e
		}
		return profile, err
	})
	if e != nil {
		return CompiledNetworkPlan{}, e
	}
	network, e := CompileNetwork(graph, owned.Network)
	if e != nil {
		return CompiledNetworkPlan{}, e
	}
	if e := ctx.Err(); e != nil {
		return CompiledNetworkPlan{}, e
	}
	if len(network) < 1 || len(network) > 262144 {
		return CompiledNetworkPlan{}, ErrInvalid
	}
	hash := sha256.Sum256(network)
	return CompiledNetworkPlan{EngineConfig: append(json.RawMessage(nil), network...), ContentHash: hex.EncodeToString(hash[:]),
		Activation: owned.Activation, RequiredEngineFeatures: append([]string{}, graph.RequiredEngineFeatures...)}, nil
}
