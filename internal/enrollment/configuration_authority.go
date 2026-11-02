package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

// ConfigurationAuthority is installed only in the independent publisher. The
// device, owner, key and grant below come from its actual authenticated device
// row; a control-API callback cannot supply or replace this publication target.
type ConfigurationTarget struct {
	Device, Owner, Thumbprint, GrantHash string
	CurrentRevision                      int64
	Capabilities                         []string
}
type PreparedConfiguration struct {
	EngineConfig         json.RawMessage
	Activation           policy.Gate
	RequiredCapabilities []string
	UntilMs              int64
	Fence                ApprovalFence
}

func (ConfigurationTarget) String() string     { return "ConfigurationTarget([redacted])" }
func (ConfigurationTarget) GoString() string   { return "ConfigurationTarget([redacted])" }
func (PreparedConfiguration) String() string   { return "PreparedConfiguration([redacted])" }
func (PreparedConfiguration) GoString() string { return "PreparedConfiguration([redacted])" }

type ConfigurationAuthority interface {
	Prepare(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error)
}

// No setting may change the audience/device/key/revision/algorithm or grant
// lifetime. A missing/invalid authority result never falls back to a template.
func applyPreparedConfiguration(payload *policy.Payload, prepared *PreparedConfiguration, capabilities []string, now time.Time) error {
	if prepared == nil || prepared.Fence == nil || prepared.UntilMs <= now.UnixMilli() || len(prepared.EngineConfig) < 1 || len(prepared.EngineConfig) > 262144 || len(prepared.RequiredCapabilities) > 16 {
		return ErrDenied
	}
	raw := append([]byte(nil), prepared.EngineConfig...)
	if validatePreparedNetwork(raw) != nil {
		return identity.ErrInvalid
	}
	payload.EngineConfigB64 = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	payload.ContentHash = hex.EncodeToString(sum[:])
	payload.Activation = prepared.Activation
	payload.Activation.Checks = append([]policy.Check(nil), prepared.Activation.Checks...)
	payload.OfflineUntilMs = min(payload.OfflineUntilMs, prepared.UntilMs)
	payload.RefreshAfterMs = min(payload.RefreshAfterMs, payload.OfflineUntilMs-1000)
	available := map[string]bool{}
	for _, value := range capabilities {
		available[value] = true
	}
	seen := map[string]bool{}
	for _, value := range payload.RequiredCapabilities {
		seen[value] = true
	}
	extras := map[string]bool{}
	for _, value := range prepared.RequiredCapabilities {
		if !available[value] || extras[value] {
			return ErrDenied
		}
		extras[value] = true
		if !seen[value] {
			payload.RequiredCapabilities = append(payload.RequiredCapabilities, value)
			seen[value] = true
		}
	}
	return payload.Validate(now)
}

func validatePreparedNetwork(raw []byte) error {
	var root map[string]json.RawMessage
	if identity.DecodeConfiguration(raw, &root) != nil || root == nil {
		return identity.ErrInvalid
	}
	for name := range root {
		if name != "outbounds" && name != "route" && name != "dns" && name != "route_checks" {
			return identity.ErrInvalid
		}
	}
	var outbounds []map[string]json.RawMessage
	if json.Unmarshal(root["outbounds"], &outbounds) != nil || len(outbounds) < 1 || len(outbounds) > 64 {
		return identity.ErrInvalid
	}
	tags := map[string]bool{}
	for _, node := range outbounds {
		var tag, kind string
		if json.Unmarshal(node["tag"], &tag) != nil || len(tag) < 1 || len(tag) > 256 || tags[tag] || json.Unmarshal(node["type"], &kind) != nil {
			return identity.ErrInvalid
		}
		switch kind {
		case "direct", "http", "socks", "vless", "ssh", "selector", "urltest":
		case "netbird":
			for _, field := range []string{"setup_key", "state_directory", "managed_namespace"} {
				if _, ok := node[field]; ok {
					return identity.ErrInvalid
				}
			}
		default:
			return identity.ErrInvalid
		}
		tags[tag] = true
	}
	var route struct {
		Final string `json:"final"`
	}
	if json.Unmarshal(root["route"], &route) != nil || !tags[route.Final] {
		return identity.ErrInvalid
	}
	return nil
}
