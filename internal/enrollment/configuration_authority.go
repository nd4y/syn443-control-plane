package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/routecheck"
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
	AlgorithmRevision    string
	UntilMs              int64
	Fence                ApprovalFence
	Source               ConfigurationSource
}

// ConfigurationSource identifies the approved desired snapshot that the
// publisher's final fence rechecks. A zero value leaves the origin unlinked.
type ConfigurationSource struct {
	Revision int64
	Hash     string
}

func (s ConfigurationSource) valid() bool {
	if s.Revision == 0 {
		return s.Hash == ""
	}
	if s.Revision < 0 || s.Revision > 9007199254740991 || len(s.Hash) != 64 || strings.ToLower(s.Hash) != s.Hash {
		return false
	}
	_, err := hex.DecodeString(s.Hash)
	return err == nil
}

func (ConfigurationTarget) String() string     { return "ConfigurationTarget([redacted])" }
func (ConfigurationTarget) GoString() string   { return "ConfigurationTarget([redacted])" }
func (PreparedConfiguration) String() string   { return "PreparedConfiguration([redacted])" }
func (PreparedConfiguration) GoString() string { return "PreparedConfiguration([redacted])" }

type ConfigurationAuthority interface {
	Prepare(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error)
}

// No setting may change the audience, device, key, revision or grant lifetime.
// The only algorithm change is an approved, locally supported preset.
func applyPreparedConfiguration(payload *policy.Payload, prepared *PreparedConfiguration, capabilities []string, now time.Time) error {
	if payload == nil || prepared == nil || prepared.Fence == nil || prepared.UntilMs <= now.UnixMilli() || len(prepared.EngineConfig) < 1 || len(prepared.EngineConfig) > 262144 || len(prepared.RequiredCapabilities) > 16 || !prepared.Source.valid() {
		return ErrDenied
	}
	raw := append([]byte(nil), prepared.EngineConfig...)
	if validatePreparedNetwork(raw) != nil || configuration.ValidateIssuedCheckPlans(raw) != nil {
		return identity.ErrInvalid
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return identity.ErrInvalid
	}
	hasProfile := false
	if checks, present := root["route_checks"]; present {
		plans, e := routecheck.DecodePlans(checks)
		if e != nil {
			return identity.ErrInvalid
		}
		for _, plan := range plans {
			hasProfile = hasProfile || plan.Profile != nil
		}
	}
	if hasProfile != slices.Contains(prepared.RequiredCapabilities, policy.RouteCheckPlanV2) {
		return ErrDenied
	}
	_, modeSelection := root["network_mode"]
	if modeSelection != slices.Contains(prepared.RequiredCapabilities, policy.NetworkModeSelection) {
		return ErrDenied
	}
	_, homeProof := root["home_proof"]
	if homeProof != slices.Contains(prepared.RequiredCapabilities, policy.HomeWiFiProof) {
		return ErrDenied
	}
	_, adaptive := root["adaptive_routes"]
	if adaptive != (prepared.AlgorithmRevision == policy.AdaptiveTCPAlgorithm) || adaptive != slices.Contains(prepared.RequiredCapabilities, policy.RouteAdaptiveTCP) {
		return ErrDenied
	}
	// A rejected callback must not leave partial algorithm/engine/capability
	// changes in the caller's owned candidate or its grant-backed slices.
	candidate := *payload
	candidate.RequiredCapabilities = append([]string(nil), payload.RequiredCapabilities...)
	if prepared.AlgorithmRevision != "" {
		if prepared.AlgorithmRevision != policy.ConfirmedFailoverAlgorithm && prepared.AlgorithmRevision != policy.AdaptiveTCPAlgorithm || !slices.Contains(prepared.RequiredCapabilities, policy.RouteDecision) {
			return ErrDenied
		}
		candidate.AlgorithmRevision = prepared.AlgorithmRevision
	}
	candidate.EngineConfigB64 = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	candidate.ContentHash = hex.EncodeToString(sum[:])
	candidate.Activation = prepared.Activation
	candidate.Activation.Checks = append([]policy.Check(nil), prepared.Activation.Checks...)
	candidate.OfflineUntilMs = min(payload.OfflineUntilMs, prepared.UntilMs)
	candidate.RefreshAfterMs = min(payload.RefreshAfterMs, candidate.OfflineUntilMs-1000)
	available := map[string]bool{}
	for _, value := range capabilities {
		available[value] = true
	}
	seen := map[string]bool{}
	for _, value := range candidate.RequiredCapabilities {
		seen[value] = true
	}
	extras := map[string]bool{}
	for _, value := range prepared.RequiredCapabilities {
		if !available[value] || extras[value] {
			return ErrDenied
		}
		extras[value] = true
		if !seen[value] {
			candidate.RequiredCapabilities = append(candidate.RequiredCapabilities, value)
			seen[value] = true
		}
	}
	if err := candidate.Validate(now); err != nil {
		return err
	}
	*payload = candidate
	return nil
}

func validatePreparedNetwork(raw []byte) error {
	var root map[string]json.RawMessage
	if identity.DecodeConfiguration(raw, &root) != nil || root == nil {
		return identity.ErrInvalid
	}
	_, adaptive := root["adaptive_routes"]
	for name := range root {
		switch name {
		case "outbounds", "route", "dns", "route_checks", "route_failover", "adaptive_routes":
		case "home_proof", "network_mode":
			if !adaptive {
				return identity.ErrInvalid
			}
		default:
			return identity.ErrInvalid
		}
	}
	if adaptive && configuration.ValidateAdaptiveIssuedEngine(raw) != nil {
		return identity.ErrInvalid
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
		case "syn443-adaptive":
			var group string
			if !adaptive || len(node) != 3 || json.Unmarshal(node["group"], &group) != nil || group == "" {
				return identity.ErrInvalid
			}
		case "netbird":
			for _, field := range []string{"setup_key", "state_directory", "managed_namespace", "credential_pending", "recover_existing"} {
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
