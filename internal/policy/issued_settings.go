package policy

import (
	"encoding/base64"
	"encoding/json"
)

// IssuedSettings is the credential-free view stored with a signed publication.
// Fields are projected explicitly; arbitrary engine JSON, endpoints and check
// targets must never enter the administrative inventory response.
type IssuedSettings struct {
	Revision          int64            `json:"revision"`
	AlgorithmRevision string           `json:"algorithmRevision"`
	OfflineUntilMs    int64            `json:"offlineUntilMs"`
	Outbounds         []IssuedOutbound `json:"outbounds"`
	RouteFinal        string           `json:"routeFinal,omitempty"`
	RouteRuleCount    int              `json:"routeRuleCount"`
	DNSFinal          string           `json:"dnsFinal,omitempty"`
	Activation        IssuedActivation `json:"activation"`
}

type IssuedOutbound struct {
	Type    string   `json:"type"`
	Tag     string   `json:"tag"`
	Detour  string   `json:"detour,omitempty"`
	Members []string `json:"outbounds,omitempty"`
	Default string   `json:"default,omitempty"`
}

type IssuedActivation struct {
	TimeoutSeconds int           `json:"timeoutSeconds"`
	AllowDegraded  bool          `json:"allowDegraded"`
	Checks         []IssuedCheck `json:"checks"`
}

type IssuedCheck struct {
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// ConsoleSettings projects an already validated signed payload without
// exposing the envelope or widening access to its encryption key.
func (p Payload) ConsoleSettings() *IssuedSettings {
	if p.Operation != "configure" {
		return nil
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(p.EngineConfigB64)
	if err != nil {
		return nil
	}
	var engine struct {
		Outbounds []IssuedOutbound `json:"outbounds"`
		Route     struct {
			Final string            `json:"final"`
			Rules []json.RawMessage `json:"rules"`
		} `json:"route"`
		DNS struct {
			Final string `json:"final"`
		} `json:"dns"`
	}
	if json.Unmarshal(raw, &engine) != nil || len(engine.Outbounds) == 0 || len(engine.Outbounds) > 256 {
		return nil
	}
	view := &IssuedSettings{
		Revision: p.Revision, AlgorithmRevision: p.AlgorithmRevision, OfflineUntilMs: p.OfflineUntilMs,
		Outbounds:  make([]IssuedOutbound, 0, len(engine.Outbounds)),
		RouteFinal: issuedTag(engine.Route.Final), RouteRuleCount: len(engine.Route.Rules),
		DNSFinal:   issuedTag(engine.DNS.Final),
		Activation: IssuedActivation{TimeoutSeconds: p.Activation.TimeoutSeconds, AllowDegraded: p.Activation.AllowDegraded},
	}
	for _, outbound := range engine.Outbounds {
		switch outbound.Type {
		case "direct", "block", "http", "socks", "ssh", "vless", "netbird", "selector", "urltest", "dns":
		default:
			continue
		}
		if outbound.Tag = issuedTag(outbound.Tag); outbound.Tag == "" {
			continue
		}
		outbound.Detour = issuedTag(outbound.Detour)
		outbound.Default = issuedTag(outbound.Default)
		members := make([]string, 0, len(outbound.Members))
		for _, member := range outbound.Members {
			if tag := issuedTag(member); tag != "" {
				members = append(members, tag)
			}
		}
		outbound.Members = members
		view.Outbounds = append(view.Outbounds, outbound)
	}
	if len(view.Outbounds) == 0 {
		return nil
	}
	for _, check := range p.Activation.Checks {
		view.Activation.Checks = append(view.Activation.Checks, IssuedCheck{Type: check.Type, Required: check.Required})
	}
	return view
}

func issuedTag(value string) string {
	if identifier.MatchString(value) {
		return value
	}
	return ""
}
