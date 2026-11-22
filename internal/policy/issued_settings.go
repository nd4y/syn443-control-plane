package policy

import (
	"encoding/base64"
	"encoding/json"
)

// IssuedSettings is the credential-free view stored with a signed publication.
// Fields are projected explicitly; arbitrary engine JSON, endpoints and check
// targets must never enter the administrative inventory response.
type IssuedSettings struct {
	Revision                int64            `json:"revision"`
	AlgorithmRevision       string           `json:"algorithmRevision"`
	DecisionProgramRevision int64            `json:"decisionProgramRevision,omitempty"`
	OfflineUntilMs          int64            `json:"offlineUntilMs"`
	Outbounds               []IssuedOutbound `json:"outbounds"`
	NetBird                 *IssuedOverlay   `json:"netbird,omitempty"`
	RouteFinal              string           `json:"routeFinal,omitempty"`
	RouteRuleCount          int              `json:"routeRuleCount"`
	DNSFinal                string           `json:"dnsFinal,omitempty"`
	Activation              IssuedActivation `json:"activation"`
}

// IssuedOverlay describes only the transport and namespace in a signed policy.
// Peer paths, connection state and provider credentials are not inventory data.
type IssuedOverlay struct {
	Tag        string `json:"tag"`
	Transport  string `json:"transport"`
	OverlayID  string `json:"overlayId,omitempty"`
	ResourceID string `json:"resourceId,omitempty"`
	NetworkID  string `json:"networkId,omitempty"`
}

type issuedEngineOutbound struct {
	IssuedOutbound
	ConnectionMode json.RawMessage `json:"connection_mode"`
	Managed        json.RawMessage `json:"managed"`
}

func (e issuedEngineOutbound) netBirdSettings() *IssuedOverlay {
	var mode string
	if json.Unmarshal(e.ConnectionMode, &mode) != nil || issuedTag(e.Tag) == "" {
		return nil
	}
	switch mode {
	case "direct":
		if e.Detour != "" {
			return nil
		}
	case "vless":
		if issuedTag(e.Detour) == "" || e.Detour == e.Tag {
			return nil
		}
	default:
		return nil
	}
	view := &IssuedOverlay{Tag: e.Tag, Transport: mode}
	if len(e.Managed) > 0 {
		var m struct {
			OverlayID  string `json:"overlayId"`
			ResourceID string `json:"resourceId"`
			NetworkID  string `json:"networkId"`
		}
		if json.Unmarshal(e.Managed, &m) != nil || issuedTag(m.OverlayID) == "" ||
			issuedTag(m.ResourceID) == "" || issuedTag(m.NetworkID) == "" {
			return nil
		}
		view.OverlayID, view.ResourceID, view.NetworkID = m.OverlayID, m.ResourceID, m.NetworkID
	}
	return view
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
		Outbounds []issuedEngineOutbound `json:"outbounds"`
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
	seenOverlay := false
	for _, node := range engine.Outbounds {
		outbound := node.IssuedOutbound
		if outbound.Type == "netbird" {
			if seenOverlay {
				view.NetBird = nil
			} else {
				view.NetBird = node.netBirdSettings()
			}
			seenOverlay = true
		}
		switch outbound.Type {
		case "direct", "block", "http", "socks", "ssh", "vless", "netbird", "selector", "urltest", "dns", "syn443-adaptive":
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
