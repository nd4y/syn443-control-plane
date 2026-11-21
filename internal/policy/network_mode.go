package policy

import "github.com/nd4y/syn443-control-plane/internal/identity"

const NetworkModeSelection = "network.mode-selection.v1"

// A preference selects among admissible routes on the observed transport.
// It never supplies the physical Wi-Fi proof or a new egress permission.
type NetworkModePolicy struct {
	PreferredMode      string   `json:"preferredMode"`
	UserModes          []string `json:"userModes"`
	MaxOverrideMinutes int      `json:"maxOverrideMinutes"`
}

func (p NetworkModePolicy) Valid(hasHomeProof bool) bool {
	validMode := func(mode string) bool {
		switch mode {
		case "HOME_WIFI":
			return hasHomeProof
		case "WIFI", "CELLULAR", "CELLULAR_RESTRICTED":
			return true
		default:
			return false
		}
	}
	if p.PreferredMode != "AUTO" && !validMode(p.PreferredMode) || p.UserModes == nil || len(p.UserModes) > 4 {
		return false
	}
	if len(p.UserModes) == 0 {
		return p.MaxOverrideMinutes == 0
	}
	if p.MaxOverrideMinutes < 1 || p.MaxOverrideMinutes > 1440 {
		return false
	}
	seen := make(map[string]bool, len(p.UserModes))
	for _, mode := range p.UserModes {
		if !validMode(mode) || seen[mode] {
			return false
		}
		seen[mode] = true
	}
	return true
}

func (p *NetworkModePolicy) UnmarshalJSON(raw []byte) error {
	type wire NetworkModePolicy
	var value wire
	var fields map[string]any
	if identity.DecodeConfiguration(raw, &fields) != nil || len(fields) != 3 ||
		fields["preferredMode"] == nil || fields["userModes"] == nil || fields["maxOverrideMinutes"] == nil ||
		identity.DecodeConfiguration(raw, &value) != nil || !NetworkModePolicy(value).Valid(true) {
		return identity.ErrInvalid
	}
	*p = NetworkModePolicy(value)
	return nil
}

func ValidNetworkModeJSON(raw []byte, hasHomeProof bool) bool {
	var value NetworkModePolicy
	return identity.DecodeConfiguration(raw, &value) == nil && value.Valid(hasHomeProof)
}
