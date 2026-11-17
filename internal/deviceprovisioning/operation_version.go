package deviceprovisioning

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// ConfigurationProtocol is nonsecret service eligibility only. An owner must
// explicitly declare version two after schema and every consumer are upgraded.
// This value cannot verify that deployment and grants no ACL, MFA or effect.
type ConfigurationProtocol struct {
	Version                     int `json:"version"`
	ConfigurationRequestVersion int `json:"configurationRequestVersion"`
}

func (ConfigurationProtocol) String() string   { return "ConfigurationProtocol([redacted])" }
func (ConfigurationProtocol) GoString() string { return "ConfigurationProtocol([redacted])" }

func declaredConfigurationRequestVersion(version int) (int, error) {
	switch version {
	case 0, 1:
		return 1, nil
	case 2:
		return 2, nil
	default:
		return 0, enrollment.ErrDenied
	}
}

// Only Dispatch admits this read: restricted runtime role, current control JWT
// and exact DPoP first. No object/account data, SQL mutation, compiler/provider
// call or fresh-MFA promotion occurs here. The original receipt deadline still
// covers blocking role/verifier admission before this pure read.
func (c *ConfigurationControl) protocolInformation(ctx context.Context, payload json.RawMessage, until int64, current func() time.Time) (ConfigurationProtocol, error) {
	var result ConfigurationProtocol
	if c == nil || ctx == nil || current == nil || ctx.Err() != nil || current().Unix() >= until {
		return result, enrollment.ErrDenied
	}
	if identity.DecodeConfiguration(payload, &struct{}{}) != nil {
		return result, enrollment.ErrDenied
	}
	version, e := declaredConfigurationRequestVersion(c.ConfigurationRequestVersion)
	if e != nil || ctx.Err() != nil || current().Unix() >= until {
		return result, enrollment.ErrDenied
	}
	return ConfigurationProtocol{Version: 1, ConfigurationRequestVersion: version}, nil
}
