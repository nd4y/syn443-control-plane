package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"slices"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

var capabilityName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var capabilityDeviceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// CapabilityState is availability, never an account grant or permission to
// publish. Version0 comes from the immutable independently approved enrollment.
type CapabilityState struct {
	Version      int64    `json:"version"`
	Hash         string   `json:"hash"`
	Capabilities []string `json:"capabilities"`
}

func (CapabilityState) String() string   { return "CapabilityState([redacted])" }
func (CapabilityState) GoString() string { return "CapabilityState([redacted])" }

func canonicalCapabilities(input []string) ([]string, []byte, error) {
	if len(input) < 3 || len(input) > 16 {
		return nil, nil, identity.ErrInvalid
	}
	caps := append([]string(nil), input...)
	slices.Sort(caps)
	for i, c := range caps {
		if !capabilityName.MatchString(c) || i > 0 && caps[i-1] == c {
			return nil, nil, identity.ErrInvalid
		}
	}
	for _, required := range []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"} {
		if !slices.Contains(caps, required) {
			return nil, nil, identity.ErrInvalid
		}
	}
	raw, e := json.Marshal(caps)
	return caps, raw, e
}

type CapabilityQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// EffectiveCapabilities reads only publisher-owned immutable availability
// history. Broken history cannot silently fall back to the enrollment set.
func EffectiveCapabilities(ctx context.Context, query CapabilityQuery, device string, original []string) (CapabilityState, error) {
	var result CapabilityState
	if ctx == nil || query == nil || !capabilityDeviceID.MatchString(device) {
		return result, identity.ErrInvalid
	}
	caps, raw, e := canonicalCapabilities(original)
	if e != nil {
		return result, ErrDenied
	}
	result = CapabilityState{Capabilities: caps, Hash: identity.Hash(raw)}
	var body []byte
	e = query.QueryRowContext(ctx, `SELECT h.revision,h.body_hash,v.capabilities FROM identity_capability_heads h LEFT JOIN identity_capability_versions v ON v.device=h.device AND v.revision=h.revision AND v.body_hash=h.body_hash WHERE h.device=$1`, device).Scan(&result.Version, &result.Hash, &body)
	if e == sql.ErrNoRows {
		return result, nil
	}
	if e != nil {
		return CapabilityState{}, ErrUnavailable
	}
	var approved []string
	if identity.Decode(body, &approved, true) != nil {
		return CapabilityState{}, ErrUnavailable
	}
	approved, canonical, e := canonicalCapabilities(approved)
	if e != nil || result.Version < 1 || result.Version > 13 || identity.Hash(body) != result.Hash || identity.Hash(canonical) != result.Hash || len(approved) < len(caps)+int(result.Version) {
		return CapabilityState{}, ErrUnavailable
	}
	for _, original := range caps {
		if !slices.Contains(approved, original) {
			return CapabilityState{}, ErrUnavailable
		}
	}
	result.Capabilities = approved
	return result, nil
}
