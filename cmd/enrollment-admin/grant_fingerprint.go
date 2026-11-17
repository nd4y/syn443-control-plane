package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const grantFingerprintInputLimit = 524288
const grantFingerprintOutputLimit = 16384

type grantFingerprintRow struct {
	Owner       string `json:"owner"`
	Enabled     bool   `json:"enabled"`
	DeviceLimit int    `json:"deviceLimit"`
	ValidUntil  int64  `json:"validUntil"`
	GrantHash   string `json:"grantHash"`
}

type grantFingerprintDocument struct {
	Version int                   `json:"version"`
	Grants  []grantFingerprintRow `json:"grants"`
}

// This command has no configuration, environment, database or network input.
// Validation is all-or-nothing before the single bounded metadata write. An OS
// write failure may leave partial stdout; any error makes that output unusable.
func fingerprintGrants(input io.Reader, output io.Writer, clock func() time.Time) error {
	if input == nil || output == nil || clock == nil {
		return identity.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(input, grantFingerprintInputLimit+1))
	defer clear(raw)
	if err != nil || len(raw) == 0 || len(raw) > grantFingerprintInputLimit {
		return identity.ErrInvalid
	}
	var grants []enrollment.Grant
	if identity.DecodeOperatorDocument(raw, &grants) != nil || len(grants) < 1 || len(grants) > 16 {
		return identity.ErrInvalid
	}
	// Read the live clock after the complete stdin snapshot, never before a
	// potentially blocked read. The native validator and hash stay authoritative.
	now := clock()
	owners := make(map[string]bool, len(grants))
	document := grantFingerprintDocument{Version: 1, Grants: make([]grantFingerprintRow, 0, len(grants))}
	for _, grant := range grants {
		if grant.Validate(now) != nil {
			return identity.ErrInvalid
		}
		owner := enrollment.Owner(grant.Issuer, grant.Subject)
		if owners[owner] {
			return identity.ErrInvalid
		}
		owners[owner] = true
		document.Grants = append(document.Grants, grantFingerprintRow{
			Owner: owner, Enabled: true, DeviceLimit: grant.DeviceLimit,
			ValidUntil: grant.Until, GrantHash: grant.Hash(),
		})
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded)+1 > grantFingerprintOutputLimit {
		return identity.ErrInvalid
	}
	encoded = append(encoded, '\n')
	n, err := output.Write(encoded)
	if err != nil || n != len(encoded) {
		return identity.ErrInvalid
	}
	return nil
}
