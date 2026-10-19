// Package contracts embeds the immutable normative M0 contract.
package contracts

import "embed"

// Files contains synthetic fixtures and the request schema.
//
//go:embed v1/*.json
var Files embed.FS
