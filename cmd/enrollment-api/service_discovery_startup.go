package main

import (
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// The optional public-metadata module must be completely admitted before
// ordinary enrollment startup can read its DB, IdP or credentials. It starts no
// listener itself; the validated module wraps the existing API handler.
func withServiceDiscoveryStartup(getenv func(string) string, readFile func(string, int64) ([]byte, error),
	clock func() time.Time, start func(*bootstrap.ServiceDiscovery) error) error {
	if getenv == nil || readFile == nil || clock == nil || start == nil {
		return identity.ErrInvalid
	}
	path := getenv("SYN443_SERVICE_DESCRIPTOR_CONFIG")
	if path == "" {
		return start(nil)
	}
	raw, err := readFile(path, bootstrap.ServiceDiscoveryConfigLimit)
	if err != nil {
		return identity.ErrInvalid
	}
	discovery, err := bootstrap.ParseServiceDiscovery(raw, clock)
	if err != nil {
		return identity.ErrInvalid
	}
	return start(discovery)
}
