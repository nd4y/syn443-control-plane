// Package resources defines server-side provider boundaries, not device protocols.
package resources

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

const Remnawave = "panel.remnawave"

type Instance struct {
	ResourceID    string `json:"resourceId"`
	ProviderType  string `json:"providerType"`
	APIVersion    string `json:"apiVersion"`
	Endpoint      string `json:"-"`
	CredentialRef string `json:"-"`
	Enabled       bool   `json:"enabled"`
}

func (Instance) String() string     { return "ResourceInstance([redacted])" }
func (i Instance) GoString() string { return i.String() }

var resourceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)

func (i Instance) Validate() error {
	if !resourceID.MatchString(i.ResourceID) || !i.Enabled || i.CredentialRef == "" {
		return Failure("invalid_resource", false)
	}
	if i.ProviderType != Remnawave || i.APIVersion != "3.4" {
		return Failure("adapter_not_implemented", false)
	}
	return nil
}

// A Binding comes from owner-authorized assignment state, never a device-supplied ID.
type Binding struct {
	ResourceID     string
	ExternalUserID string
}

type ObjectRef struct {
	ResourceID       string `json:"resourceId"`
	ExternalObjectID string `json:"externalObjectId"`
}

type Snapshot struct {
	Ref               ObjectRef `json:"ref"`
	ObservedAt        time.Time `json:"observedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	TrafficUsedBytes  uint64    `json:"trafficUsedBytes"`
	TrafficLimitBytes uint64    `json:"trafficLimitBytes"`
	Links             []string  `json:"links"`
}

func (Snapshot) String() string     { return "ResourceSnapshot([redacted])" }
func (s Snapshot) GoString() string { return s.String() }

type Adapter interface {
	ReadAssignment(context.Context, Binding) (Snapshot, error)
	Close()
}

// Validation intentionally does not enable multiple panels or planned provider types.
func ValidateRegistry(instances []Instance) error {
	n := 0
	seen := map[string]bool{}
	for _, i := range instances {
		if !resourceID.MatchString(i.ResourceID) || seen[i.ResourceID] {
			return Failure("invalid_resource", false)
		}
		seen[i.ResourceID] = true
		if !i.Enabled {
			continue
		}
		if err := i.Validate(); err != nil {
			return err
		}
		n++
	}
	if n != 1 {
		return Failure("single_resource_required", false)
	}
	return nil
}

type Error struct {
	Code      string
	Retryable bool
}

func (e *Error) Error() string                  { return e.Code }
func Failure(code string, retryable bool) error { return &Error{Code: code, Retryable: retryable} }
func (b Binding) String() string                { return "ResourceBinding([redacted])" }
func (b Binding) GoString() string              { return b.String() }

// Namespace never flattens identifiers from different resources into one key.
func (r ObjectRef) Namespace() string {
	return fmt.Sprintf("%d:%s%s", len(r.ResourceID), r.ResourceID, r.ExternalObjectID)
}
