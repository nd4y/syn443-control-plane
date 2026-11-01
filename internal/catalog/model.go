// Package catalog owns persistent control definitions and immutable source data.
// A catalog worker is not a publication authority.
package catalog

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

var ErrInvalid = errors.New("catalog_invalid")
var ErrDenied = errors.New("catalog_denied")
var ErrConflict = errors.New("catalog_revision_conflict")
var ErrUnavailable = errors.New("catalog_unavailable")
var ErrQuota = errors.New("catalog_quota")
var ErrStale = errors.New("catalog_stale_job")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var sourceIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)
var externalRemnawaveID = regexp.MustCompile(`^[1-9][0-9]{0,14}$`)

type Source struct {
	ID                   string   `json:"id"`
	Owner                string   `json:"owner"`
	Name                 string   `json:"name"`
	Mode                 string   `json:"mode"`
	Format               string   `json:"format"`
	ResourceID           string   `json:"resourceId,omitempty"`
	ExternalUserID       string   `json:"externalUserId,omitempty"`
	Enabled              bool     `json:"enabled"`
	Revision             int64    `json:"revision"`
	ValidUntil           int64    `json:"validUntil"`
	RefreshSeconds       int64    `json:"refreshSeconds"`
	MaxStaleSeconds      int64    `json:"maxStaleSeconds"`
	NetworkModes         []string `json:"networkModes"`
	ActiveSnapshot       string   `json:"activeSnapshot"`
	CandidateSnapshot    string   `json:"candidateSnapshot"`
	State                string   `json:"state"`
	LastSync             int64    `json:"lastSync"`
	NextSync             int64    `json:"nextSync"`
	LastResourceRevision int64    `json:"lastResourceRevision"`
}

func (Source) String() string   { return "CatalogSource([redacted])" }
func (Source) GoString() string { return "CatalogSource([redacted])" }
func (s Source) Validate(now time.Time) error {
	if !sourceIdentifier.MatchString(s.ID) || !identifier.MatchString(s.Owner) || len(s.Name) < 1 || len(s.Name) > 256 || s.Revision < 0 || s.Revision > 9007199254740991 || s.ValidUntil <= now.Unix() || s.ValidUntil > now.Add(366*24*time.Hour).Unix() || s.RefreshSeconds < 60 || s.RefreshSeconds > 86400 || s.MaxStaleSeconds < 300 || s.MaxStaleSeconds > 604800 || len(s.NetworkModes) < 1 || len(s.NetworkModes) > 4 {
		return ErrInvalid
	}
	if s.Mode != "server" && s.Mode != "device" && s.Mode != "manual" && s.Mode != "resource" {
		return ErrInvalid
	}
	if s.Format != "uri" && s.Format != "base64" && s.Format != "singbox" && s.Format != "xray" && s.Format != "mihomo" {
		return ErrInvalid
	}
	if s.Mode == "resource" {
		if !sourceIdentifier.MatchString(s.ResourceID) || !externalRemnawaveID.MatchString(s.ExternalUserID) {
			return ErrInvalid
		}
	} else if s.ResourceID != "" || s.ExternalUserID != "" {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, mode := range s.NetworkModes {
		if seen[mode] || mode != "home_wifi" && mode != "wifi" && mode != "cellular_restricted" && mode != "cellular" {
			return ErrInvalid
		}
		seen[mode] = true
	}
	return nil
}

// Secrets have an explicit mutation operation; a UI mask is never a password.
type SecretPatch struct {
	Operation string          `json:"operation"`
	Value     json.RawMessage `json:"value,omitempty"`
}

func (SecretPatch) String() string   { return "CatalogSecretPatch([redacted])" }
func (SecretPatch) GoString() string { return "CatalogSecretPatch([redacted])" }
func (p SecretPatch) Apply(previous []byte) ([]byte, error) {
	switch p.Operation {
	case "keep":
		if len(p.Value) != 0 {
			return nil, ErrInvalid
		}
		return append([]byte(nil), previous...), nil
	case "delete":
		if len(p.Value) != 0 {
			return nil, ErrInvalid
		}
		return nil, nil
	case "replace":
		if len(p.Value) == 0 || len(p.Value) > 65536 {
			return nil, ErrInvalid
		}
		v, e := subscriptions.DecodeJSON(p.Value)
		if e != nil || hasMask(v) {
			return nil, ErrInvalid
		}
		return json.Marshal(v)
	default:
		return nil, ErrInvalid
	}
}
func hasMask(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == "***" || x == "[redacted]" || x == "••••••••"
	case map[string]any:
		for _, v := range x {
			if hasMask(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if hasMask(v) {
				return true
			}
		}
	}
	return false
}

type StoredProfile struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Outbound json.RawMessage `json:"outbound"`
}

func (StoredProfile) String() string   { return "StoredProfile([redacted])" }
func (StoredProfile) GoString() string { return "StoredProfile([redacted])" }
func protectedProfiles(in []subscriptions.Profile) ([]byte, error) {
	if len(in) < 1 || len(in) > subscriptions.MaxProfiles {
		return nil, ErrInvalid
	}
	out := make([]StoredProfile, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		if !identifier.MatchString(p.ID) || seen[p.ID] || len(p.Name) > 256 || len(p.Outbound) > 262144 {
			return nil, ErrInvalid
		}
		seen[p.ID] = true
		v, e := subscriptions.DecodeJSON(p.Outbound)
		if e != nil {
			return nil, ErrInvalid
		}
		m, ok := v.(map[string]any)
		if !ok || subscriptions.ValidateOutbound(m) != nil || m["tag"] != p.ID || m["type"] != p.Kind {
			return nil, ErrInvalid
		}
		out = append(out, StoredProfile{ID: p.ID, Name: p.Name, Kind: p.Kind, Outbound: p.Outbound})
	}
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > 16*1024*1024 {
		return nil, ErrQuota
	}
	return raw, nil
}

type Snapshot struct {
	ID               string              `json:"id"`
	SourceID         string              `json:"sourceId"`
	SourceRevision   int64               `json:"sourceRevision"`
	Hash             string              `json:"hash"`
	ObservedAt       int64               `json:"observedAt"`
	ValidUntil       int64               `json:"validUntil"`
	Count            int                 `json:"count"`
	State            string              `json:"state"`
	Reason           string              `json:"reason"`
	Quota            subscriptions.Quota `json:"quota"`
	ResourceRevision int64               `json:"resourceRevision"`
}
type Job struct {
	ID               string `json:"id"`
	SourceID         string `json:"sourceId"`
	SourceRevision   int64  `json:"sourceRevision"`
	Kind             string `json:"kind"`
	Phase            string `json:"phase"`
	Attempts         int    `json:"attempts"`
	Deadline         int64  `json:"deadline"`
	Reason           string `json:"reason"`
	Lease            string `json:"-"`
	LeaseUntil       int64  `json:"-"`
	BaseSnapshot     string `json:"-"`
	ResourceRevision int64  `json:"-"`
}

func (Job) String() string   { return "CatalogJob([redacted])" }
func (Job) GoString() string { return "CatalogJob([redacted])" }
