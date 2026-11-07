// Package telemetry defines the device's closed, technical event envelope.
// Authentication and device identity are established outside this payload.
package telemetry

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const (
	MaxBatchBytes   = 16384
	MaxBatchEvents  = 32
	MaxEventAge     = 7 * 24 * time.Hour
	maxExactInteger = 9007199254740991
)

var ErrInvalid = errors.New("invalid_telemetry_batch")
var opaque = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// The client may not send text, labels, endpoints, IPs, headers or device IDs.
// The service receives device identity only from the DPoP session.
type Batch struct {
	SchemaVersion     int     `json:"schemaVersion"`
	Session           string  `json:"session"`
	Build             int     `json:"build"`
	PolicyRevision    int64   `json:"policyRevision"`
	AlgorithmRevision int     `json:"algorithmRevision"`
	Events            []Event `json:"events"`
}

type Event struct {
	ID           string `json:"id"`
	AtMS         int64  `json:"atMs"`
	ElapsedMS    int64  `json:"elapsedMs"`
	NetworkEpoch int64  `json:"networkEpoch"`
	Kind         string `json:"kind"`
	Code         string `json:"code"`
	Mode         string `json:"mode"`
	Path         string `json:"path,omitempty"`
	DurationMS   int    `json:"durationMs,omitempty"`
}

func (Batch) String() string   { return "TelemetryBatch([redacted])" }
func (Batch) GoString() string { return "TelemetryBatch([redacted])" }
func (Event) String() string   { return "TelemetryEvent([redacted])" }
func (Event) GoString() string { return "TelemetryEvent([redacted])" }

var codes = map[string]map[string]bool{
	"network": {"available": true, "lost": true, "changed": true, "not_validated": true, "captive": true},
	"vpn":     {"online": true, "degraded": true, "recovering": true, "off": true, "permission_revoked": true},
	"probe": {"ok": true, "dns_timeout": true, "dns_failure": true, "tcp_timeout": true, "tls_timeout": true,
		"tls_failure": true, "transport_eof": true, "target_failure": true, "capacity": true, "cancelled": true, "unknown": true},
	"route":   {"confirmed_failure": true, "reserve_verified": true, "reselected": true, "quarantined": true, "revalidated": true},
	"policy":  {"prepared": true, "committed": true, "rolled_back": true, "expired": true, "revoked": true},
	"engine":  {"started": true, "restarted": true, "java_crash": true, "native_crash": true, "unexpected_exit": true},
	"overlay": {"direct": true, "relay": true, "degraded": true, "unavailable": true},
}

var modes = map[string]bool{"unknown": true, "home_wifi": true, "wifi": true, "cellular_restricted": true, "cellular": true}

func Decode(raw []byte, now time.Time) (Batch, error) {
	var result Batch
	if len(raw) == 0 || len(raw) > MaxBatchBytes || identity.Decode(raw, &result, true) != nil || result.Validate(now) != nil {
		return Batch{}, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || !closed(fields, []string{"schemaVersion", "session", "build",
		"policyRevision", "algorithmRevision", "events"}, nil) {
		return Batch{}, ErrInvalid
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal(fields["events"], &rows) != nil || len(rows) != len(result.Events) {
		return Batch{}, ErrInvalid
	}
	for _, row := range rows {
		if !closed(row, []string{"id", "atMs", "elapsedMs", "networkEpoch", "kind", "code", "mode"},
			[]string{"path", "durationMs"}) {
			return Batch{}, ErrInvalid
		}
	}
	return result, nil
}

func closed(fields map[string]json.RawMessage, required, optional []string) bool {
	remaining := len(fields)
	for _, name := range required {
		raw, ok := fields[name]
		if !ok || string(raw) == "null" {
			return false
		}
		remaining--
	}
	for _, name := range optional {
		if raw, ok := fields[name]; ok {
			if string(raw) == "null" {
				return false
			}
			remaining--
		}
	}
	return remaining == 0
}

func (b Batch) Validate(now time.Time) error {
	if b.SchemaVersion != 1 || !opaque.MatchString(b.Session) || b.Build < 1 || b.Build > 2100000000 ||
		b.PolicyRevision < 0 || b.PolicyRevision > maxExactInteger || b.AlgorithmRevision < 1 || b.AlgorithmRevision > 1000000 ||
		len(b.Events) < 1 || len(b.Events) > MaxBatchEvents {
		return ErrInvalid
	}
	oldest := now.Add(-MaxEventAge).UnixMilli()
	latest := now.Add(5 * time.Minute).UnixMilli()
	seen := make(map[string]bool, len(b.Events))
	for _, event := range b.Events {
		if !opaque.MatchString(event.ID) || seen[event.ID] || event.AtMS <= 0 || event.AtMS < oldest || event.AtMS > latest ||
			event.ElapsedMS < 0 || event.ElapsedMS > maxExactInteger || event.NetworkEpoch < 0 || event.NetworkEpoch > maxExactInteger ||
			!modes[event.Mode] || !codes[event.Kind][event.Code] || event.DurationMS < 0 || event.DurationMS > 600000 ||
			(event.Path != "" && !opaque.MatchString(event.Path)) {
			return ErrInvalid
		}
		seen[event.ID] = true
	}
	return nil
}
