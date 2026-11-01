// Package decision evaluates bounded, already measured path observations.
package decision

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type Context struct {
	NetworkEpoch         int64  `json:"networkEpoch"`
	ActivationGeneration int64  `json:"activationGeneration"`
	ConfigRevision       string `json:"configRevision"`
	AlgorithmRevision    string `json:"algorithmRevision"`
	EngineGeneration     int64  `json:"engineGeneration"`
	DependencyHash       string `json:"dependencyHash"`
}

type Candidate struct {
	ID                  string  `json:"id"`
	Context             Context `json:"context"`
	Allowed             bool    `json:"allowed"`
	ExitClass           string  `json:"exitClass"`
	RequiredHealthy     bool    `json:"requiredHealthy"`
	OptionalDegraded    bool    `json:"optionalDegraded"`
	HardFailure         bool    `json:"hardFailure"`
	ObservedAtMs        int64   `json:"observedAtMs"`
	Samples             int64   `json:"samples"`
	Failures            int64   `json:"failures"`
	TrailingSuccesses   int64   `json:"trailingSuccesses"`
	BytesPerMinute      *int64  `json:"bytesPerMinute"`
	HandshakesPerMinute *int64  `json:"handshakesPerMinute"`
	ActiveBackups       *int64  `json:"activeBackups"`
	LatencyMs           *int64  `json:"latencyMs"`
	MetricGroup         string  `json:"metricGroup"`
}
type Request struct {
	SchemaVersion int         `json:"schemaVersion"`
	Context       Context     `json:"context"`
	NowMs         int64       `json:"nowMs"`
	EvidenceTtlMs int64       `json:"evidenceTtlMs"`
	Intent        string      `json:"intent"`
	MetricGroup   string      `json:"metricGroup"`
	Candidates    []Candidate `json:"candidates"`
}
type Rejection struct {
	PathID string `json:"pathId"`
	Reason string `json:"reason"`
}
type Result struct {
	SelectedPathID *string     `json:"selectedPathId"`
	OrderedPathIDs []string    `json:"orderedPathIds"`
	Rejected       []Rejection `json:"rejected"`
}

var schemaOnce sync.Once
var compiledSchema *jsonschema.Schema
var schemaErr error

func requestSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		raw, err := contracts.Files.ReadFile("v1/decision-request.schema.json")
		if err != nil {
			schemaErr = err
			return
		}
		var doc any
		if err = json.Unmarshal(raw, &doc); err != nil {
			schemaErr = err
			return
		}
		compiler := jsonschema.NewCompiler()
		const url = "https://schemas.syn443.invalid/v1/decision-request.schema.json"
		if err = compiler.AddResource(url, doc); err != nil {
			schemaErr = err
			return
		}
		compiledSchema, schemaErr = compiler.Compile(url)
	})
	return compiledSchema, schemaErr
}

// Validate rejects malformed aggregates and duplicates before any ranking.
func Validate(r Request) error {
	if len(r.Candidates) > 4096 || !validContext(r.Context) || !identifier.MatchString(r.MetricGroup) || len(r.Intent) > 8 {
		return errors.New("invalid decision request")
	}
	for _, c := range r.Candidates {
		if !validContext(c.Context) || !identifier.MatchString(c.ID) || !identifier.MatchString(c.MetricGroup) || len(c.ExitClass) > 8 {
			return errors.New("invalid decision request")
		}
	}
	s, err := requestSchema()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var doc any
	if err = json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if err = s.Validate(doc); err != nil {
		return errors.New("invalid decision request")
	}
	seen := make(map[string]bool, len(r.Candidates))
	for _, c := range r.Candidates {
		if seen[c.ID] {
			return fmt.Errorf("duplicate path id")
		}
		seen[c.ID] = true
		if c.Failures > c.Samples || c.TrailingSuccesses > c.Samples-c.Failures {
			return errors.New("inconsistent sample aggregate")
		}
	}
	return nil
}

func reject(r Request, c Candidate) string {
	switch {
	case c.Context != r.Context:
		return "context_mismatch"
	case !c.Allowed:
		return "disallowed"
	case c.ExitClass != r.Intent:
		return "wrong_exit"
	case !c.RequiredHealthy:
		return "required_check_failed"
	case c.HardFailure:
		return "hard_failure"
	case c.ObservedAtMs > r.NowMs || r.NowMs-c.ObservedAtMs >= r.EvidenceTtlMs:
		return "stale_evidence"
	default:
		return ""
	}
}
func band(v *int64, low, medium int64) int64 {
	if v == nil {
		return 2
	}
	if *v <= low {
		return 0
	}
	if *v <= medium {
		return 1
	}
	return 2
}
func rank(r Request, c Candidate) [4]int64 {
	stability := int64(1)
	if c.OptionalDegraded {
		stability = 2
	} else if c.Samples >= 5 && c.TrailingSuccesses >= 3 && c.Failures*100 <= c.Samples*5 {
		stability = 0
	} else if c.Samples >= 5 {
		stability = 2
	}
	energy := max(band(c.BytesPerMinute, 2048, 8192), band(c.HandshakesPerMinute, 1, 4), band(c.ActiveBackups, 1, 2))
	latency := int64(24001)
	if c.LatencyMs != nil && c.MetricGroup == r.MetricGroup {
		latency = *c.LatencyMs / 25
	}
	confidence := int64(2)
	if c.Samples >= 10 {
		confidence = 0
	} else if c.Samples >= 5 {
		confidence = 1
	}
	return [4]int64{stability, energy, latency, confidence}
}

// Select never probes a network or relaxes eligibility to obtain a winner.
func Select(r Request) (Result, error) {
	result := Result{OrderedPathIDs: []string{}, Rejected: []Rejection{}}
	if err := Validate(r); err != nil {
		return result, err
	}
	eligible := make([]Candidate, 0, len(r.Candidates))
	for _, c := range r.Candidates {
		if why := reject(r, c); why != "" {
			result.Rejected = append(result.Rejected, Rejection{c.ID, why})
		} else {
			eligible = append(eligible, c)
		}
	}
	sort.Slice(result.Rejected, func(i, j int) bool { return result.Rejected[i].PathID < result.Rejected[j].PathID })
	sort.Slice(eligible, func(i, j int) bool {
		a, b := rank(r, eligible[i]), rank(r, eligible[j])
		for k := range a {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return eligible[i].ID < eligible[j].ID
	})
	for _, c := range eligible {
		result.OrderedPathIDs = append(result.OrderedPathIDs, c.ID)
	}
	if len(result.OrderedPathIDs) > 0 {
		id := result.OrderedPathIDs[0]
		result.SelectedPathID = &id
	}
	return result, nil
}
