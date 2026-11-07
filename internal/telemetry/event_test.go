package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestClosedBatchRejectsPrivateFieldsAndUnboundedEvidence(t *testing.T) {
	now := time.Unix(1800000000, 0)
	opaqueValue := identity.Hash([]byte("synthetic telemetry session"))
	batch := Batch{SchemaVersion: 1, Session: opaqueValue, Build: 51, AlgorithmRevision: 1,
		Events: []Event{{ID: identity.Hash([]byte("synthetic event")), AtMS: now.UnixMilli(),
			Kind: "probe", Code: "dns_timeout", Mode: "wifi"}}}
	raw, _ := json.Marshal(batch)
	if _, err := Decode(raw, now); err != nil {
		t.Fatal("valid technical telemetry was rejected", err)
	}
	for _, mutated := range []string{
		strings.Replace(string(raw), `"elapsedMs":0,`, "", 1),
		strings.Replace(string(raw), `"networkEpoch":0`, `"networkEpoch":null`, 1),
		strings.Replace(string(raw), `"policyRevision":0`, `"PolicyRevision":0`, 1),
		strings.Replace(string(raw), `"mode":"wifi"`, `"mode":"wifi","ssid":"synthetic-private-label"`, 1),
		strings.Replace(string(raw), `"mode":"wifi"`, `"mode":"wifi","path":"node.example.invalid"`, 1),
		strings.Replace(string(raw), `"dns_timeout"`, `"private detail"`, 1),
	} {
		if _, err := Decode([]byte(mutated), now); err == nil {
			t.Fatal("unbounded or private evidence accepted")
		}
	}
	batch.Events = append(batch.Events, batch.Events[0])
	if batch.Validate(now) == nil {
		t.Fatal("duplicate event IDs accepted")
	}
	batch.Events = batch.Events[:1]
	batch.Events[0].AtMS = now.Add(-MaxEventAge - time.Second).UnixMilli()
	if batch.Validate(now) == nil {
		t.Fatal("expired evidence accepted")
	}
}
