package chatweb

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConsoleSourceReviewRequiresAnExplicitAndBoundDecision(t *testing.T) {
	const hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	base := map[string]any{"sourceId": "example", "sourceRevision": 3, "active": "old", "candidate": "new", "hash": hash, "approve": false}
	check := func(changes map[string]any, remove string, want bool) {
		t.Helper()
		payload := map[string]any{}
		for k, v := range base {
			payload[k] = v
		}
		for k, v := range changes {
			payload[k] = v
		}
		delete(payload, remove)
		body, err := json.Marshal(map[string]any{"version": 1, "action": "source.review", "requestId": "synthetic-review-request", "payload": payload})
		if err != nil || validConsoleAction(body, false) != want || validConsoleAction(body, true) {
			t.Fatalf("unexpected console review admission for changed fields %v, removed %q", changes, remove)
		}
	}
	check(nil, "", true)
	check(map[string]any{"active": "", "approve": true}, "", true)
	for _, field := range []string{"sourceId", "sourceRevision", "active", "candidate", "approve", "hash"} {
		check(nil, field, false)
	}
	for _, change := range []map[string]any{{"active": "new"}, {"candidate": "../new"}, {"hash": strings.Repeat("A", 42) + "B"}, {"approve": "true"}, {"sourceRevision": 0}, {"sourceRevision": int64(9007199254740992)}, {"secret": "value"}} {
		check(change, "", false)
	}
}
