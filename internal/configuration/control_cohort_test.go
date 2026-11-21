package configuration

import (
	"encoding/json"
	"testing"
)

func TestPermanentControlAtTreatmentExpansionAndExactBoundaries(t *testing.T) {
	// The fixture's control buckets are 8941 for synthetic-a and 2872 for synthetic-b.
	points := 10000
	rollout := DeviceRollout{ID: "fixture-canary", BasisPoints: &points}
	for _, row := range []struct {
		control rolloutControlShare
		a, b    bool
	}{{0, true, true}, {2872, true, true}, {2873, true, false}, {8941, true, false}, {8942, false, false}, {10000, false, false}} {
		rollout.ControlBasisPoints = row.control
		for _, includes := range []func(string) bool{rollout.IncludesDecision, rollout.IncludesProbeCooldown} {
			if includes("synthetic-a") != row.a || includes("synthetic-b") != row.b {
				t.Fatalf("unexpected assignment for reserved share %d", row.control)
			}
		}
	}
	rollout.ControlBasisPoints = 2873
	for _, points = range []int{0, 1, 2500, 5000, 9999, 10000, 0} {
		if rollout.IncludesDecision("synthetic-b") || rollout.IncludesProbeCooldown("synthetic-b") {
			t.Fatal("control device changed during treatment expansion or rollback")
		}
	}
}

func TestMalformedPermanentControlCannotClearTheReservation(t *testing.T) {
	for _, raw := range []string{`null`, `""`, `"0"`, `false`, `0.5`, `10001`, `-1`, `1e2`} {
		var rollout DeviceRollout
		if err := json.Unmarshal([]byte(`{"id":"fixture","basisPoints":10000,"controlBasisPoints":`+raw+"}"), &rollout); err == nil {
			t.Fatal("invalid control percentage accepted", raw)
		}
	}
}
