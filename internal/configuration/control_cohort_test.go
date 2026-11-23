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

func TestDraftCohortsMatchPublicationAndDistinguishPermanentControl(t *testing.T) {
	rate := 2129
	rollout := DeviceRollout{ID: "fixture-canary", BasisPoints: &rate, ControlBasisPoints: 2873}
	for _, tc := range []struct {
		device             string
		decision, cooldown Cohort
	}{
		{"synthetic-a", CohortTreatment, CohortBaseline},
		{"synthetic-b", CohortControl, CohortControl},
	} {
		groups, err := PreviewDeviceRollouts(tc.device, &rollout, &rollout)
		if err != nil || len(groups) != 2 || groups["decision"] != tc.decision || groups["probeCooldown"] != tc.cooldown ||
			rollout.IncludesDecision(tc.device) != (tc.decision == CohortTreatment) ||
			rollout.IncludesProbeCooldown(tc.device) != (tc.cooldown == CohortTreatment) {
			t.Fatalf("assignment diverged for %s: %v %v", tc.device, groups, err)
		}
	}
	other := rollout
	other.ControlBasisPoints = 10000
	if _, err := PreviewDeviceRollouts("synthetic-a", &rollout, &other); err == nil {
		t.Fatal("conflicting shared control accepted")
	}
	other.ID = "independent"
	groups, err := PreviewDeviceRollouts("synthetic-a", &rollout, &other)
	if err != nil || groups["decision"] != CohortTreatment || groups["probeCooldown"] != CohortControl {
		t.Fatal("distinct cohorts not independent")
	}
}

func TestExplicitPausePreservesRolloutSharesAndControlMembership(t *testing.T) {
	points := 10000
	published := DeviceRollout{ID: "fixture-canary", BasisPoints: &points, ControlBasisPoints: 2873}
	paused := published
	paused.Paused = true
	for _, device := range []string{"synthetic-a", "synthetic-b"} {
		before, err := PreviewDeviceRollouts(device, &published, &published)
		if err != nil {
			t.Fatal(err)
		}
		during, err := PreviewDeviceRollouts(device, &paused, &published)
		want := CohortBaseline
		if before["decision"] == CohortControl {
			want = CohortControl
		}
		if err != nil || during["decision"] != want || during["probeCooldown"] != before["probeCooldown"] ||
			paused.IncludesDecision(device) || paused.IncludesProbeCooldown(device) {
			t.Fatal("pause changed the control or unrelated feature", err)
		}
		bytes, err := json.Marshal(paused)
		var decoded DeviceRollout
		if err != nil || json.Unmarshal(bytes, &decoded) != nil || !decoded.Paused ||
			decoded.BasisPoints == nil || *decoded.BasisPoints != points ||
			decoded.ControlBasisPoints != published.ControlBasisPoints || decoded.ID != published.ID {
			t.Fatal("saved pause lost its shares or identity")
		}
		decoded.Paused = false
		after, err := PreviewDeviceRollouts(device, &decoded, &published)
		if err != nil || before["decision"] != after["decision"] {
			t.Fatal("resuming changed the original cohort", err)
		}
	}
}

func TestInvalidPauseCannotEnableTreatment(t *testing.T) {
	for _, raw := range []string{"null", `"false"`, "0", "[]", "{}"} {
		var rollout DeviceRollout
		request := "{\"id\":\"fixture-canary\",\"basisPoints\":10000,\"paused\":" + raw + "}"
		if json.Unmarshal([]byte(request), &rollout) == nil {
			t.Fatal("invalid pause state accepted")
		}
	}
}
