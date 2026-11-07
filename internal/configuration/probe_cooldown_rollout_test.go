package configuration

import "testing"

func TestProbeCooldownRolloutIsStableAndMonotoneAtExactThreshold(t *testing.T) {
	rate := 0
	rollout := ProbeCooldownRollout{ID: "fixture-canary", BasisPoints: &rate}
	for _, row := range []struct {
		basisPoints int
		a, b        bool
	}{
		{0, false, false}, {2133, false, false}, {2134, false, true},
		{9294, false, true}, {9295, true, true}, {10000, true, true},
	} {
		rate = row.basisPoints
		for i := 0; i < 10; i++ {
			if rollout.Includes("synthetic-b") != row.b || rollout.Includes("synthetic-a") != row.a {
				t.Fatal("cohort moved on retry or crossed its threshold")
			}
		}
	}
	rate = 7000
	if rollout.Includes("synthetic-a") ||
		!(ProbeCooldownRollout{ID: "fixture-other", BasisPoints: &rate}).Includes("synthetic-a") {
		t.Fatal("rollout IDs are not independent")
	}
	rate = 10000
	if rollout.Includes("short") || rollout.Includes("synthetic/a") {
		t.Fatal("untrusted device identity entered a cohort")
	}
}

func TestProbeCooldownRolloutRejectsOmittedAndUnboundedInputs(t *testing.T) {
	below, above, valid := -1, 10001, 10000
	for _, r := range []ProbeCooldownRollout{
		{ID: "fixture"}, {ID: "fixture", BasisPoints: &below}, {ID: "fixture", BasisPoints: &above},
		{ID: "Fixture", BasisPoints: &valid}, {ID: "/fixture", BasisPoints: &valid},
	} {
		if r.valid() || r.Includes("synthetic-a") {
			t.Fatal("invalid cohort selected a device")
		}
	}
}
