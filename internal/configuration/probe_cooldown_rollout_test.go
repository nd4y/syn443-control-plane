package configuration

import "testing"

func TestProbeCooldownRolloutIsStableAndMonotoneAtExactThreshold(t *testing.T) {
	rate := 0
	rollout := DeviceRollout{ID: "fixture-canary", BasisPoints: &rate}
	for _, row := range []struct {
		basisPoints int
		a, b        bool
	}{
		{0, false, false}, {2133, false, false}, {2134, false, true},
		{9294, false, true}, {9295, true, true}, {10000, true, true},
	} {
		rate = row.basisPoints
		for i := 0; i < 10; i++ {
			if rollout.IncludesProbeCooldown("synthetic-b") != row.b || rollout.IncludesProbeCooldown("synthetic-a") != row.a {
				t.Fatal("cohort moved on retry or crossed its threshold")
			}
		}
	}
	rate = 7000
	if rollout.IncludesProbeCooldown("synthetic-a") ||
		!(DeviceRollout{ID: "fixture-other", BasisPoints: &rate}).IncludesProbeCooldown("synthetic-a") {
		t.Fatal("rollout IDs are not independent")
	}
	rate = 10000
	if rollout.IncludesProbeCooldown("short") || rollout.IncludesProbeCooldown("synthetic/a") {
		t.Fatal("untrusted device identity entered a cohort")
	}
}

func TestProbeCooldownRolloutRejectsOmittedAndUnboundedInputs(t *testing.T) {
	below, above, valid := -1, 10001, 10000
	for _, r := range []DeviceRollout{
		{ID: "fixture"}, {ID: "fixture", BasisPoints: &below}, {ID: "fixture", BasisPoints: &above},
		{ID: "Fixture", BasisPoints: &valid}, {ID: "/fixture", BasisPoints: &valid},
	} {
		if r.valid() || r.IncludesProbeCooldown("synthetic-a") {
			t.Fatal("invalid cohort selected a device")
		}
	}
}

func TestDecisionRolloutHasAStableIndependentThreshold(t *testing.T) {
	rate := 2128
	rollout := DeviceRollout{ID: "fixture-canary", BasisPoints: &rate}
	if rollout.IncludesDecision("synthetic-a") {
		t.Fatal("device entered before its threshold")
	}
	rate++
	for i := 0; i < 10; i++ {
		if !rollout.IncludesDecision("synthetic-a") || rollout.IncludesProbeCooldown("synthetic-a") {
			t.Fatal("decision cohort shifted or reused the reserve cooldown cohort")
		}
	}
	rate = 10000
	if !rollout.IncludesDecision("synthetic-a") || rollout.IncludesDecision("synthetic/a") {
		t.Fatal("invalid eligibility at 100 percent")
	}
}
