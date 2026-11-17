package routecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
)

func sampleProfile() Profile {
	return Profile{SchemaVersion: 2, ID: "connectivity", Revision: 1, DeadlineMs: 12000,
		Leaves: []Leaf{{ID: "a", Check: Check{Method: "tcp", Target: "a.example.invalid:443"}}, {ID: "b", Check: Check{Method: "https_204", Target: "https://b.example.invalid/"}}},
		Gates:  []string{}, Stages: []Expr{{Any: []Expr{{Leaf: "a"}, {Leaf: "b"}}}}}
}
func cloneProfile(t *testing.T, p Profile) Profile {
	t.Helper()
	b, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	var out Profile
	if json.Unmarshal(b, &out) != nil {
		t.Fatal("valid profile fixture")
	}
	return out
}

func TestCheckPlanV2SharedContractValidInvalidAndRawVectors(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/route-check-profile-v2-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors struct {
		SchemaVersion int `json:"schemaVersion"`
		Valid         []struct {
			Name    string          `json:"name"`
			Profile json.RawMessage `json:"profile"`
			SHA     string          `json:"sha256"`
		} `json:"validCases"`
		Invalid []struct {
			Name    string          `json:"name"`
			Profile json.RawMessage `json:"profile"`
		} `json:"invalidCases"`
		Raw []struct {
			Name string `json:"name"`
			Raw  string `json:"raw"`
		} `json:"invalidRawCases"`
		Truth []struct {
			Profile json.RawMessage `json:"profile"`
		} `json:"truthCases"`
		Legacy []struct {
			Checks []Check `json:"checks"`
			SHA    string  `json:"sha256"`
		} `json:"legacyCases"`
	}
	if json.Unmarshal(raw, &vectors) != nil || vectors.SchemaVersion != 1 || len(vectors.Valid) != 9 || len(vectors.Invalid) != 37 || len(vectors.Raw) != 6 || len(vectors.Truth) != 51 || len(vectors.Legacy) != 1 {
		t.Fatal("shared vector scope changed")
	}
	for _, v := range vectors.Valid {
		t.Run(v.Name, func(t *testing.T) {
			var p Profile
			if json.Unmarshal(v.Profile, &p) != nil || p.Validate() != nil {
				t.Fatal("valid shared profile rejected")
			}
			b, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(append([]byte("syn443-route-check-plan-v2\n"), b...))
			if hex.EncodeToString(sum[:]) != v.SHA {
				t.Fatal("normalized domain-separated profile hash diverged")
			}
			var again Profile
			if json.Unmarshal(b, &again) != nil {
				t.Fatal("normalization lost complete program")
			}
		})
	}
	for _, v := range vectors.Invalid {
		t.Run("invalid/"+v.Name, func(t *testing.T) {
			var p Profile
			if json.Unmarshal(v.Profile, &p) == nil {
				t.Fatal("invalid common profile accepted")
			}
		})
	}
	for _, v := range vectors.Raw {
		t.Run("raw/"+v.Name, func(t *testing.T) {
			var p Profile
			if json.Unmarshal([]byte(v.Raw), &p) == nil {
				t.Fatal("ambiguous raw profile accepted")
			}
		})
	}
	for _, v := range vectors.Truth {
		var p Profile
		if json.Unmarshal(v.Profile, &p) != nil {
			t.Fatal("runtime truth fixture has incompatible syntax")
		}
	}
	b, e := json.Marshal(vectors.Legacy[0].Checks)
	sum := sha256.Sum256(b)
	if e != nil || hex.EncodeToString(sum[:]) != vectors.Legacy[0].SHA {
		t.Fatal("legacy ordered check hash changed")
	}
}

func TestCheckPlanV2ClosedXorNullCaseAndDuplicateRows(t *testing.T) {
	p, _ := json.Marshal(sampleProfile())
	valid := `{"outbound":"direct","required":false,"profile":` + string(p) + `}`
	for _, raw := range []string{
		`{"outbound":"direct","required":false}`, `{"outbound":"direct","required":false,"checks":null}`,
		`{"outbound":"direct","required":false,"profile":null}`, strings.Replace(valid, `"profile":`, `"checks":[],"profile":`, 1),
		strings.Replace(valid, `"profile":`, `"Profile":`, 1), strings.Replace(valid, `"required":false,`, ``, 1),
		strings.Replace(valid, `"required":false`, `"required":null`, 1), strings.Replace(valid, `"outbound":"direct"`, `"outbound":"direct","outbound":"direct"`, 1),
		strings.Replace(valid, `"outbound":"direct"`, `"outbound":"direct","\u006futbound":"direct"`, 1), valid + `[]`,
	} {
		if _, e := DecodePlans([]byte("[" + raw + "]")); e == nil {
			t.Fatal("closed profile row accepted ambiguous presence")
		}
	}
	plans, e := DecodePlans([]byte("[" + valid + "]"))
	if e != nil || plans[0].Profile == nil || plans[0].Checks != nil {
		t.Fatal("v2 row flattened")
	}
	legacy, e := DecodePlans([]byte(`[{"outbound":"direct","checks":[{"method":"tcp","target":"a.example.invalid:443"}]}]`))
	if e != nil || legacy[0].Required || legacy[0].Profile != nil {
		t.Fatal("legacy optional required flag changed")
	}
}

func TestCheckPlanV2SecurityLeavesMustBeUnconditionalMatchingGates(t *testing.T) {
	for _, c := range []Check{{Method: "tls", Target: "https://tls.example.invalid/"}, {Method: "https_exit_ip", Target: "https://ip.example.invalid/", ExpectedIP: "192.0.2.9"}, {Method: "https_exit_country", Target: "https://country.example.invalid/", ExpectedExitClass: "RU"}} {
		p := sampleProfile()
		p.Leaves[0].Check = c
		if p.Validate() == nil {
			t.Fatal("security primitive inside alternative")
		}
		p.Gates = []string{"a"}
		p.Stages = []Expr{{Leaf: "b"}}
		if p.Validate() != nil {
			t.Fatal("unconditional security gate rejected")
		}
		if c.Method == "https_exit_country" {
			plan := Plan{Outbound: "direct", Profile: &p}
			if plan.ValidateIntent("RU") != nil || plan.ValidateIntent("NON_RU") == nil || plan.ValidateIntent("INTERNAL") == nil {
				t.Fatal("country gate confused target with exit intent")
			}
		}
	}
}

func TestCheckPlanV2IntegerDeadlineLeafAndProgramBoundaries(t *testing.T) {
	p := sampleProfile()
	p.Revision = 9007199254740991
	p.DeadlineMs = 1
	p.Leaves = append(p.Leaves, Leaf{ID: "c", Check: Check{Method: "tcp", Target: "c.example.invalid:443"}}, Leaf{ID: "d", Check: Check{Method: "tcp", Target: "d.example.invalid:443"}})
	p.Stages = []Expr{{All: []Expr{{Leaf: "a"}, {Any: []Expr{{Leaf: "b"}, {All: []Expr{{Leaf: "c"}, {Leaf: "d"}}}}}}}}
	if p.Validate() != nil {
		t.Fatal("exact four leaves/seven nodes/depth four rejected")
	}
	for _, mutate := range []func(*Profile){func(p *Profile) { p.Revision++ }, func(p *Profile) { p.Revision = 0 }, func(p *Profile) { p.DeadlineMs = 12001 }, func(p *Profile) { p.DeadlineMs = 0 }, func(p *Profile) {
		p.Leaves = append(p.Leaves, Leaf{ID: "e", Check: Check{Method: "tcp", Target: "e.example.invalid:443"}})
	}, func(p *Profile) { p.Stages = append(p.Stages, Expr{Leaf: "a"}) }, func(p *Profile) { p.Leaves[3].Check = p.Leaves[0].Check }, func(p *Profile) { p.Leaves[3].ID = p.Leaves[0].ID }} {
		v := cloneProfile(t, p)
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("profile exceeded exact safety boundary")
		}
	}
	raw, _ := json.Marshal(sampleProfile())
	for _, pair := range [][2]string{{`"schemaVersion":2`, `"schemaVersion":2.0`}, {`"revision":1`, `"revision":1e0`}, {`"deadlineMs":12000`, `"deadlineMs":"12000"`}} {
		var v Profile
		if json.Unmarshal([]byte(strings.Replace(string(raw), pair[0], pair[1], 1)), &v) == nil {
			t.Fatal("noninteger schema number accepted")
		}
	}
}

func TestCheckPlanV2CanonicalLeafOrderDoesNotRewriteBranchOrderOrLegacy(t *testing.T) {
	p := sampleProfile()
	p.Leaves[0], p.Leaves[1] = p.Leaves[1], p.Leaves[0]
	b, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	var v Profile
	if json.Unmarshal(b, &v) != nil || v.Leaves[0].ID != "a" || v.Stages[0].Any[0].Leaf != "a" || v.Stages[0].Any[1].Leaf != "b" {
		t.Fatal("canonical leaves changed execution order")
	}
	legacy := Plan{Outbound: "direct", Required: true, Checks: []Check{{Method: "tcp", Target: "a.example.invalid:443"}}}
	old, e := json.Marshal(legacy)
	if e != nil || string(old) != `{"outbound":"direct","required":true,"checks":[{"method":"tcp","target":"a.example.invalid:443"}]}` {
		t.Fatal("legacy JSON wire changed")
	}
}

func TestCheckPlanV2DeclaredLeavesAreOwnedAndNeverDiscountShortCircuitCost(t *testing.T) {
	p := sampleProfile()
	plan := Plan{Outbound: "direct", Profile: &p}
	all := plan.AllChecks()
	if len(all) != 2 || len(plan.GateChecks()) != 0 {
		t.Fatal("alternative discounted admission cost")
	}
	all[0].Target = "mutated.example.invalid:443"
	if plan.Profile.Leaves[0].Check.Target == all[0].Target {
		t.Fatal("scan accessor leaked caller mutation")
	}
	gate := p
	gate.Gates = []string{"a"}
	gate.Stages = []Expr{{Leaf: "b"}}
	plan.Profile = &gate
	g := plan.GateChecks()
	g[0].Target = "mutated.example.invalid:443"
	if plan.Profile.Leaves[0].Check.Target == g[0].Target {
		t.Fatal("gate accessor leaked storage")
	}
}

func TestCheckPlanV2MetadataBytePlanBoundsAndDiagnosticsStayRedacted(t *testing.T) {
	p := sampleProfile()
	plan := Plan{Outbound: "private-marker", Profile: &p}
	for _, v := range []any{plan, p, p.Leaves[0], p.Leaves[0].Check, p.Stages[0], Quorum{K: 1, Of: p.Stages}} {
		out := fmt.Sprintf("%v %#v", v, v)
		if strings.Contains(out, "example.invalid") || strings.Contains(out, "connectivity") || strings.Contains(out, "private-marker") {
			t.Fatal("route check formatting leaked data")
		}
	}
	plans := make([]Plan, 16)
	for i := range plans {
		plans[i] = plan
	}
	b, _ := json.Marshal(plans)
	if _, e := DecodePlans(b); e != nil {
		t.Fatal("sixteen profile rows rejected")
	}
	plans = append(plans, plan)
	b, _ = json.Marshal(plans)
	if _, e := DecodePlans(b); e == nil {
		t.Fatal("seventeenth row accepted")
	}
	if _, e := DecodePlans([]byte(strings.Repeat(" ", MaxBytes) + "[]")); e == nil {
		t.Fatal("metadata byte limit bypassed")
	}
}
