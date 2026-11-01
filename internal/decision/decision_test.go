package decision

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
)

type vector struct {
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
	Expected Result          `json:"expected"`
}
type vectors struct {
	Cases        []vector `json:"cases"`
	InvalidCases []vector `json:"invalidCases"`
}

func fixture(t testing.TB) vectors {
	t.Helper()
	raw, err := contracts.Files.ReadFile("v1/decision-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func first(t testing.TB) Request {
	t.Helper()
	r, err := DecodeRequest(fixture(t).Cases[0].Input)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestConformance(t *testing.T) {
	v := fixture(t)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r, err := DecodeRequest(c.Input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Select(r)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.Expected) {
				t.Fatalf("got %+v, expected %+v", got, c.Expected)
			}
			rng := rand.New(rand.NewPCG(42, 17))
			for range 12 {
				rng.Shuffle(len(r.Candidates), func(i, j int) { r.Candidates[i], r.Candidates[j] = r.Candidates[j], r.Candidates[i] })
				shuffled, err := Select(r)
				if err != nil || !reflect.DeepEqual(got, shuffled) {
					t.Fatalf("order changed result: %+v %v", shuffled, err)
				}
			}
		})
	}
	for _, c := range v.InvalidCases {
		t.Run(c.Name, func(t *testing.T) {
			if _, err := DecodeRequest(c.Input); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}
func TestStrictWire(t *testing.T) {
	valid := string(fixture(t).Cases[0].Input)
	bad := []string{
		"", "null", "[]", "true", "0", "{", "[1,", `{"x":1,"x":2}`, `{"x":1,"\u0078":2}`,
		`{"x":-1}`, `{"x":1.0}`, `{"x":1e1}`, valid + " " + valid,
		strings.Repeat("[", 18) + strings.Repeat("]", 18),
		"[" + strings.Repeat("0,", 4096) + "0]",
	}
	members := []string{}
	for i := range 65 {
		members = append(members, fmt.Sprintf(`"key%d":0`, i))
	}
	bad = append(bad, "{"+strings.Join(members, ",")+"}", strings.Repeat(" ", MaxWireBytes+1))
	for i, raw := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := DecodeRequest([]byte(raw)); err == nil {
				t.Fatal("invalid wire accepted")
			}
		})
	}
}
func TestBoundsAndRejectionOrder(t *testing.T) {
	r := first(t)
	r.Candidates = make([]Candidate, 4096)
	base := first(t).Candidates[0]
	for i := range r.Candidates {
		r.Candidates[i] = base
		r.Candidates[i].ID = fmt.Sprintf("path-%04d", i)
	}
	if _, err := Select(r); err != nil {
		t.Fatal(err)
	}
	r.Candidates = append(r.Candidates, base)
	if _, err := Select(r); err == nil {
		t.Fatal("4097 candidates accepted")
	}
	r = first(t)
	r.Candidates[0].Allowed = false
	r.Candidates[1].Allowed = false
	r.Candidates[0].ID = "z"
	r.Candidates[1].ID = "a"
	got, err := Select(r)
	if err != nil || len(got.Rejected) != 2 || got.Rejected[0].PathID != "a" {
		t.Fatalf("%+v %v", got, err)
	}
	r.Candidates[0].Samples = -1
	if _, err := Select(r); err == nil {
		t.Fatal("negative samples accepted")
	}
}
func TestEnergyWorstDimension(t *testing.T) {
	r := first(t)
	c := r.Candidates[0]
	low := int64(0)
	high := int64(100)
	c.BytesPerMinute = &low
	c.HandshakesPerMinute = &low
	c.ActiveBackups = &low
	if rank(r, c)[1] != 0 {
		t.Fatal("expected low")
	}
	for i := range 3 {
		q := c
		switch i {
		case 0:
			q.BytesPerMinute = nil
		case 1:
			q.HandshakesPerMinute = &high
		case 2:
			q.ActiveBackups = &high
		}
		if rank(r, q)[1] != 2 {
			t.Fatal("worst dimension ignored")
		}
	}
}
func TestCoordinatorStaleAndStop(t *testing.T) {
	initial := first(t).Context
	c, err := NewCoordinator(initial)
	if err != nil {
		t.Fatal(err)
	}
	if c.TryApply(initial, "p") {
		t.Fatal("applied while stopped")
	}
	token, err := c.Start()
	if err != nil || !c.TryApply(token, "p") {
		t.Fatal("start/apply failed")
	}
	if c.TryApply(token, "../bad") {
		t.Fatal("invalid path accepted")
	}
	changed, err := c.NetworkChanged()
	if err != nil || c.TryApply(token, "p") || changed.NetworkEpoch != token.NetworkEpoch+1 {
		t.Fatal("stale network applied")
	}
	token, err = c.Activate("cfg-2", "alg-2", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	old := token
	if _, err = c.EngineChanged(); err != nil {
		t.Fatal(err)
	}
	if c.TryApply(old, "p") {
		t.Fatal("stale engine applied")
	}
	if _, err = c.Activate("INVALID", "alg-2", strings.Repeat("b", 64)); err == nil {
		t.Fatal("bad activation accepted")
	}
	token = c.Snapshot().Context
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				c.TryApply(token, "p")
				_ = c.Snapshot()
			}
		})
	}
	if _, err = c.Stop(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if c.TryApply(token, "p") || c.Snapshot().DesiredOn || c.Snapshot().ActivePathID != "" {
		t.Fatal("Stop lost to completion")
	}
}
func TestCoordinatorAllContextFields(t *testing.T) {
	for field := range 6 {
		c, _ := NewCoordinator(first(t).Context)
		token, _ := c.Start()
		changed := token
		switch field {
		case 0:
			changed.NetworkEpoch++
		case 1:
			changed.ActivationGeneration++
		case 2:
			changed.ConfigRevision = "cfg-x"
		case 3:
			changed.AlgorithmRevision = "alg-x"
		case 4:
			changed.EngineGeneration++
		case 5:
			changed.DependencyHash = strings.Repeat("b", 64)
		}
		if c.TryApply(changed, "p") {
			t.Fatalf("context field %d ignored", field)
		}
	}
}
func TestCoordinatorOverflowAtomic(t *testing.T) {
	for field := range 3 {
		ctx := first(t).Context
		switch field {
		case 0:
			ctx.ActivationGeneration = MaxGeneration
		case 1:
			ctx.NetworkEpoch = MaxGeneration
		case 2:
			ctx.EngineGeneration = MaxGeneration
		}
		c, err := NewCoordinator(ctx)
		if err != nil {
			t.Fatal(err)
		}
		before := c.Snapshot()
		switch field {
		case 0:
			_, err = c.Start()
			if err == nil {
				t.Fatal("overflow Start")
			}
			_, err = c.Stop()
			if err != nil {
				t.Fatal("Stop must succeed at exhaustion")
			}
			_, err = c.Activate("cfg-2", "alg-2", strings.Repeat("b", 64))
		case 1:
			_, err = c.NetworkChanged()
		case 2:
			_, err = c.EngineChanged()
		}
		if err == nil || c.Snapshot() != before {
			t.Fatal("overflow mutated state")
		}
	}
	bad := first(t).Context
	bad.NetworkEpoch = -1
	if _, err := NewCoordinator(bad); err == nil {
		t.Fatal("invalid context accepted")
	}
	last := first(t).Context
	last.ActivationGeneration = MaxGeneration - 1
	c, _ := NewCoordinator(last)
	token, _ := c.Start()
	if !c.TryApply(token, "p") {
		t.Fatal("last generation should be usable")
	}
	if _, err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().DesiredOn || c.Snapshot().ActivePathID != "" || c.TryApply(token, "p") {
		t.Fatal("exhaustion prevented Stop")
	}
	if _, err := c.Start(); err == nil {
		t.Fatal("exhausted generation restarted")
	}
}
func FuzzDecode(f *testing.F) {
	for _, c := range fixture(f).Cases {
		f.Add([]byte(c.Input))
	}
	f.Add([]byte(`{"schemaVersion":1,"schemaVersion":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := DecodeRequest(raw)
		if err != nil {
			return
		}
		result, err := Select(r)
		if err != nil {
			t.Fatal(err)
		}
		if result.SelectedPathID != nil && (len(result.OrderedPathIDs) == 0 || *result.SelectedPathID != result.OrderedPathIDs[0]) {
			t.Fatal("inconsistent winner")
		}
	})
}
