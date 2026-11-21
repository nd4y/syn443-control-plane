package routegraph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type graphQuery struct {
	Name, Group, Mode, PathID string
	Path                      []string
	Allowed                   bool
}
type validVector struct {
	Name                      string
	Catalogue                 []string
	Graph                     json.RawMessage
	GroupBounds, IntentBounds map[string]int
	Queries                   []graphQuery
}
type invalidVector struct {
	Name, Raw string
	Catalogue []string
}
type sharedVectors struct {
	ValidCases   []validVector
	InvalidCases []invalidVector
}

func fixture(t testing.TB) sharedVectors {
	t.Helper()
	data, err := os.ReadFile("../../contracts/v1/route-graph-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var result sharedVectors
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.ValidCases) == 0 || len(result.InvalidCases) < 60 {
		t.Fatal("missing shared conformance vectors")
	}
	return result
}

func TestSharedRouteGraphConformance(t *testing.T) {
	for _, v := range fixture(t).ValidCases {
		t.Run(v.Name, func(t *testing.T) {
			g, err := Decode(v.Graph, v.Catalogue)
			if err != nil {
				t.Fatal(err)
			}
			for name, want := range v.GroupBounds {
				if got, ok := g.UpperBound(name); !ok || got != want {
					t.Fatalf("group bound %s: %d %v", name, got, ok)
				}
			}
			for name, want := range v.IntentBounds {
				if got, ok := g.IntentUpperBound(name); !ok || got != want {
					t.Fatalf("intent bound %s: %d %v", name, got, ok)
				}
			}
			for _, q := range v.Queries {
				t.Run(q.Name, func(t *testing.T) {
					if got := g.Allows(q.Group, q.Mode, q.Path); got != q.Allowed {
						t.Fatalf("declaration mismatch: %v", got)
					}
					if q.Allowed {
						id, err := StablePathID(q.Path)
						if err != nil || id != q.PathID {
							t.Fatalf("cross-language path identity mismatch: %s %v", id, err)
						}
					}
				})
			}
			if _, ok := g.UpperBound("missing"); ok {
				t.Fatal("invented group bound")
			}
			if _, ok := g.IntentUpperBound("missing"); ok {
				t.Fatal("invented intent bound")
			}
			if g.Allows("foreign", "AUTO", []string{"exit-b"}) {
				t.Fatal("invented mode")
			}
		})
	}
}

func TestSharedInvalidRouteGraphsFailWithoutPartialAuthority(t *testing.T) {
	for _, v := range fixture(t).InvalidCases {
		t.Run(v.Name, func(t *testing.T) {
			g, err := Decode([]byte(v.Raw), v.Catalogue)
			if g != nil || !errors.Is(err, ErrInvalid) || err.Error() != "invalid route graph" {
				t.Fatalf("not a redacted closed failure: %v %v", g, err)
			}
		})
	}
}

func syntheticGraph(t testing.TB, count int, widths []int) ([]byte, []string) {
	t.Helper()
	catalogue := make([]string, count)
	hops := make([]any, count)
	for i := range catalogue {
		catalogue[i] = fmt.Sprintf("node-%03d", i)
		hops[i] = map[string]any{"id": catalogue[i], "entryModes": []string{"WIFI"}, "exitClass": "NON_RU", "features": []string{"TCP", "IPV4"}}
	}
	slots := make([][]string, len(widths))
	for i, width := range widths {
		slots[i] = catalogue[:width]
	}
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "hops": hops, "edges": []any{},
		"templates": []any{map[string]any{"id": "wide", "slots": slots}},
		"groups":    []any{map[string]any{"id": "foreign", "intent": "NON_RU", "features": []string{"TCP", "IPV4"}, "templates": []string{"wide"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw, catalogue
}
func mutate(t testing.TB, raw []byte, change func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	change(doc)
	result, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func reject(t testing.TB, raw []byte, catalogue []string) {
	t.Helper()
	g, err := Decode(raw, catalogue)
	if g != nil || err != ErrInvalid {
		t.Fatal("invalid graph yielded partial or unredacted result")
	}
}

func TestCatalogueAndCandidateBoundaryCannotBeTruncated(t *testing.T) {
	raw, catalogue := syntheticGraph(t, 500, []int{16, 16, 16})
	g, err := Decode(raw, catalogue)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := g.UpperBound("foreign"); !ok || n != 4096 {
		t.Fatal("exact candidate boundary lost")
	}
	if n, ok := g.IntentUpperBound("NON_RU"); !ok || n != 4096 {
		t.Fatal("exact intent boundary lost")
	}
	tooWide, _ := syntheticGraph(t, 500, []int{17, 16, 16})
	reject(t, tooWide, catalogue)
	if g, err := DecodeForPreview(tooWide, catalogue); g != nil || err != ErrCandidateLimit {
		t.Fatal("editor did not receive the template bound")
	}
	overflow, _ := syntheticGraph(t, 500, []int{500, 500, 500, 500})
	reject(t, overflow, catalogue)
	tooMany, ids := syntheticGraph(t, 501, []int{1})
	reject(t, tooMany, ids)
	one, ids := syntheticGraph(t, 1, []int{1})
	oneGraph, err := Decode(one, ids)
	if err != nil || !oneGraph.Allows("foreign", "WIFI", ids) {
		t.Fatal("single-hop route refused")
	}
}

func TestPerIntentSumDeduplicatesTemplatesButNeverSeparateOverflowingGroups(t *testing.T) {
	raw, catalogue := syntheticGraph(t, 16, []int{16, 16, 16})
	same := mutate(t, raw, func(doc map[string]any) {
		doc["groups"] = append(doc["groups"].([]any), map[string]any{"id": "second", "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"wide"}})
	})
	g, err := Decode(same, catalogue)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := g.IntentUpperBound("NON_RU"); n != 4096 {
		t.Fatal("shared template counted twice")
	}
	for _, grouped := range []bool{false, true} {
		over := mutate(t, raw, func(doc map[string]any) {
			doc["templates"] = append(doc["templates"].([]any), map[string]any{"id": "extra", "slots": [][]string{{catalogue[0]}}})
			if grouped {
				doc["groups"].([]any)[0].(map[string]any)["templates"] = []string{"wide", "extra"}
			} else {
				doc["groups"] = append(doc["groups"].([]any), map[string]any{"id": "second", "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"extra"}})
			}
		})
		reject(t, over, catalogue)
		if g, err := DecodeForPreview(over, catalogue); g != nil || err != ErrCandidateLimit {
			t.Fatal("editor did not receive the group or intent bound")
		}
	}
}

func TestUTF8ByteAndParserLimitsFailClosed(t *testing.T) {
	v := fixture(t).ValidCases[0]
	padded := append(bytes.Clone(v.Graph), bytes.Repeat([]byte{' '}, MaxBytes-len(v.Graph))...)
	if _, err := Decode(padded, v.Catalogue); err != nil {
		t.Fatal("exact byte boundary refused")
	}
	reject(t, append(padded, ' '), v.Catalogue)
	reject(t, nil, v.Catalogue)
	reject(t, bytes.Replace(v.Graph, []byte("entry"), []byte{0xff}, 1), v.Catalogue)
	reject(t, []byte(strings.Repeat("[", 18)+strings.Repeat("]", 18)), v.Catalogue)
	keys := []string{}
	for i := 0; i < 65; i++ {
		keys = append(keys, fmt.Sprintf("\"k%d\":1", i))
	}
	reject(t, []byte("{"+strings.Join(keys, ",")+"}"), v.Catalogue)
	reject(t, []byte("["+strings.Repeat("0,", 4096)+"0]"), v.Catalogue)
}

func TestDecodedGraphOwnsItsMetadataAndOnlyExposesRedactedDiagnostics(t *testing.T) {
	v := fixture(t).ValidCases[0]
	raw := bytes.Clone(v.Graph)
	ids := append([]string(nil), v.Catalogue...)
	g, err := Decode(raw, ids)
	if err != nil {
		t.Fatal(err)
	}
	clear(raw)
	clear(ids)
	original := g.GroupIDs()
	caller := g.GroupIDs()
	caller[0] = "changed"
	if !reflect.DeepEqual(original, g.GroupIDs()) || !g.Allows("foreign", "WIFI", []string{"exit-b"}) {
		t.Fatal("caller mutated decoded metadata")
	}
	for _, rendered := range []string{g.String(), fmt.Sprintf("%#v", g)} {
		if rendered != "RouteGraph(hops=5,groups=5)" {
			t.Fatal("diagnostics exposed route metadata")
		}
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 1000 {
				g.GroupIDs()
				g.UpperBound("foreign")
				g.IntentUpperBound("NON_RU")
				g.Allows("foreign", "WIFI", []string{"exit-b"})
			}
		}()
	}
	workers.Wait()
}

func TestStableIdentityRequiresASimpleBoundedPath(t *testing.T) {
	for _, path := range [][]string{nil, {}, {"a", "b", "c", "d", "e"}, {"a/b"}, {"A"}, {"a", "a"}} {
		if value, err := StablePathID(path); value != "" || err != ErrInvalid {
			t.Fatal("invalid path acquired an identity")
		}
	}
	one, _ := StablePathID([]string{"a", "b"})
	two, _ := StablePathID([]string{"b", "a"})
	if one == two {
		t.Fatal("hop order lost from identity")
	}
}

func FuzzRouteGraphDecode(f *testing.F) {
	v := fixture(f)
	f.Add([]byte(v.ValidCases[0].Graph))
	for _, c := range v.InvalidCases {
		f.Add([]byte(c.Raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		graph, err := Decode(raw, v.ValidCases[0].Catalogue)
		if err != nil {
			if graph != nil || err != ErrInvalid {
				t.Fatal("partial or unredacted decoder failure")
			}
			return
		}
		for _, id := range graph.GroupIDs() {
			if n, ok := graph.UpperBound(id); !ok || n < 1 || n > 4096 {
				t.Fatal("accepted graph has invalid bounds")
			}
		}
	})
}
