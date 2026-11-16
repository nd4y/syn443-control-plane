package routegraph

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPublicCandidateSeparatesDeclaredExitFromGroupIntent(t *testing.T) {
	var public, fenced validVector
	for _, vector := range fixture(t).ValidCases {
		switch vector.Name {
		case "public-candidate-shared-exit-class":
			public = vector
		case "public-candidate-transit-null-and-capability-fences":
			fenced = vector
		}
	}
	if len(public.Graph) == 0 || len(fenced.Graph) == 0 {
		t.Fatal("missing shared public-candidate conformance inputs")
	}
	g, e := Decode(public.Graph, public.Catalogue)
	if e != nil || !reflect.DeepEqual(g.GroupIDs(), []string{"foreign", "inside", "ru"}) {
		t.Fatal("public candidate changed the group declarations", e)
	}
	if _, ok := g.IntentUpperBound("PUBLIC"); ok {
		t.Fatal("PUBLIC became an observed/group exit intent")
	}
	for mode := range modes {
		if !g.Allows("ru", mode, []string{"public"}) || !g.Allows("foreign", mode, []string{"public"}) || g.Allows("inside", mode, []string{"public"}) {
			t.Fatal("the same public candidate did not preserve exit-intent separation")
		}
	}
	bound, e := Decode(fenced.Graph, fenced.Catalogue)
	if e != nil {
		t.Fatal(e)
	}
	for mode := range modes {
		for _, group := range []string{"ru", "foreign", "inside"} {
			if bound.Allows(group, mode, []string{"no-tcp"}) || bound.Allows(group, mode, []string{"transit"}) {
				t.Fatal("PUBLIC or null bypassed the existing TCP/terminal capability fence")
			}
		}
	}
	var node any
	if e := json.Unmarshal(public.Graph, &node); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(node)
	if e != nil {
		t.Fatal(e)
	}
	for _, malformed := range []string{
		strings.Replace(string(raw), `"intent":"RU"`, `"intent":"PUBLIC"`, 1),
		strings.Replace(string(raw), `"exitClass":"PUBLIC"`, `"exitClass":"PUBLIC_INTERNAL"`, 1),
		strings.Replace(string(raw), `"exitClass":"PUBLIC"`, `"exitClass":null,"publicCandidate":true`, 1),
	} {
		if decoded, e := Decode([]byte(malformed), public.Catalogue); decoded != nil || e != ErrInvalid {
			t.Fatal("unknown or ambiguous public metadata acquired authority")
		}
	}
	nullExit := strings.Replace(string(raw), `"exitClass":"PUBLIC"`, `"exitClass":null`, 1)
	transit, e := Decode([]byte(nullExit), public.Catalogue)
	if e != nil {
		t.Fatal(e)
	}
	for _, group := range transit.GroupIDs() {
		if transit.Allows(group, "WIFI", []string{"public"}) {
			t.Fatal("a nullable transit exit became route-selection eligibility")
		}
	}
}
