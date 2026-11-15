package routegraph

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestGroupInfoReturnsOwnedBoundedDeclarations(t *testing.T) {
	raw := []byte(`{"schemaVersion":1,"hops":[{"id":"entry","entryModes":["WIFI"],"exitClass":null,"features":["TCP","IPV4"]},{"id":"exit","entryModes":["WIFI"],"exitClass":"INTERNAL","features":["TCP","IPV4"]}],"edges":[{"from":"entry","to":"exit","features":["TCP","IPV4"]}],"templates":[{"id":"two","slots":[["entry"],["exit"]]},{"id":"one","slots":[["exit"]]}],"groups":[{"id":"inside","intent":"INTERNAL","features":["TCP","IPV4"],"templates":["two","one"]}]}`)
	graph, e := Decode(raw, []string{"entry", "exit"})
	if e != nil {
		t.Fatal(e)
	}
	info, ok := graph.GroupInfo("inside")
	if !ok || info.Intent != "INTERNAL" || info.UpperBound != 2 || info.MaxHops != 2 || !reflect.DeepEqual(info.Features, []string{"IPV4", "TCP"}) {
		t.Fatal("incorrect declaration view", info, ok)
	}
	info.Features[0] = "UDP"
	again, ok := graph.GroupInfo("inside")
	if !ok || !reflect.DeepEqual(again.Features, []string{"IPV4", "TCP"}) || !graph.Allows("inside", "WIFI", []string{"entry", "exit"}) || !graph.Allows("inside", "WIFI", []string{"exit"}) {
		t.Fatal("returned view changed graph authority")
	}
	if info, ok := graph.GroupInfo("unknown"); ok || info.Intent != "" || info.MaxHops != 0 || len(info.Features) != 0 {
		t.Fatal("unknown group gained declarations")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", info, info), "INTERNAL") {
		t.Fatal("group diagnostics are not redacted")
	}
}
