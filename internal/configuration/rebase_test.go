package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestThreeWayRebasePreservesIndependentChangesAndReportsTriples(t *testing.T) {
	ctx := context.Background()
	base := json.RawMessage(`{"dns":{"final":"direct"},"ui":{"theme":"dark"}}`)
	local := json.RawMessage(`{"dns":{"final":"proxy"},"ui":{"theme":"dark"}}`)
	server := json.RawMessage(`{"dns":{"final":"direct"},"ui":{"theme":"system"}}`)
	result, e := Rebase(ctx, base, local, server, supported)
	if e != nil || len(result.Conflicts) != 0 || !bytes.Equal(result.Document, []byte(`{"dns":{"final":"proxy"},"ui":{"theme":"system"}}`)) {
		t.Fatal("independent rebase", e)
	}
	server = []byte(`{"dns":{"final":"other"},"ui":{"theme":"system"}}`)
	result, e = Rebase(ctx, base, local, server, supported)
	if !errors.Is(e, ErrConflict) || len(result.Conflicts) != 1 {
		t.Fatal("concurrent field conflict lost", e)
	}
	conflict := result.Conflicts[0]
	if conflict.Path != "/dns/final" || string(conflict.Base.Value) != `"direct"` || string(conflict.Local.Value) != `"proxy"` || string(conflict.Server.Value) != `"other"` || !bytes.Contains(result.Document, []byte(`"other"`)) {
		t.Fatal("conflict triple/server baseline")
	}
	result, e = Rebase(ctx, base, local, local, supported)
	if e != nil || len(result.Conflicts) != 0 {
		t.Fatal("identical concurrent change conflicted", e)
	}
	result, e = Rebase(ctx, []byte(`{}`), []byte(`{"dns":{"a":1}}`), []byte(`{"dns":{"b":2}}`), supported)
	if e != nil || !bytes.Equal(result.Document, []byte(`{"dns":{"a":1,"b":2}}`)) {
		t.Fatal("independent object additions", e)
	}
	if bytes.Contains([]byte(fmt.Sprintf("%v %#v", result, conflict)), []byte("proxy")) {
		t.Fatal("conflict logging leaked values")
	}
}

func TestRebaseDeletionTypeAndOrderedArrayConflicts(t *testing.T) {
	for _, test := range []struct{ base, draft, server, path string }{{`{"dns":{"a":1}}`, `{}`, `{"dns":{"a":2}}`, "/dns"}, {`{"routes":["a","b"]}`, `{"routes":["b","a"]}`, `{"routes":["a"]}`, "/routes"}, {`{"mode":"direct"}`, `{"mode":{"value":"local"}}`, `{"mode":"other"}`, "/mode"}} {
		result, e := Rebase(context.Background(), []byte(test.base), []byte(test.draft), []byte(test.server), supported)
		if !errors.Is(e, ErrConflict) || len(result.Conflicts) != 1 || result.Conflicts[0].Path != test.path {
			t.Fatal("atomic conflict", e)
		}
	}
	result, e := Rebase(context.Background(), []byte(`{"mode":"direct"}`), []byte(`{"mode":"direct"}`), []byte(`{}`), supported)
	if e != nil || string(result.Document) != "{}" {
		t.Fatal("unchanged local blocked server deletion", e)
	}
}

func TestRebaseBudgetsCancellationAndUnsupportedSettings(t *testing.T) {
	ctx := context.Background()
	valid := json.RawMessage(`{"mode":"direct"}`)
	for _, bad := range [][]byte{[]byte(`[]`), []byte(`{"mode":null}`), []byte(`{"mode":"a","mode":"b"}`), bytes.Repeat([]byte{'x'}, 262145)} {
		if _, e := Rebase(ctx, bad, valid, valid, supported); e == nil {
			t.Fatal("invalid base document accepted")
		}
	}
	if _, e := Rebase(ctx, valid, valid, valid, nil); e == nil {
		t.Fatal("schema validator omitted")
	}
	if _, e := Rebase(ctx, valid, []byte(`{"runtime":"not a setting"}`), valid, supported); e == nil {
		t.Fatal("unsupported setting published")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := Rebase(cancelled, valid, valid, valid, supported); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled rebase produced candidate")
	}
	during, cancel := context.WithCancel(ctx)
	if _, e := Rebase(during, valid, valid, valid, func(json.RawMessage) error { cancel(); return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal("late cancellation lost")
	}
	makeDoc := func(value int) []byte {
		root := map[string]any{}
		for _, group := range []string{"a", "b", "c"} {
			fields := map[string]any{}
			for i := 0; i < 100; i++ {
				fields[fmt.Sprintf("f%d", i)] = value
			}
			root[group] = fields
		}
		raw, _ := json.Marshal(map[string]any{"routes": root})
		return raw
	}
	if _, e := Rebase(ctx, makeDoc(0), makeDoc(1), makeDoc(2), supported); !errors.Is(e, ErrInvalid) {
		t.Fatal("conflict result exceeded bounded size")
	}
}
