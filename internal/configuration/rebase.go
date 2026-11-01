package configuration

import (
	"context"
	"encoding/json"
	"sort"
)

type FieldValue struct {
	Present bool            `json:"present"`
	Value   json.RawMessage `json:"value,omitempty"`
}
type Conflict struct {
	Path   string     `json:"path"`
	Base   FieldValue `json:"base"`
	Local  FieldValue `json:"local"`
	Server FieldValue `json:"server"`
}

func (Conflict) String() string   { return "ConfigurationConflict([redacted])" }
func (Conflict) GoString() string { return "ConfigurationConflict([redacted])" }

type Rebased struct {
	Document  json.RawMessage `json:"document"`
	Conflicts []Conflict      `json:"conflicts"`
}

func (Rebased) String() string   { return "RebasedConfiguration([redacted])" }
func (Rebased) GoString() string { return "RebasedConfiguration([redacted])" }
func same(a any, af bool, b any, bf bool) bool {
	return af == bf && (!af || canonical(a) == canonical(b))
}
func fieldValue(v any, present bool) FieldValue {
	f := FieldValue{Present: present}
	if present {
		f.Value, _ = json.Marshal(v)
	}
	return f
}

// Rebase preserves unrelated server edits. Arrays remain atomic; a delete versus
// an independent modification produces an explicit base/local/server conflict.
// A conflicted document is for review only and is returned with ErrConflict.
func Rebase(ctx context.Context, base, local, server json.RawMessage, validate func(json.RawMessage) error) (Rebased, error) {
	result := Rebased{Conflicts: []Conflict{}}
	if ctx == nil || validate == nil {
		return result, ErrInvalid
	}
	var documents []map[string]any
	for _, raw := range []json.RawMessage{base, local, server} {
		if len(raw) > 262144 || validate(raw) != nil {
			return result, ErrInvalid
		}
		v, e := value(raw)
		if e != nil {
			return result, e
		}
		m, ok := v.(map[string]any)
		if !ok {
			return result, ErrInvalid
		}
		if _, e = leaves(m); e != nil {
			return result, e
		}
		documents = append(documents, m)
	}
	var merge func(any, bool, any, bool, any, bool, string, int) (any, bool, error)
	merge = func(b any, bf bool, l any, lf bool, s any, sf bool, p string, depth int) (any, bool, error) {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if depth > 16 || len(result.Conflicts) > 256 {
			return nil, false, ErrInvalid
		}
		if same(l, lf, b, bf) {
			return s, sf, nil
		}
		if same(s, sf, b, bf) || same(l, lf, s, sf) {
			return l, lf, nil
		}
		bm, bok := b.(map[string]any)
		lm, lok := l.(map[string]any)
		sm, sok := s.(map[string]any)
		if lok && sok && (!bf || bok) {
			all := map[string]bool{}
			for k := range bm {
				all[k] = true
			}
			for k := range lm {
				all[k] = true
			}
			for k := range sm {
				all[k] = true
			}
			keys := make([]string, 0, len(all))
			for k := range all {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out := map[string]any{}
			for _, k := range keys {
				bv, bf := bm[k]
				lv, lf := lm[k]
				sv, sf := sm[k]
				v, found, e := merge(bv, bf, lv, lf, sv, sf, p+"/"+k, depth+1)
				if e != nil {
					return nil, false, e
				}
				if found {
					out[k] = v
				}
			}
			return out, true, nil
		}
		result.Conflicts = append(result.Conflicts, Conflict{p, fieldValue(b, bf), fieldValue(l, lf), fieldValue(s, sf)})
		return s, sf, nil
	}
	merged, _, e := merge(documents[0], true, documents[1], true, documents[2], true, "", 0)
	if e != nil {
		return result, e
	}
	if len(result.Conflicts) > 256 {
		return result, ErrInvalid
	}
	raw, e := json.Marshal(merged)
	if e != nil || len(raw) > 262144 || validate(raw) != nil {
		return result, ErrInvalid
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	result.Document = raw
	if len(result.Conflicts) > 0 {
		return result, ErrConflict
	}
	return result, nil
}
