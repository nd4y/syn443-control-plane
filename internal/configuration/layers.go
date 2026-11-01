// Package configuration merges bounded declarative settings. It has no network,
// device state, credentials, command evaluation or publication authority.
package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

var ErrInvalid = errors.New("configuration_invalid")
var ErrConflict = errors.New("configuration_conflict")
var ErrLocked = errors.New("configuration_field_locked")
var id = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var key = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

func DecodeLayers(raw []byte) ([]Layer, error) {
	var layers []Layer
	if len(raw) > 524288 || identity.DecodeConfiguration(raw, &layers) != nil || len(layers) < 1 || len(layers) > 20 {
		return nil, ErrInvalid
	}
	return layers, nil
}

type Change struct {
	Path      string          `json:"path"`
	Operation string          `json:"operation"`
	Value     json.RawMessage `json:"value,omitempty"`
}
type Permission struct {
	Path    string            `json:"path"`
	Mode    string            `json:"mode"`
	Choices []json.RawMessage `json:"choices,omitempty"`
	Minimum *int64            `json:"minimum,omitempty"`
	Maximum *int64            `json:"maximum,omitempty"`
}
type Layer struct {
	ID          string       `json:"id"`
	Kind        string       `json:"kind"`
	Priority    int          `json:"priority"`
	Revision    int64        `json:"revision"`
	Changes     []Change     `json:"changes"`
	Permissions []Permission `json:"permissions"`
}
type Origin struct {
	LayerID  string `json:"layerId"`
	Kind     string `json:"kind"`
	Revision int64  `json:"revision"`
}
type Restriction struct {
	Permission Permission `json:"permission"`
	Origin     Origin     `json:"origin"`
}
type groupClaim struct{ Signature, LayerID string }
type Effective struct {
	Document     json.RawMessage   `json:"document"`
	Fields       map[string]Origin `json:"fields"`
	Restrictions []Restriction     `json:"restrictions"`
}

func (Effective) String() string   { return "EffectiveConfiguration([redacted])" }
func (Effective) GoString() string { return "EffectiveConfiguration([redacted])" }
func (Layer) String() string       { return "ConfigurationLayer([redacted])" }
func (Layer) GoString() string     { return "ConfigurationLayer([redacted])" }
func path(raw string) ([]string, error) {
	if len(raw) < 2 || len(raw) > 512 || !strings.HasPrefix(raw, "/") {
		return nil, ErrInvalid
	}
	parts := strings.Split(raw[1:], "/")
	if len(parts) > 16 {
		return nil, ErrInvalid
	}
	for _, part := range parts {
		if !key.MatchString(part) {
			return nil, ErrInvalid
		}
	}
	return parts, nil
}
func value(raw json.RawMessage) (any, error) {
	var v any
	var holder struct {
		Value json.RawMessage `json:"value"`
	}
	wrapped := append([]byte(`{"value":`), raw...)
	wrapped = append(wrapped, '}')
	if identity.DecodeConfiguration(wrapped, &holder) != nil {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&v) != nil || v == nil {
		return nil, ErrInvalid
	}
	if !boundedNumbers(v) {
		return nil, ErrInvalid
	}
	return v, nil
}
func boundedNumbers(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case json.Number:
		raw := x.String()
		if len(raw) > 64 {
			return false
		}
		if at := strings.IndexAny(raw, "eE"); at >= 0 {
			exponent, e := strconv.Atoi(raw[at+1:])
			if e != nil || exponent < -308 || exponent > 308 {
				return false
			}
		}
		number, e := strconv.ParseFloat(raw, 64)
		return e == nil && !math.IsInf(number, 0) && !math.IsNaN(number) && math.Abs(number) <= 9007199254740991
	case map[string]any:
		for _, v := range x {
			if !boundedNumbers(v) {
				return false
			}
		}
	case []any:
		for _, v := range x {
			if !boundedNumbers(v) {
				return false
			}
		}
	}
	return true
}
func canonical(v any) string { raw, _ := json.Marshal(v); return string(raw) }
func lookup(root map[string]any, parts []string) (any, bool) {
	var node any = root
	for _, part := range parts {
		m, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		node, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return node, true
}
func apply(root map[string]any, change Change) error {
	parts, e := path(change.Path)
	if e != nil {
		return e
	}
	m := root
	for _, part := range parts[:len(parts)-1] {
		next, exists := m[part]
		if !exists {
			if change.Operation == "delete" {
				return nil
			}
			child := map[string]any{}
			m[part] = child
			m = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		m = child
	}
	last := parts[len(parts)-1]
	switch change.Operation {
	case "set":
		v, e := value(change.Value)
		if e != nil {
			return e
		}
		m[last] = v
	case "delete":
		if len(change.Value) != 0 {
			return ErrInvalid
		}
		delete(m, last)
	default:
		return ErrInvalid
	}
	return nil
}
func leaves(root map[string]any) (map[string]any, error) {
	result := map[string]any{}
	var walk func(any, string, int) error
	walk = func(v any, p string, depth int) error {
		if depth > 16 || len(result) > 4096 {
			return ErrInvalid
		}
		if m, ok := v.(map[string]any); ok && len(m) > 0 {
			for k, child := range m {
				if !key.MatchString(k) {
					return ErrInvalid
				}
				if e := walk(child, p+"/"+k, depth+1); e != nil {
					return e
				}
			}
		} else {
			result[p] = v
		}
		return nil
	}
	if e := walk(root, "", 0); e != nil {
		return nil, e
	}
	delete(result, "")
	if len(result) > 4096 {
		return nil, ErrInvalid
	}
	return result, nil
}
func contains(parent, child string) bool {
	return parent == child || strings.HasPrefix(child, parent+"/")
}
func scalarRange(v any, minimum, maximum *int64) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	integer, e := n.Int64()
	return e == nil && (minimum == nil || integer >= *minimum) && (maximum == nil || integer <= *maximum)
}
func check(permission Permission, v any, found bool) bool {
	switch permission.Mode {
	case "locked":
		return false
	case "free":
		return true
	case "choice":
		if !found {
			return false
		}
		for _, raw := range permission.Choices {
			option, e := value(raw)
			if e == nil && canonical(option) == canonical(v) {
				return true
			}
		}
		return false
	case "range":
		return found && scalarRange(v, permission.Minimum, permission.Maximum)
	}
	return false
}
func (p Permission) Validate() error {
	if _, e := path(p.Path); e != nil {
		return e
	}
	switch p.Mode {
	case "locked", "free":
		if len(p.Choices) != 0 || p.Minimum != nil || p.Maximum != nil {
			return ErrInvalid
		}
	case "choice":
		if len(p.Choices) < 1 || len(p.Choices) > 32 || p.Minimum != nil || p.Maximum != nil {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, raw := range p.Choices {
			v, e := value(raw)
			if e != nil || seen[canonical(v)] {
				return ErrInvalid
			}
			seen[canonical(v)] = true
		}
	case "range":
		if len(p.Choices) != 0 || p.Minimum == nil && p.Maximum == nil || p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func kindOrder(kind string) int {
	switch kind {
	case "template":
		return 0
	case "group":
		return 1
	case "user":
		return 2
	case "device":
		return 3
	case "local":
		return 4
	}
	return -1
}

// Merge is deterministic under input permutation. The caller must provide the
// supported settings schema; a generic merge never turns arbitrary JSON into a
// publishable client configuration. Arrays are atomic ordered values.
func Merge(ctx context.Context, input []Layer, validate func(json.RawMessage) error) (Effective, error) {
	result := Effective{Fields: map[string]Origin{}, Restrictions: []Restriction{}}
	if ctx == nil || len(input) < 1 || len(input) > 20 || validate == nil {
		return result, ErrInvalid
	}
	layers := append([]Layer(nil), input...)
	seen := map[string]bool{}
	kinds := map[string]int{}
	changes, permissions := 0, 0
	for index, l := range layers {
		encoded, e := json.Marshal(l)
		order := kindOrder(l.Kind)
		changes += len(l.Changes)
		permissions += len(l.Permissions)
		if e != nil || changes > 512 || permissions > 256 || !id.MatchString(l.ID) || seen[l.ID] || order < 0 || l.Priority < -10000 || l.Priority > 10000 || l.Kind != "group" && l.Priority != 0 || l.Revision < 1 || l.Revision > 9007199254740991 || len(l.Changes) > 256 || len(l.Permissions) > 256 || len(encoded) > 262144 {
			return result, ErrInvalid
		}
		var owned Layer
		if json.Unmarshal(encoded, &owned) != nil {
			return result, ErrInvalid
		}
		layers[index] = owned
		seen[l.ID] = true
		kinds[l.Kind]++
		if l.Kind != "group" && kinds[l.Kind] > 1 || l.Kind == "group" && kinds[l.Kind] > 16 {
			return result, ErrInvalid
		}
	}
	if kinds["template"] != 1 {
		return result, ErrInvalid
	}
	sort.Slice(layers, func(i, j int) bool {
		a, b := layers[i], layers[j]
		if kindOrder(a.Kind) != kindOrder(b.Kind) {
			return kindOrder(a.Kind) < kindOrder(b.Kind)
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.ID < b.ID
	})
	root := map[string]any{}
	groupWrites := map[int]map[string]groupClaim{}
	for _, l := range layers {
		origin := Origin{l.ID, l.Kind, l.Revision}
		layerPaths := map[string]bool{}
		for _, change := range l.Changes {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			_, e := path(change.Path)
			if e != nil || layerPaths[change.Path] {
				return result, ErrInvalid
			}
			for previous := range layerPaths {
				if contains(previous, change.Path) || contains(change.Path, previous) {
					return result, ErrInvalid
				}
			}
			layerPaths[change.Path] = true
			before, _ := json.Marshal(root)
			var previous map[string]any
			decoder := json.NewDecoder(bytes.NewReader(before))
			decoder.UseNumber()
			decoder.Decode(&previous)
			if e = apply(root, change); e != nil {
				return result, e
			}
			after, e := json.Marshal(root)
			if e != nil || len(after) > 262144 {
				return result, ErrInvalid
			}
			oldLeaves, e := leaves(previous)
			if e != nil {
				return result, e
			}
			newLeaves, e := leaves(root)
			if e != nil {
				return result, e
			}
			for _, restriction := range result.Restrictions {
				p := restriction.Permission
				if !contains(change.Path, p.Path) && !contains(p.Path, change.Path) {
					continue
				}
				pParts, _ := path(p.Path)
				old, oldFound := lookup(previous, pParts)
				current, found := lookup(root, pParts)
				if oldFound == found && canonical(old) == canonical(current) {
					continue
				}
				if p.Mode == "locked" || !check(p, current, found) {
					return result, ErrLocked
				}
			}
			if l.Kind == "local" {
				permitted := false
				for _, r := range result.Restrictions {
					if contains(r.Permission.Path, change.Path) && r.Permission.Mode != "locked" {
						permitted = true
					}
				}
				if !permitted {
					return result, ErrLocked
				}
			}
			all := map[string]bool{}
			for p := range oldLeaves {
				all[p] = true
			}
			for p := range newLeaves {
				all[p] = true
			}
			touched := false
			for p := range all {
				old, oldOK := oldLeaves[p]
				current, ok := newLeaves[p]
				changed := oldOK != ok || canonical(old) != canonical(current)
				explicit := contains(change.Path, p) || changed && contains(p, change.Path)
				if !explicit {
					continue
				}
				touched = true
				if l.Kind == "group" {
					parts, _ := path(p)
					_, stillExists := lookup(root, parts)
					// Replacing an empty object by a child is a container change,
					// not a claim that the whole parent was deleted.
					if !ok && stillExists {
						delete(result.Fields, p)
						continue
					}
					writes := groupWrites[l.Priority]
					if writes == nil {
						writes = map[string]groupClaim{}
						groupWrites[l.Priority] = writes
					}
					signature := "deleted"
					if ok {
						signature = "set/" + canonical(current)
					}
					if e = groupWrite(writes, p, signature, l.ID); e != nil {
						return result, e
					}
				}
				if ok {
					result.Fields[p] = origin
				} else {
					delete(result.Fields, p)
				}
			}
			if l.Kind == "group" && !touched && change.Operation == "delete" {
				writes := groupWrites[l.Priority]
				if writes == nil {
					writes = map[string]groupClaim{}
					groupWrites[l.Priority] = writes
				}
				if e = groupWrite(writes, change.Path, "deleted", l.ID); e != nil {
					return result, e
				}
			}
		}
		for _, permission := range l.Permissions {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			if permission.Validate() != nil {
				return result, ErrInvalid
			}
			if l.Kind != "template" && permission.Mode != "locked" {
				inherited := false
				for _, r := range result.Restrictions {
					if contains(r.Permission.Path, permission.Path) && r.Permission.Mode != "locked" {
						inherited = true
					}
					if r.Permission.Mode == "locked" && (contains(r.Permission.Path, permission.Path) || contains(permission.Path, r.Permission.Path)) {
						return result, ErrLocked
					}
				}
				if !inherited {
					return result, ErrLocked
				}
			}
			parts, _ := path(permission.Path)
			current, found := lookup(root, parts)
			if !found || permission.Mode != "locked" && !check(permission, current, true) {
				return result, ErrInvalid
			}
			result.Restrictions = append(result.Restrictions, Restriction{permission, origin})
		}
	}
	raw, e := json.Marshal(root)
	if e != nil || len(raw) > 262144 || validate(raw) != nil {
		return result, ErrInvalid
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	result.Document = raw
	return result, nil
}
func groupWrite(writes map[string]groupClaim, p, signature, layerID string) error {
	for previous, old := range writes {
		if old.LayerID == layerID {
			continue
		}
		if previous == p && old.Signature != signature {
			return ErrConflict
		}
		if previous != p && (contains(previous, p) || contains(p, previous)) && (old.Signature != "deleted" || signature != "deleted") {
			return ErrConflict
		}
	}
	writes[p] = groupClaim{signature, layerID}
	return nil
}
