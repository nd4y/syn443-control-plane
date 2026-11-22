package configuration

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
)

// MergeNetworkPlan checks the document the device will receive and the individual
// edits the control plane retains. A later override must not make an unrelated
// field portable. Layers may still supply different parts of a required object.
func MergeNetworkPlan(ctx context.Context, layers []Layer) (Effective, NetworkPlan, error) {
	var plan NetworkPlan
	effective, err := Merge(ctx, layers, func(raw json.RawMessage) error {
		var err error
		plan, err = DecodeNetworkPlan(raw)
		return err
	})
	if err != nil {
		return Effective{}, NetworkPlan{}, err
	}
	for _, layer := range layers {
		for _, change := range layer.Changes {
			if err := checkPortableField(ctx, change.Path, change.Value); err != nil {
				return Effective{}, NetworkPlan{}, err
			}
		}
		for _, permission := range layer.Permissions {
			if err := checkPortableField(ctx, permission.Path, permission.Choices...); err != nil {
				return Effective{}, NetworkPlan{}, err
			}
		}
	}
	return effective, plan, nil
}

// Map entries are user-defined IDs. Struct members must match their wire names,
// and arrays are replaced as a whole under the existing patch contract.
func portableMember(typ reflect.Type, field string) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Map:
		return typ.Elem()
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			member := typ.Field(i)
			name, _, _ := strings.Cut(member.Tag.Get("json"), ",")
			if name == "" {
				name = member.Name
			}
			if member.IsExported() && name != "-" && name == field {
				return member.Type
			}
		}
	}
	return nil
}

func checkPortableField(ctx context.Context, field string, values ...json.RawMessage) error {
	parts, err := path(field)
	if err != nil {
		return err
	}
	typ := reflect.TypeFor[NetworkPlan]()
	for _, part := range parts {
		typ = portableMember(typ, part)
		if typ == nil {
			return ErrInvalid
		}
	}
	for _, raw := range values {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(raw) == 0 {
			continue
		}
		fragment, err := value(raw)
		if err != nil || !portableValue(typ, fragment) {
			return ErrInvalid
		}
	}
	return ctx.Err()
}

// Check only JSON member names and kinds in individual layers. Numeric lexemes,
// partial objects and method-specific semantics are resolved by the complete
// effective plan. Never rewrite the original bytes stored in the layer.
func portableValue(typ reflect.Type, fragment any) bool {
	if fragment == nil {
		return true
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	kind := typ.Kind()
	switch v := fragment.(type) {
	case map[string]any:
		if kind != reflect.Struct && kind != reflect.Map {
			return false
		}
		for name, item := range v {
			child := portableMember(typ, name)
			if child == nil || !portableValue(child, item) {
				return false
			}
		}
		return true
	case []any:
		if kind != reflect.Slice && kind != reflect.Array {
			return false
		}
		for _, item := range v {
			if !portableValue(typ.Elem(), item) {
				return false
			}
		}
		return true
	case string:
		return kind == reflect.String
	case bool:
		return kind == reflect.Bool
	case json.Number:
		return kind >= reflect.Int && kind <= reflect.Float64
	default:
		return false
	}
}
