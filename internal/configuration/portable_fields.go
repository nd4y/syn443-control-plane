package configuration

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/identity"
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
func checkPortableField(ctx context.Context, field string, values ...json.RawMessage) error {
	parts, err := path(field)
	if err != nil {
		return err
	}
	typ := reflect.TypeFor[NetworkPlan]()
	for _, part := range parts {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		switch typ.Kind() {
		case reflect.Map:
			typ = typ.Elem()
		case reflect.Struct:
			var child reflect.Type
			for i := 0; i < typ.NumField(); i++ {
				member := typ.Field(i)
				name, _, _ := strings.Cut(member.Tag.Get("json"), ",")
				if member.IsExported() && name == part {
					child = member.Type
					break
				}
			}
			if child == nil {
				return ErrInvalid
			}
			typ = child
		default:
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
		if err != nil {
			return err
		}
		shape, err := json.Marshal(portableShape(fragment))
		if err != nil || identity.DecodeConfiguration(shape, reflect.New(typ).Interface()) != nil {
			return ErrInvalid
		}
	}
	return ctx.Err()
}

// Historical layers can use different numeric lexemes and fractional defaults
// superseded by a later layer. Check the JSON type here. The effective document
// still goes through the exact integer, range and semantic checks above.
func portableShape(fragment any) any {
	switch v := fragment.(type) {
	case json.Number:
		return 0
	case map[string]any:
		for name, item := range v {
			v[name] = portableShape(item)
		}
	case []any:
		for i, item := range v {
			v[i] = portableShape(item)
		}
	}
	return fragment
}
