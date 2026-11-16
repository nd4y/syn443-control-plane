package configuration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/routegraph"
)

const MaxAdaptivePlanBytes = 196608

func adaptivePlanTag(tag string) bool {
	return adaptiveHopID.MatchString(tag) && !strings.Contains(tag, ".") && graphTag(tag)
}

// AdaptivePlan is portable credential-free control data. Its large closed
// metadata/reference documents stay opaque to the ordinary128/256 JSON limits.
// Only the dedicated decoder below may interpret them; this is not an engine
// catalogue and carries neither normalized credentials nor probe authority.
type AdaptivePlan struct {
	MetadataB64 string            `json:"metadataB64"`
	BindingsB64 string            `json:"bindingsB64"`
	Groups      map[string]string `json:"groups"`
}

func (AdaptivePlan) String() string   { return "AdaptivePlan([redacted])" }
func (AdaptivePlan) GoString() string { return "AdaptivePlan([redacted])" }

// AdaptivePlanSnapshot owns its handoff. Graph is immutable and every returned
// buffer/map is copied, so further draft mutation cannot replace dependencies.
type AdaptivePlanSnapshot struct {
	metadata []byte
	bindings map[string]ProfileReference
	groups   map[string]string
	graph    *routegraph.Graph
}

func (*AdaptivePlanSnapshot) String() string     { return "AdaptivePlanSnapshot([redacted])" }
func (*AdaptivePlanSnapshot) GoString() string   { return "AdaptivePlanSnapshot([redacted])" }
func (s *AdaptivePlanSnapshot) Metadata() []byte { return append([]byte(nil), s.metadata...) }
func (s *AdaptivePlanSnapshot) Bindings() map[string]ProfileReference {
	out := make(map[string]ProfileReference, len(s.bindings))
	for hop, ref := range s.bindings {
		out[hop] = ref
	}
	return out
}
func (s *AdaptivePlanSnapshot) Groups() map[string]string {
	out := make(map[string]string, len(s.groups))
	for group, tag := range s.groups {
		out[group] = tag
	}
	return out
}
func (s *AdaptivePlanSnapshot) Graph() *routegraph.Graph { return s.graph }

func adaptiveBase64(raw string) ([]byte, error) {
	if len(raw) < 1 || len(raw) > MaxAdaptivePlanBytes {
		return nil, ErrInvalid
	}
	decoded, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	if e != nil || len(decoded) < 1 || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, ErrInvalid
	}
	return decoded, nil
}

// The exact canonical encoding is a JSON object sorted by hop ID, containing
// objects with lexicographically sorted profileId/sourceId string fields. A
// small token parser enforces the shape without widening any generic decoder:
// no nested container, null, unknown/case-folded/duplicate field or alias.
func adaptiveBindings(raw []byte) (map[string]ProfileReference, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return nil, ErrInvalid
	}
	refs := map[string]ProfileReference{}
	canonical := map[string]map[string]string{}
	seenRefs := map[ProfileReference]bool{}
	for d.More() {
		name, e := d.Token()
		hop, ok := name.(string)
		if e != nil || !ok || !adaptiveHopID.MatchString(hop) || len(refs) >= 500 {
			return nil, ErrInvalid
		}
		if _, exists := refs[hop]; exists {
			return nil, ErrInvalid
		}
		token, e := d.Token()
		if e != nil || token != json.Delim('{') {
			return nil, ErrInvalid
		}
		fields := map[string]string{}
		for d.More() {
			key, e := d.Token()
			field, ok := key.(string)
			if e != nil || !ok || field != "sourceId" && field != "profileId" {
				return nil, ErrInvalid
			}
			if _, exists := fields[field]; exists {
				return nil, ErrInvalid
			}
			value, e := d.Token()
			text, ok := value.(string)
			if e != nil || !ok {
				return nil, ErrInvalid
			}
			fields[field] = text
		}
		token, e = d.Token()
		if e != nil || token != json.Delim('}') || len(fields) != 2 || !adaptiveSourceID.MatchString(fields["sourceId"]) || !graphProfileID.MatchString(fields["profileId"]) {
			return nil, ErrInvalid
		}
		ref := ProfileReference{SourceID: fields["sourceId"], ProfileID: fields["profileId"]}
		if seenRefs[ref] {
			return nil, ErrInvalid
		}
		refs[hop], canonical[hop], seenRefs[ref] = ref, fields, true
	}
	last, e := d.Token()
	if e != nil || last != json.Delim('}') || len(refs) == 0 {
		return nil, ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	encoded, e := json.Marshal(canonical)
	if e != nil || !bytes.Equal(raw, encoded) {
		return nil, ErrInvalid
	}
	return refs, nil
}

// DecodeAdaptivePlan validates portable input only. Actual source selection,
// normalized profile compilation, capabilities and signed publication remain
// separate; a successful result cannot activate or select a route.
func DecodeAdaptivePlan(plan AdaptivePlan, static Graph) (*AdaptivePlanSnapshot, error) {
	if len(plan.MetadataB64) < 1 || len(plan.MetadataB64) > MaxAdaptivePlanBytes || len(plan.BindingsB64) < 1 || len(plan.BindingsB64) > MaxAdaptivePlanBytes || len(plan.Groups) < 1 || len(plan.Groups) > 16 {
		return nil, ErrInvalid
	}
	for group, tag := range plan.Groups {
		if !adaptiveHopID.MatchString(group) || !adaptivePlanTag(tag) {
			return nil, ErrInvalid
		}
	}
	encoded, e := json.Marshal(plan)
	if e != nil || len(encoded) > MaxAdaptivePlanBytes {
		return nil, ErrInvalid
	}
	metadata, e := adaptiveBase64(plan.MetadataB64)
	if e != nil {
		return nil, ErrInvalid
	}
	rawBindings, e := adaptiveBase64(plan.BindingsB64)
	if e != nil {
		return nil, ErrInvalid
	}
	bindings, e := adaptiveBindings(rawBindings)
	if e != nil {
		return nil, ErrInvalid
	}
	ids := make([]string, 0, len(bindings))
	for hop := range bindings {
		ids = append(ids, hop)
	}
	sort.Strings(ids)
	graph, e := routegraph.Decode(metadata, ids)
	if e != nil || len(graph.GroupIDs()) != len(plan.Groups) {
		return nil, ErrInvalid
	}
	groups := make(map[string]string, len(plan.Groups))
	seen := map[string]bool{}
	for _, group := range graph.GroupIDs() {
		tag, exists := plan.Groups[group]
		_, profile := static.Profiles[tag]
		_, chain := static.Chains[tag]
		_, balancer := static.Balancers[tag]
		if !exists || !adaptivePlanTag(tag) || seen[tag] || profile || chain || balancer || static.NetBird != nil && static.NetBird.Tag == tag {
			return nil, ErrInvalid
		}
		seen[tag], groups[group] = true, tag
	}
	return &AdaptivePlanSnapshot{metadata: metadata, bindings: bindings, groups: groups, graph: graph}, nil
}
