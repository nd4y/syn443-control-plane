// Package routegraph validates finite route metadata, never network authority.
package routegraph

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxBytes = 262144

var ErrInvalid = errors.New("invalid route graph")
var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var modes = map[string]bool{"HOME_WIFI": true, "WIFI": true, "CELLULAR_RESTRICTED": true, "CELLULAR": true}
var intents = map[string]bool{"RU": true, "NON_RU": true, "INTERNAL": true}
var terminalExits = map[string]bool{"RU": true, "NON_RU": true, "INTERNAL": true, "PUBLIC": true}
var features = map[string]bool{"TCP": true, "UDP": true, "IPV4": true, "IPV6": true, "ICMP": true}

type hop struct {
	modes, features map[string]bool
	exit            string
}
type edgeKey struct{ from, to string }
type template struct {
	slots [][]string
	bound int
}
type group struct {
	intent    string
	features  map[string]bool
	templates []string
	bound     int
}

// Graph is immutable after Decode. Its predicates establish only declarations;
// a fresh context-bound native probe is still required before route selection.
type Graph struct {
	hops        map[string]hop
	edges       map[edgeKey]map[string]bool
	templates   map[string]template
	groups      map[string]group
	intentBound map[string]int
}

func (g *Graph) String() string {
	return fmt.Sprintf("RouteGraph(hops=%d,groups=%d)", len(g.hops), len(g.groups))
}
func (g *Graph) GoString() string { return g.String() }

func object(value any, keys ...string) (map[string]any, bool) {
	v, ok := value.(map[string]any)
	if !ok || len(v) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := v[key]; !ok {
			return nil, false
		}
	}
	return v, true
}
func array(value any, min, max int) ([]any, bool) {
	v, ok := value.([]any)
	return v, ok && len(v) >= min && len(v) <= max
}
func id(value any) (string, bool) {
	v, ok := value.(string)
	return v, ok && identifier.MatchString(v)
}
func values(value any, allowed map[string]bool, min, max int) (map[string]bool, bool) {
	v, ok := array(value, min, max)
	if !ok {
		return nil, false
	}
	out := make(map[string]bool, len(v))
	for _, item := range v {
		s, ok := item.(string)
		if !ok || !allowed[s] || out[s] {
			return nil, false
		}
		out[s] = true
	}
	return out, true
}
func ids(value any, min, max int) ([]string, bool) {
	v, ok := array(value, min, max)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(v))
	seen := map[string]bool{}
	for _, item := range v {
		s, ok := id(item)
		if !ok || seen[s] {
			return nil, false
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, true
}
func contains(actual, required map[string]bool) bool {
	for value := range required {
		if !actual[value] {
			return false
		}
	}
	return true
}

// read preserves escaped duplicate keys before decoding could discard them.
func read(d *json.Decoder, depth int) (any, bool) {
	if depth > 16 {
		return nil, false
	}
	token, err := d.Token()
	if err != nil {
		return nil, false
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, true
	}
	switch delim {
	case '{':
		out := map[string]any{}
		for d.More() {
			keyToken, err := d.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || len(out) == 64 {
				return nil, false
			}
			if _, exists := out[key]; exists {
				return nil, false
			}
			value, ok := read(d, depth+1)
			if !ok {
				return nil, false
			}
			out[key] = value
		}
		end, err := d.Token()
		return out, err == nil && end == json.Delim('}')
	case '[':
		out := make([]any, 0)
		for d.More() {
			if len(out) == 4096 {
				return nil, false
			}
			value, ok := read(d, depth+1)
			if !ok {
				return nil, false
			}
			out = append(out, value)
		}
		end, err := d.Token()
		return out, err == nil && end == json.Delim(']')
	default:
		return nil, false
	}
}

// Decode requires the independently authorized catalogue IDs, not IDs supplied
// by the metadata as a substitute for resolving profile ownership/dependencies.
func Decode(raw []byte, catalogue []string) (*Graph, error) {
	bad := func() (*Graph, error) { return nil, ErrInvalid }
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) || len(catalogue) < 1 || len(catalogue) > 500 {
		return bad()
	}
	known := make(map[string]bool, len(catalogue))
	for _, name := range catalogue {
		if !identifier.MatchString(name) || known[name] {
			return bad()
		}
		known[name] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, ok := read(d, 0)
	if !ok {
		return bad()
	}
	if _, err := d.Token(); err != io.EOF {
		return bad()
	}
	root, ok := object(value, "schemaVersion", "hops", "edges", "templates", "groups")
	if !ok || root["schemaVersion"] != json.Number("1") {
		return bad()
	}
	g := &Graph{hops: map[string]hop{}, edges: map[edgeKey]map[string]bool{}, templates: map[string]template{}, groups: map[string]group{}, intentBound: map[string]int{}}
	hops, ok := array(root["hops"], 1, 500)
	if !ok || len(hops) != len(known) {
		return bad()
	}
	for _, value := range hops {
		row, ok := object(value, "id", "entryModes", "exitClass", "features")
		if !ok {
			return bad()
		}
		name, ok := id(row["id"])
		if !ok || !known[name] {
			return bad()
		}
		if _, exists := g.hops[name]; exists {
			return bad()
		}
		entry, ok := values(row["entryModes"], modes, 0, 4)
		if !ok {
			return bad()
		}
		capabilities, ok := values(row["features"], features, 1, 5)
		if !ok {
			return bad()
		}
		exit := ""
		if row["exitClass"] != nil {
			var ok bool
			exit, ok = row["exitClass"].(string)
			if !ok || !terminalExits[exit] {
				return bad()
			}
		}
		g.hops[name] = hop{entry, capabilities, exit}
	}
	edges, ok := array(root["edges"], 0, 4096)
	if !ok {
		return bad()
	}
	for _, value := range edges {
		row, ok := object(value, "from", "to", "features")
		if !ok {
			return bad()
		}
		from, a := id(row["from"])
		to, b := id(row["to"])
		first, c := g.hops[from]
		last, e := g.hops[to]
		if !a || !b || !c || !e || from == to {
			return bad()
		}
		key := edgeKey{from, to}
		if _, exists := g.edges[key]; exists {
			return bad()
		}
		capabilities, ok := values(row["features"], features, 1, 5)
		if !ok || !contains(first.features, capabilities) || !contains(last.features, capabilities) {
			return bad()
		}
		g.edges[key] = capabilities
	}
	templates, ok := array(root["templates"], 1, 64)
	if !ok {
		return bad()
	}
	for _, value := range templates {
		row, ok := object(value, "id", "slots")
		if !ok {
			return bad()
		}
		name, ok := id(row["id"])
		if !ok {
			return bad()
		}
		if _, exists := g.templates[name]; exists {
			return bad()
		}
		slots, ok := array(row["slots"], 1, 4)
		if !ok {
			return bad()
		}
		t := template{bound: 1}
		for _, value := range slots {
			choices, ok := ids(value, 1, 500)
			if !ok || len(choices) > 4096/t.bound {
				return bad()
			}
			for _, name := range choices {
				if _, exists := g.hops[name]; !exists {
					return bad()
				}
			}
			sort.Strings(choices)
			t.slots = append(t.slots, choices)
			t.bound *= len(choices)
		}
		g.templates[name] = t
	}
	groups, ok := array(root["groups"], 1, 16)
	if !ok {
		return bad()
	}
	intentTemplates := map[string]map[string]bool{}
	for _, value := range groups {
		row, ok := object(value, "id", "intent", "features", "templates")
		if !ok {
			return bad()
		}
		name, ok := id(row["id"])
		if !ok {
			return bad()
		}
		if _, exists := g.groups[name]; exists {
			return bad()
		}
		intent, ok := row["intent"].(string)
		if !ok || !intents[intent] {
			return bad()
		}
		required, ok := values(row["features"], features, 1, 5)
		if !ok {
			return bad()
		}
		references, ok := ids(row["templates"], 1, 64)
		if !ok {
			return bad()
		}
		bound := 0
		if intentTemplates[intent] == nil {
			intentTemplates[intent] = map[string]bool{}
		}
		for _, reference := range references {
			t, exists := g.templates[reference]
			if !exists || t.bound > 4096-bound {
				return bad()
			}
			bound += t.bound
			intentTemplates[intent][reference] = true
		}
		sort.Strings(references)
		g.groups[name] = group{intent, required, references, bound}
	}
	for intent, references := range intentTemplates {
		for reference := range references {
			bound := g.templates[reference].bound
			if bound > 4096-g.intentBound[intent] {
				return bad()
			}
			g.intentBound[intent] += bound
		}
	}
	return g, nil
}

// GroupInfo is an owned declaration view, never protocol/probe authority.
type GroupInfo struct {
	Intent              string
	Features            []string
	UpperBound, MaxHops int
}

func (GroupInfo) String() string     { return "RouteGroupInfo([redacted])" }
func (i GroupInfo) GoString() string { return i.String() }

func (g *Graph) GroupInfo(groupID string) (GroupInfo, bool) {
	row, ok := g.groups[groupID]
	if !ok {
		return GroupInfo{}, false
	}
	info := GroupInfo{Intent: row.intent, UpperBound: row.bound, Features: make([]string, 0, len(row.features))}
	for feature := range row.features {
		info.Features = append(info.Features, feature)
	}
	sort.Strings(info.Features)
	for _, id := range row.templates {
		if hops := len(g.templates[id].slots); hops > info.MaxHops {
			info.MaxHops = hops
		}
	}
	return info, true
}

func (g *Graph) GroupIDs() []string {
	out := make([]string, 0, len(g.groups))
	for name := range g.groups {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
func (g *Graph) UpperBound(groupID string) (int, bool) {
	row, ok := g.groups[groupID]
	return row.bound, ok
}
func (g *Graph) IntentUpperBound(intent string) (int, bool) {
	value, ok := g.intentBound[intent]
	return value, ok
}

// A public candidate is metadata eligibility for either public intent only.
func declaresExit(exit, intent string) bool {
	return exit == intent || exit == "PUBLIC" && (intent == "RU" || intent == "NON_RU")
}

// Allows is a static declaration predicate. It cannot grant a selection proof.
func (g *Graph) Allows(groupID, mode string, path []string) bool {
	row, ok := g.groups[groupID]
	if !ok || !modes[mode] || len(path) < 1 || len(path) > 4 {
		return false
	}
	for i, name := range path {
		current, exists := g.hops[name]
		if !exists || !contains(current.features, row.features) {
			return false
		}
		for j := 0; j < i; j++ {
			if path[j] == name {
				return false
			}
		}
		if i == 0 && !current.modes[mode] || i == len(path)-1 && !declaresExit(current.exit, row.intent) {
			return false
		}
		if i > 0 && !contains(g.edges[edgeKey{path[i-1], name}], row.features) {
			return false
		}
	}
	for _, name := range row.templates {
		slots := g.templates[name].slots
		if len(slots) != len(path) {
			continue
		}
		match := true
		for i, choices := range slots {
			j := sort.SearchStrings(choices, path[i])
			if j == len(choices) || choices[j] != path[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// StablePathID deliberately carries no authority or transport credentials.
func StablePathID(path []string) (string, error) {
	if len(path) < 1 || len(path) > 4 {
		return "", ErrInvalid
	}
	seen := map[string]bool{}
	for _, name := range path {
		if !identifier.MatchString(name) || seen[name] {
			return "", ErrInvalid
		}
		seen[name] = true
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(path, "/")))), nil
}
