// Package routecheck is a bounded value-only route check contract. It grants
// neither source authority nor a current successful network observation.
package routecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("route_check_invalid")
var identifier = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

const MaxBytes = 24000

type Check struct {
	Method            string `json:"method"`
	Target            string `json:"target"`
	ExpectedIP        string `json:"expected_ip,omitempty"`
	ExpectedExitClass string `json:"expected_exit_class,omitempty"`
}
type Plan struct {
	Outbound string   `json:"outbound"`
	Required bool     `json:"required"`
	Checks   []Check  `json:"checks,omitempty"`
	Profile  *Profile `json:"profile,omitempty"`
}
type Profile struct {
	SchemaVersion int      `json:"schemaVersion"`
	ID            string   `json:"id"`
	Revision      int64    `json:"revision"`
	DeadlineMs    int      `json:"deadlineMs"`
	Leaves        []Leaf   `json:"leaves"`
	Gates         []string `json:"gates"`
	Stages        []Expr   `json:"stages"`
}
type Leaf struct {
	ID    string `json:"id"`
	Check Check  `json:"check"`
}
type Expr struct {
	Leaf   string  `json:"leaf,omitempty"`
	All    []Expr  `json:"all,omitempty"`
	Any    []Expr  `json:"any,omitempty"`
	Quorum *Quorum `json:"quorum,omitempty"`
}
type Quorum struct {
	K  int    `json:"k"`
	Of []Expr `json:"of"`
}

func (Check) String() string     { return "OutboundCheck([redacted])" }
func (Check) GoString() string   { return "OutboundCheck([redacted])" }
func (Plan) String() string      { return "OutboundCheckPlan([redacted])" }
func (Plan) GoString() string    { return "OutboundCheckPlan([redacted])" }
func (Profile) String() string   { return "CheckProfile([redacted])" }
func (Profile) GoString() string { return "CheckProfile([redacted])" }
func (Leaf) String() string      { return "CheckLeaf([redacted])" }
func (Leaf) GoString() string    { return "CheckLeaf([redacted])" }
func (Expr) String() string      { return "CheckExpr([redacted])" }
func (Expr) GoString() string    { return "CheckExpr([redacted])" }
func (Quorum) String() string    { return "CheckQuorum([redacted])" }
func (Quorum) GoString() string  { return "CheckQuorum([redacted])" }

// strict checks the complete tree before encoding/json can allocate recursive
// typed values. Its limits are local and do not widen any identity decoder.
func strict(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	remaining := 4096
	var read func(int) error
	read = func(depth int) error {
		remaining--
		if depth > 16 || remaining < 0 {
			return ErrInvalid
		}
		v, e := d.Token()
		if e != nil || v == nil {
			return ErrInvalid
		}
		switch x := v.(type) {
		case string:
			if len(x) > 2048 {
				return ErrInvalid
			}
		case json.Delim:
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] || len(seen) >= 128 || len(s) > 256 {
						return ErrInvalid
					}
					seen[s] = true
					if read(depth+1) != nil {
						return ErrInvalid
					}
				}
				v, e = d.Token()
				if e != nil || v != json.Delim('}') {
					return ErrInvalid
				}
			case '[':
				n := 0
				for d.More() {
					n++
					if n > 256 || read(depth+1) != nil {
						return ErrInvalid
					}
				}
				v, e = d.Token()
				if e != nil || v != json.Delim(']') {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
		return nil
	}
	if read(0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}

func object(raw []byte, allowed, required string) (map[string]json.RawMessage, error) {
	if strict(raw) != nil {
		return nil, ErrInvalid
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, ErrInvalid
	}
	for k := range m {
		if !strings.Contains(" "+allowed+" ", " "+k+" ") {
			return nil, ErrInvalid
		}
	}
	for _, k := range strings.Fields(required) {
		if _, ok := m[k]; !ok {
			return nil, ErrInvalid
		}
	}
	return m, nil
}
func decode(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	return nil
}

func (c *Check) UnmarshalJSON(raw []byte) error {
	m, e := object(raw, "method target expected_ip expected_exit_class", "method target")
	if e != nil {
		return e
	}
	type plain Check
	var v plain
	if decode(raw, &v) != nil {
		return ErrInvalid
	}
	_, ip := m["expected_ip"]
	_, country := m["expected_exit_class"]
	if ip != (v.Method == "https_exit_ip") || country != (v.Method == "https_exit_country") || !ValidTarget(Check(v)) {
		return ErrInvalid
	}
	*c = Check(v)
	return nil
}
func (p *Plan) UnmarshalJSON(raw []byte) error {
	m, e := object(raw, "outbound required checks profile", "outbound")
	if e != nil {
		return e
	}
	_, old := m["checks"]
	_, next := m["profile"]
	if old == next {
		return ErrInvalid
	}
	if _, present := m["required"]; next && !present {
		return ErrInvalid
	}
	type plain Plan
	var v plain
	if decode(raw, &v) != nil || Plan(v).Validate() != nil {
		return ErrInvalid
	}
	*p = Plan(v)
	return nil
}
func (p *Profile) UnmarshalJSON(raw []byte) error {
	if _, e := object(raw, "schemaVersion id revision deadlineMs leaves gates stages", "schemaVersion id revision deadlineMs leaves gates stages"); e != nil {
		return e
	}
	type plain Profile
	var v plain
	if decode(raw, &v) != nil || Profile(v).Validate() != nil {
		return ErrInvalid
	}
	*p = Profile(v)
	return nil
}

// Only v2 is normalized. The legacy Check/Plan field order and bytes stay
// unchanged; gates and stages retain their declared execution order.
func (p Profile) MarshalJSON() ([]byte, error) {
	if p.Validate() != nil {
		return nil, ErrInvalid
	}
	type plain Profile
	owned := plain(p)
	owned.Leaves = append([]Leaf(nil), p.Leaves...)
	sort.Slice(owned.Leaves, func(i, j int) bool { return owned.Leaves[i].ID < owned.Leaves[j].ID })
	return json.Marshal(owned)
}
func (l *Leaf) UnmarshalJSON(raw []byte) error {
	if _, e := object(raw, "id check", "id check"); e != nil {
		return e
	}
	type plain Leaf
	var v plain
	if decode(raw, &v) != nil || !identifier.MatchString(v.ID) {
		return ErrInvalid
	}
	*l = Leaf(v)
	return nil
}
func (e *Expr) UnmarshalJSON(raw []byte) error {
	m, err := object(raw, "leaf all any quorum", "")
	if err != nil || len(m) != 1 {
		return ErrInvalid
	}
	type plain Expr
	var v plain
	if decode(raw, &v) != nil {
		return ErrInvalid
	}
	*e = Expr(v)
	return nil
}
func (q *Quorum) UnmarshalJSON(raw []byte) error {
	if _, e := object(raw, "k of", "k of"); e != nil {
		return e
	}
	type plain Quorum
	var v plain
	if decode(raw, &v) != nil {
		return ErrInvalid
	}
	*q = Quorum(v)
	return nil
}

func (p Plan) Validate() error {
	if p.Outbound == "" || len(p.Outbound) > 256 || (p.Profile != nil) == (p.Checks != nil) {
		return ErrInvalid
	}
	if p.Profile != nil {
		return p.Profile.Validate()
	}
	if len(p.Checks) < 1 || len(p.Checks) > 4 {
		return ErrInvalid
	}
	for _, c := range p.Checks {
		if !ValidTarget(c) {
			return ErrInvalid
		}
	}
	return nil
}
func (p Profile) Validate() error {
	if p.SchemaVersion != 2 || !identifier.MatchString(p.ID) || p.Revision < 1 || p.Revision > 9007199254740991 || p.DeadlineMs < 1 || p.DeadlineMs > 12000 || len(p.Leaves) < 1 || len(p.Leaves) > 4 || p.Gates == nil || p.Stages == nil || len(p.Gates) > 4 || len(p.Stages) > 4 || len(p.Gates)+len(p.Stages) == 0 {
		return ErrInvalid
	}
	leaves := map[string]Check{}
	defs := map[string]bool{}
	used := map[string]bool{}
	gates := map[string]bool{}
	for _, l := range p.Leaves {
		b, _ := json.Marshal(l.Check)
		if !identifier.MatchString(l.ID) || (!ValidTarget(l.Check) || strings.Contains(l.Check.Target, "\\")) || defs[string(b)] {
			return ErrInvalid
		}
		if _, ok := leaves[l.ID]; ok {
			return ErrInvalid
		}
		leaves[l.ID] = l.Check
		defs[string(b)] = true
	}
	use := func(id string) bool {
		if _, ok := leaves[id]; !ok || used[id] {
			return false
		}
		used[id] = true
		return true
	}
	for _, id := range p.Gates {
		if !use(id) {
			return ErrInvalid
		}
		gates[id] = true
	}
	var visit func(Expr, int, *int) bool
	visit = func(e Expr, depth int, nodes *int) bool {
		*nodes += 1
		if depth > 4 || *nodes > 7 {
			return false
		}
		n := 0
		if e.Leaf != "" {
			n++
		}
		if e.All != nil {
			n++
		}
		if e.Any != nil {
			n++
		}
		if e.Quorum != nil {
			n++
		}
		if n != 1 {
			return false
		}
		if e.Leaf != "" {
			return identifier.MatchString(e.Leaf) && use(e.Leaf)
		}
		children := e.All
		if e.Any != nil {
			children = e.Any
		}
		if e.Quorum != nil {
			children = e.Quorum.Of
			if e.Quorum.K < 1 || e.Quorum.K > len(children) {
				return false
			}
		}
		if len(children) < 2 || len(children) > 4 {
			return false
		}
		for _, child := range children {
			if !visit(child, depth+1, nodes) {
				return false
			}
		}
		return true
	}
	nodes := 0
	for _, stage := range p.Stages {
		if !visit(stage, 1, &nodes) {
			return ErrInvalid
		}
	}
	if len(used) != len(leaves) {
		return ErrInvalid
	}
	for id, c := range leaves {
		if (c.Method == "tls" || c.Method == "https_exit_ip" || c.Method == "https_exit_country") && !gates[id] {
			return ErrInvalid
		}
	}
	return nil
}

// AllChecks includes every declared leaf, including leaves that can be skipped
// by short circuit. Admission must reserve their full cost before execution.
func (p Plan) AllChecks() []Check {
	if p.Profile == nil {
		return append([]Check(nil), p.Checks...)
	}
	out := make([]Check, 0, len(p.Profile.Leaves))
	for _, l := range p.Profile.Leaves {
		out = append(out, l.Check)
	}
	return out
}
func (p Plan) GateChecks() []Check {
	if p.Profile == nil {
		return p.AllChecks()
	}
	out := []Check{}
	for _, id := range p.Profile.Gates {
		for _, l := range p.Profile.Leaves {
			if l.ID == id {
				out = append(out, l.Check)
			}
		}
	}
	return out
}
func (p Plan) ValidateIntent(intent string) error {
	if p.Validate() != nil || intent != "INTERNAL" && intent != "RU" && intent != "NON_RU" {
		return ErrInvalid
	}
	matched := false
	for _, c := range p.AllChecks() {
		if c.Method == "https_exit_country" && (intent == "INTERNAL" || c.ExpectedExitClass != intent) {
			return ErrInvalid
		}
	}
	for _, c := range p.GateChecks() {
		matched = matched || c.Method == "https_exit_country" && c.ExpectedExitClass == intent
	}
	if intent != "INTERNAL" && !matched {
		return ErrInvalid
	}
	return nil
}
func DecodePlans(raw []byte) ([]Plan, error) {
	if strict(raw) != nil {
		return nil, ErrInvalid
	}
	var p []Plan
	if decode(raw, &p) != nil || len(p) < 1 || len(p) > 16 {
		return nil, ErrInvalid
	}
	return p, nil
}

func host(value string) bool {
	ip, e := netip.ParseAddr(value)
	if e == nil {
		return ip.Zone() == ""
	}
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	for _, l := range strings.Split(value, ".") {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	return true
}
func port(value string) bool {
	n, e := strconv.Atoi(value)
	return e == nil && n > 0 && n <= 65535 && len(value) <= 5 && strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) < 0
}
func ValidTarget(c Check) bool {
	raw := c.Target
	if len(raw) < 1 || len(raw) > 2048 || strings.IndexFunc(raw, func(r rune) bool { return r <= 32 || r > 126 }) >= 0 {
		return false
	}
	if c.Method == "https_exit_ip" {
		a, e := netip.ParseAddr(c.ExpectedIP)
		if len(c.ExpectedIP) > 45 || e != nil || a.Zone() != "" || a.Is4In6() {
			return false
		}
	} else if c.ExpectedIP != "" {
		return false
	}
	if c.Method == "https_exit_country" {
		if c.ExpectedExitClass != "RU" && c.ExpectedExitClass != "NON_RU" {
			return false
		}
	} else if c.ExpectedExitClass != "" {
		return false
	}
	switch c.Method {
	case "tcp", "ssh_banner":
		h, p, e := net.SplitHostPort(raw)
		return e == nil && host(h) && port(p)
	case "tls", "https_204", "https_exit_ip", "https_exit_country":
		u, e := url.Parse(raw)
		return e == nil && u.Scheme == "https" && u.User == nil && u.Opaque == "" && !strings.Contains(raw, "#") && !strings.HasSuffix(u.Host, ":") && host(u.Hostname()) && (u.Port() == "" || port(u.Port())) && (c.Method != "https_exit_country" || (u.Path == "" || u.Path == "/") && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery)
	default:
		return false
	}
}
