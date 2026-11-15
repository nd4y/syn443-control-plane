package subscriptions

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil, ErrInvalid
	}
	return m, nil
}
func only(m map[string]any, keys string) error {
	allowed := strings.Fields(keys)
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return ErrUnsupported
		}
	}
	return nil
}
func text(m map[string]any, k string, max int, required bool) (string, error) {
	v, ok := m[k]
	if !ok {
		if required {
			return "", ErrInvalid
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok || len(s) > max || required && s == "" || strings.IndexFunc(s, func(r rune) bool { return r == 0 || r == '\r' || r == '\n' }) >= 0 {
		return "", ErrInvalid
	}
	return s, nil
}
func stringsValue(v any, max int) bool {
	s, ok := v.(string)
	if ok {
		return len(s) > 0 && len(s) <= max && !strings.ContainsRune(s, 0)
	}
	a, ok := v.([]any)
	if !ok || len(a) < 1 || len(a) > 16 {
		return false
	}
	for _, x := range a {
		if _, ok := x.(string); !ok || !stringsValue(x, max) {
			return false
		}
	}
	return true
}

// DecodeJSON checks ignored metadata as well, without losing duplicate keys.
func DecodeJSON(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		nodes++
		if depth > 24 || nodes > 200000 {
			return nil, ErrInvalid
		}
		t, e := d.Token()
		if e != nil {
			return nil, ErrInvalid
		}
		switch x := t.(type) {
		case json.Delim:
			if x == '{' {
				m := map[string]any{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || len(s) > 256 || len(m) >= 256 {
						return nil, ErrInvalid
					}
					if _, ok = m[s]; ok {
						return nil, ErrInvalid
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					m[s] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, ErrInvalid
				}
				return m, nil
			}
			if x == '[' {
				a := []any{}
				for d.More() {
					if len(a) >= MaxProfiles {
						return nil, ErrInvalid
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, ErrInvalid
				}
				return a, nil
			}
			return nil, ErrInvalid
		case string:
			if len(x) > 65536 || strings.ContainsRune(x, 0) {
				return nil, ErrInvalid
			}
		case json.Number:
			n, e := x.Float64()
			if e != nil || math.IsInf(n, 0) || math.IsNaN(n) {
				return nil, ErrInvalid
			}
		}
		return t, nil
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}

// Import is all-or-nothing. Routing, listeners and imported groups are never
// promoted from an untrusted full configuration into the effective policy.
func Import(source string, salt []byte, format string, raw []byte) ([]Profile, error) {
	if !sourceID.MatchString(source) || len(salt) != 32 || len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	if format == "mihomo" {
		var e error
		raw, e = fromMihomo(raw)
		if e != nil {
			return nil, e
		}
		format = "singbox"
	}
	if format == "base64" {
		var e error
		compact := strings.Join(strings.Fields(string(raw)), "")
		raw, e = base64.StdEncoding.Strict().DecodeString(compact)
		if e != nil {
			raw, e = base64.RawStdEncoding.Strict().DecodeString(compact)
		}
		if e != nil || len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
			return nil, ErrInvalid
		}
		format = "uri"
	}
	var out []map[string]any
	if format == "uri" {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if len(out) >= MaxProfiles {
				return nil, ErrInvalid
			}
			m, e := parseURI(line)
			if e != nil {
				return nil, e
			}
			out = append(out, m)
		}
	} else {
		v, e := DecodeJSON(raw)
		if e != nil {
			return nil, e
		}
		m, e := object(v)
		if e != nil {
			return nil, e
		}
		a, ok := m["outbounds"].([]any)
		if !ok {
			return nil, ErrInvalid
		}
		for _, v := range a {
			m, e := object(v)
			if e != nil {
				return nil, e
			}
			if format == "xray" {
				m, e = fromXray(m)
				if e != nil {
					return nil, e
				}
				if m == nil {
					continue
				}
			} else if format == "singbox" {
				kind, _ := m["type"].(string)
				if kind == "direct" || kind == "block" || kind == "dns" || kind == "selector" || kind == "urltest" {
					continue
				}
			} else {
				return nil, ErrUnsupported
			}
			out = append(out, m)
		}
	}
	if len(out) == 0 || len(out) > MaxProfiles {
		return nil, ErrInvalid
	}
	result := make([]Profile, 0, len(out))
	seen := map[string]bool{}
	for _, m := range out {
		if e := ValidateOutbound(m); e != nil {
			return nil, e
		}
		name, e := text(m, "tag", 256, false)
		if e != nil {
			return nil, e
		}
		delete(m, "tag")
		canonical, e := json.Marshal(m)
		if e != nil {
			return nil, ErrInvalid
		}
		id, e := profileID(source, salt, canonical)
		if e != nil {
			return nil, e
		}
		if seen[id] {
			return nil, ErrAmbiguous
		}
		seen[id] = true
		if name == "" {
			name = m["type"].(string)
		}
		m["tag"] = id
		b, _ := json.Marshal(m)
		result = append(result, Profile{ID: id, Name: name, Kind: m["type"].(string), Outbound: b})
	}
	return result, nil
}

func port(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, e := n.Int64()
	return e == nil && i >= 1 && i <= 65535
}
func host(s string) bool {
	return len(s) > 0 && len(s) <= 253 && strings.IndexFunc(s, func(r rune) bool { return r < 33 || r > 126 }) < 0 && !strings.ContainsAny(s, " /\\\t\r\n\x00") && (net.ParseIP(s) != nil || !strings.Contains(s, ":"))
}
func ValidateOutbound(m map[string]any) error {
	kind, e := text(m, "type", 16, true)
	if e != nil {
		return e
	}
	fields := "type tag server server_port"
	switch kind {
	case "http":
		fields += " username password tls"
	case "socks":
		fields += " username password version"
	case "vless":
		fields += " uuid flow encryption packet_encoding network tls transport"
	case "ssh":
		fields += " user password private_key private_key_passphrase host_key host_key_algorithms client_version"
	default:
		return ErrUnsupported
	}
	if e = only(m, fields); e != nil {
		return e
	}
	server, e := text(m, "server", 253, true)
	if e != nil || !host(server) || !port(m["server_port"]) {
		return ErrInvalid
	}
	for _, key := range []string{"tag", "username", "password", "user", "flow", "encryption", "packet_encoding", "network", "version", "client_version", "private_key_passphrase"} {
		if _, e = text(m, key, 8192, false); e != nil {
			return e
		}
	}
	if kind == "vless" {
		id, e := text(m, "uuid", 36, true)
		if e != nil || !uuid.MatchString(id) {
			return ErrInvalid
		}
		if f, _ := m["flow"].(string); f != "" && f != "xtls-rprx-vision" {
			return ErrUnsupported
		}
		if n, _ := m["network"].(string); n != "" && n != "tcp" && n != "udp" {
			return ErrUnsupported
		}
		if p, _ := m["packet_encoding"].(string); p != "" && p != "xudp" && p != "packetaddr" {
			return ErrUnsupported
		}
	}
	if kind == "socks" {
		if s, _ := m["version"].(string); s != "" && s != "5" && s != "4" && s != "4a" {
			return ErrUnsupported
		}
	}
	if kind == "ssh" {
		if _, e = text(m, "user", 256, true); e != nil {
			return e
		}
		if !stringsValue(m["host_key"], 8192) {
			return ErrInvalid
		}
		if p, _ := m["password"].(string); p == "" && !stringsValue(m["private_key"], 65536) {
			return ErrInvalid
		}
		for _, k := range []string{"private_key", "host_key_algorithms"} {
			if v, ok := m[k]; ok && !stringsValue(v, 65536) {
				return ErrInvalid
			}
		}
	}
	if v, ok := m["tls"]; ok {
		t, e := object(v)
		if e != nil {
			return e
		}
		if e = validateTLS(t); e != nil {
			return e
		}
	}
	if v, ok := m["transport"]; ok {
		t, e := object(v)
		if e != nil {
			return e
		}
		if e = validateTransport(t); e != nil {
			return e
		}
	}
	return nil
}
func validateTLS(t map[string]any) error {
	if e := only(t, "enabled server_name insecure alpn utls reality min_version max_version certificate"); e != nil {
		return e
	}
	if v, ok := t["enabled"].(bool); !ok || !v {
		return ErrInvalid
	}
	for _, key := range []string{"server_name", "min_version", "max_version"} {
		if _, e := text(t, key, 253, false); e != nil {
			return e
		}
	}
	if v, ok := t["insecure"]; ok {
		b, ok := v.(bool)
		if !ok {
			return ErrInvalid
		}
		if b {
			return ErrUnsupported
		}
	}
	for _, key := range []string{"alpn", "certificate"} {
		if v, ok := t[key]; ok && !stringsValue(v, 65536) {
			return ErrInvalid
		}
	}
	if v, ok := t["utls"]; ok {
		m, e := object(v)
		if e != nil {
			return e
		}
		if e = only(m, "enabled fingerprint"); e != nil {
			return e
		}
		if enabled, ok := m["enabled"].(bool); !ok || !enabled {
			return ErrInvalid
		}
		if _, e = text(m, "fingerprint", 64, true); e != nil {
			return e
		}
	}
	if v, ok := t["reality"]; ok {
		m, e := object(v)
		if e != nil {
			return e
		}
		if e = only(m, "enabled public_key short_id"); e != nil {
			return e
		}
		if enabled, ok := m["enabled"].(bool); !ok || !enabled {
			return ErrInvalid
		}
		key, e := text(m, "public_key", 64, true)
		raw, err := base64.RawURLEncoding.Strict().DecodeString(key)
		if e != nil || err != nil || len(raw) != 32 {
			return ErrInvalid
		}
		s, e := text(m, "short_id", 16, false)
		if e != nil || len(s)%2 != 0 || strings.Trim(s, "0123456789abcdefABCDEF") != "" {
			return ErrInvalid
		}
	}
	return nil
}
func validateTransport(m map[string]any) error {
	kind, e := text(m, "type", 16, true)
	if e != nil {
		return e
	}
	fields := "type"
	switch kind {
	case "ws":
		fields += " path headers max_early_data early_data_header_name"
	case "grpc":
		fields += " service_name"
	case "xhttp":
		fields += " host path mode headers"
	default:
		return ErrUnsupported
	}
	if e = only(m, fields); e != nil {
		return e
	}
	for _, key := range []string{"path", "host", "mode", "service_name", "early_data_header_name"} {
		if _, e = text(m, key, 4096, false); e != nil {
			return e
		}
	}
	if v, ok := m["headers"]; ok {
		h, e := object(v)
		if e != nil || len(h) > 32 {
			return ErrInvalid
		}
		for k, v := range h {
			if len(k) == 0 || len(k) > 128 || strings.ContainsAny(k, "\r\n\x00:") {
				return ErrInvalid
			}
			if !stringsValue(v, 4096) {
				return ErrInvalid
			}
			b, _ := json.Marshal(v)
			if bytes.Contains(b, []byte(`\r`)) || bytes.Contains(b, []byte(`\n`)) {
				return ErrInvalid
			}
		}
	}
	if v, ok := m["max_early_data"]; ok {
		n, ok := v.(json.Number)
		if !ok {
			return ErrInvalid
		}
		i, e := n.Int64()
		if e != nil || i < 0 || i > 65536 {
			return ErrInvalid
		}
	}
	if kind == "xhttp" {
		mode, _ := m["mode"].(string)
		if mode != "" && mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
			return ErrUnsupported
		}
	}
	return nil
}
func parseURI(raw string) (map[string]any, error) {
	if len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, ErrInvalid
	}
	u, e := url.Parse(raw)
	if e != nil || u.Opaque != "" || u.Hostname() == "" || u.Path != "" && u.Path != "/" {
		return nil, ErrInvalid
	}
	kind := u.Scheme
	if kind == "https" {
		kind = "http"
	}
	if kind == "socks5" || kind == "socks4" || kind == "socks4a" {
		kind = "socks"
	}
	if kind != "http" && kind != "socks" && kind != "vless" && kind != "ssh" {
		return nil, ErrUnsupported
	}
	p := u.Port()
	if p == "" {
		switch u.Scheme {
		case "http":
			p = "80"
		case "https":
			p = "443"
		case "ssh":
			p = "22"
		default:
			return nil, ErrInvalid
		}
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 1 || n > 65535 {
		return nil, ErrInvalid
	}
	m := map[string]any{"type": kind, "server": u.Hostname(), "server_port": json.Number(p)}
	if u.Fragment != "" {
		m["tag"] = u.Fragment
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return nil, ErrInvalid
	}
	for _, v := range q {
		if len(v) != 1 {
			return nil, ErrInvalid
		}
	}
	allowed := ""
	switch kind {
	case "vless":
		allowed = "security sni alpn fp pbk sid type host path serviceName mode flow encryption packetEncoding"
	case "ssh":
		allowed = "hostKey privateKey privateKeyPassphrase"
	}
	for k := range q {
		found := false
		for _, a := range strings.Fields(allowed) {
			if k == a {
				found = true
			}
		}
		if !found {
			return nil, ErrUnsupported
		}
	}
	if u.User != nil {
		user := u.User.Username()
		password, has := u.User.Password()
		if kind == "vless" {
			if has {
				return nil, ErrInvalid
			}
			m["uuid"] = user
		} else if kind == "ssh" {
			m["user"] = user
			if has {
				m["password"] = password
			}
		} else {
			m["username"] = user
			if has {
				m["password"] = password
			}
		}
	}
	if kind == "socks" {
		switch u.Scheme {
		case "socks4":
			m["version"] = "4"
		case "socks4a":
			m["version"] = "4a"
		default:
			m["version"] = "5"
		}
	}
	if kind == "ssh" {
		if s := q.Get("hostKey"); s != "" {
			m["host_key"] = s
		}
		if s := q.Get("privateKey"); s != "" {
			m["private_key"] = s
		}
		if s := q.Get("privateKeyPassphrase"); s != "" {
			m["private_key_passphrase"] = s
		}
	}
	security := q.Get("security")
	if u.Scheme == "https" {
		security = "tls"
	}
	if security != "reality" {
		if _, ok := q["pbk"]; ok {
			return nil, ErrUnsupported
		}
		if _, ok := q["sid"]; ok {
			return nil, ErrUnsupported
		}
	}
	if security != "" && security != "none" {
		if security != "tls" && security != "reality" {
			return nil, ErrUnsupported
		}
		tls := map[string]any{"enabled": true}
		if s := q.Get("sni"); s != "" {
			tls["server_name"] = s
		}
		if s := q.Get("alpn"); s != "" {
			items := []any{}
			for _, v := range strings.Split(s, ",") {
				items = append(items, v)
			}
			tls["alpn"] = items
		}
		if s := q.Get("fp"); s != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": s}
		}
		if security == "reality" {
			tls["reality"] = map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
		}
		m["tls"] = tls
	} else if q.Get("sni") != "" || q.Get("alpn") != "" || q.Get("fp") != "" || q.Get("pbk") != "" || q.Get("sid") != "" {
		return nil, ErrInvalid
	}
	if kind == "vless" {
		for key, target := range map[string]string{"flow": "flow", "encryption": "encryption", "packetEncoding": "packet_encoding"} {
			if s := q.Get(key); s != "" && !(key == "encryption" && s == "none") {
				m[target] = s
			}
		}
		transport := q.Get("type")
		for _, key := range []string{"host", "path", "serviceName", "mode"} {
			if _, ok := q[key]; !ok {
				continue
			}
			if (key == "host" || key == "path") && (transport == "ws" || transport == "xhttp") {
				continue
			}
			if key == "serviceName" && transport == "grpc" {
				continue
			}
			if key == "mode" && transport == "xhttp" {
				continue
			}
			return nil, ErrUnsupported
		}
		if transport != "" && transport != "tcp" {
			tr := map[string]any{"type": transport}
			switch transport {
			case "ws":
				if s := q.Get("host"); s != "" {
					tr["headers"] = map[string]any{"Host": s}
				}
				if s := q.Get("path"); s != "" {
					tr["path"] = s
				}
			case "grpc":
				tr["service_name"] = q.Get("serviceName")
			case "xhttp":
				for _, k := range []string{"host", "path", "mode"} {
					if s := q.Get(k); s != "" {
						tr[k] = s
					}
				}
			default:
				return nil, ErrUnsupported
			}
			m["transport"] = tr
		}
	}
	return m, nil
}
