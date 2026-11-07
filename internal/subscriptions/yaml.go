package subscriptions

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Decode nodes ourselves: never resolve aliases/merge keys, instantiate tags or
// infer a provider timestamp as executable/application-specific data.
func yamlJSON(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return nil, ErrInvalid
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if decoder.Decode(&document) != nil || len(document.Content) != 1 {
		return nil, ErrInvalid
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrInvalid
	}
	nodes := 0
	var walk func(*yaml.Node, int) (any, error)
	walk = func(n *yaml.Node, depth int) (any, error) {
		nodes++
		if depth > 24 || nodes > 200000 || n.Alias != nil || n.Anchor != "" || len(n.Value) > 65536 || strings.ContainsRune(n.Value, 0) {
			return nil, ErrInvalid
		}
		switch n.Kind {
		case yaml.MappingNode:
			if n.Tag != "!!map" || len(n.Content) > 512 || len(n.Content)%2 != 0 {
				return nil, ErrInvalid
			}
			m := map[string]any{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || len(k.Value) > 256 || k.Value == "<<" {
					return nil, ErrInvalid
				}
				if _, ok := m[k.Value]; ok {
					return nil, ErrInvalid
				}
				v, e := walk(n.Content[i+1], depth+1)
				if e != nil {
					return nil, e
				}
				m[k.Value] = v
			}
			return m, nil
		case yaml.SequenceNode:
			if n.Tag != "!!seq" || len(n.Content) > MaxProfiles {
				return nil, ErrInvalid
			}
			a := []any{}
			for _, n := range n.Content {
				v, e := walk(n, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			return a, nil
		case yaml.ScalarNode:
			switch n.Tag {
			case "!!str":
				return n.Value, nil
			case "!!null":
				return nil, nil
			case "!!bool":
				v, e := strconv.ParseBool(n.Value)
				if e != nil {
					return nil, ErrInvalid
				}
				return v, nil
			case "!!int":
				v, e := strconv.ParseInt(strings.ReplaceAll(n.Value, "_", ""), 0, 64)
				if e != nil {
					return nil, ErrInvalid
				}
				return json.Number(strconv.FormatInt(v, 10)), nil
			case "!!float":
				v, e := strconv.ParseFloat(n.Value, 64)
				if e != nil || math.IsInf(v, 0) || math.IsNaN(v) {
					return nil, ErrInvalid
				}
				return json.Number(strconv.FormatFloat(v, 'g', -1, 64)), nil
			default:
				return nil, ErrUnsupported
			}
		default:
			return nil, ErrInvalid
		}
	}
	return walk(document.Content[0], 0)
}

func fromMihomo(raw []byte) ([]byte, error) {
	v, e := yamlJSON(raw)
	if e != nil {
		return nil, e
	}
	root, e := object(v)
	if e != nil {
		return nil, e
	}
	a, ok := root["proxies"].([]any)
	if !ok || len(a) == 0 {
		return nil, ErrInvalid
	}
	out := []any{}
	for _, v := range a {
		m, e := object(v)
		if e != nil {
			return nil, e
		}
		if e = only(m, "name type server port username password uuid flow network tls servername sni skip-cert-verify alpn client-fingerprint reality-opts ws-opts grpc-opts xhttp-opts private-key private-key-passphrase host-key host-key-algorithms client-version"); e != nil {
			return nil, e
		}
		kind, e := text(m, "type", 16, true)
		if e != nil {
			return nil, e
		}
		if kind == "socks5" {
			kind = "socks"
		}
		if kind != "http" && kind != "socks" && kind != "vless" && kind != "ssh" {
			return nil, ErrUnsupported
		}
		n := map[string]any{"type": kind, "server": m["server"], "server_port": m["port"]}
		for from, to := range map[string]string{"name": "tag", "username": "username", "password": "password", "uuid": "uuid", "flow": "flow", "private-key": "private_key", "private-key-passphrase": "private_key_passphrase", "host-key": "host_key", "host-key-algorithms": "host_key_algorithms", "client-version": "client_version"} {
			if v, ok := m[from]; ok {
				n[to] = v
			}
		}
		if kind == "ssh" {
			n["user"] = m["username"]
			delete(n, "username")
		}
		if kind == "socks" {
			n["version"] = "5"
		}
		enabled := false
		if v, ok := m["tls"]; ok {
			b, ok := v.(bool)
			if !ok {
				return nil, ErrInvalid
			}
			enabled = b
		}
		if enabled {
			t := map[string]any{"enabled": true}
			if _, a := m["sni"]; a {
				if _, b := m["servername"]; b {
					return nil, ErrAmbiguous
				}
			}
			for from, to := range map[string]string{"sni": "server_name", "servername": "server_name", "skip-cert-verify": "insecure", "alpn": "alpn"} {
				if v, ok := m[from]; ok {
					t[to] = v
				}
			}
			if v, ok := m["client-fingerprint"]; ok {
				t["utls"] = map[string]any{"enabled": true, "fingerprint": v}
			}
			if v, ok := m["reality-opts"]; ok {
				r, e := object(v)
				if e != nil {
					return nil, e
				}
				if e = only(r, "public-key short-id"); e != nil {
					return nil, e
				}
				t["reality"] = map[string]any{"enabled": true, "public_key": r["public-key"], "short_id": r["short-id"]}
			}
			n["tls"] = t
		} else {
			for _, k := range []string{"servername", "sni", "skip-cert-verify", "alpn", "client-fingerprint", "reality-opts"} {
				if _, ok := m[k]; ok {
					return nil, ErrUnsupported
				}
			}
		}
		network, e := text(m, "network", 16, false)
		if e != nil {
			return nil, e
		}
		if network != "" && network != "tcp" {
			if kind != "vless" {
				return nil, ErrUnsupported
			}
			key := network + "-opts"
			tr := map[string]any{"type": network}
			v, e := object(m[key])
			if e != nil {
				return nil, e
			}
			fields := ""
			switch network {
			case "ws":
				fields = "path headers"
			case "grpc":
				fields = "grpc-service-name"
			case "xhttp":
				fields = "path host mode headers"
			default:
				return nil, ErrUnsupported
			}
			if e = only(v, fields); e != nil {
				return nil, e
			}
			for k, v := range v {
				if k == "grpc-service-name" {
					k = "service_name"
				}
				tr[k] = v
			}
			n["transport"] = tr
		}
		for _, kind := range []string{"ws", "grpc", "xhttp"} {
			if network != kind {
				if _, ok := m[kind+"-opts"]; ok {
					return nil, ErrUnsupported
				}
			}
		}
		out = append(out, n)
	}
	return json.Marshal(map[string]any{"outbounds": out})
}
