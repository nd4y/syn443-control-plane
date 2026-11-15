package subscriptions

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func salt() []byte { return bytes.Repeat([]byte{7}, 32) }
func authURI(scheme, host, query string) string {
	u := url.URL{Scheme: scheme, Host: host, RawQuery: query, User: url.UserPassword("synthetic", "password")}
	return u.String()
}
func syntheticID() string {
	return strings.Repeat("1", 8) + "-" + strings.Repeat("2", 4) + "-4" + strings.Repeat("3", 3) + "-8" + strings.Repeat("4", 3) + "-" + strings.Repeat("5", 12)
}
func proxy(kind string) map[string]any {
	m := map[string]any{"type": kind, "tag": "Example", "server": "proxy.example.invalid", "server_port": json.Number("443")}
	switch kind {
	case "socks":
		m["version"] = "5"
	case "vless":
		m["uuid"] = syntheticID()
	case "ssh":
		m["user"] = "synthetic-user"
		m["password"] = "synthetic-only-password"
		m["host_key"] = "ssh-ed25519 synthetic-public-host-key"
	}
	return m
}
func document(m ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"outbounds": m})
	return b
}
func imported(t *testing.T, format string, raw []byte) []Profile {
	t.Helper()
	p, e := Import("source-a", salt(), format, raw)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestFormatsAndTransportPreservation(t *testing.T) {
	for _, kind := range []string{"http", "socks", "ssh", "vless"} {
		t.Run(kind, func(t *testing.T) {
			m := proxy(kind)
			p := imported(t, "singbox", document(m))
			if len(p) != 1 || p[0].Kind != kind || !strings.HasPrefix(p[0].ID, "source-a_") {
				t.Fatal("profile identity")
			}
			if bytes.Contains([]byte(fmt.Sprintf("%v %#v", p[0], p[0])), []byte("synthetic-only-password")) {
				t.Fatal("sensitive formatting")
			}
		})
	}
	uri := "vless://" + syntheticID() + "@proxy.example.invalid:443?security=tls&sni=cover.example.invalid&alpn=h2%2Ch3&type=xhttp&mode=stream-one&path=%2Ftransport&host=cdn.example.invalid&fp=chrome#First"
	p := imported(t, "uri", []byte(uri))
	var m map[string]any
	json.Unmarshal(p[0].Outbound, &m)
	tls := m["tls"].(map[string]any)
	transport := m["transport"].(map[string]any)
	if transport["mode"] != "stream-one" || transport["path"] != "/transport" || tls["server_name"] != "cover.example.invalid" || len(tls["alpn"].([]any)) != 2 {
		t.Fatal("transport/TLS lost")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(uri))
	q := imported(t, "base64", []byte(encoded))
	if p[0].ID != q[0].ID {
		t.Fatal("base64 changed profile")
	}
	for _, raw := range []string{authURI("https", "proxy.example.invalid:8443", ""), authURI("socks5", "proxy.example.invalid:1080", ""), "socks4a://proxy.example.invalid:1080", authURI("ssh", "proxy.example.invalid:22", "hostKey=ssh-ed25519%20synthetic-key")} {
		imported(t, "uri", []byte(raw))
	}
	for _, transport := range []string{"ws", "grpc"} {
		suffix := "&type=ws&host=cdn.example.invalid&path=%2Fws"
		if transport == "grpc" {
			suffix = "&type=grpc&serviceName=service"
		}
		imported(t, "uri", []byte("vless://"+syntheticID()+"@proxy.example.invalid:443?security=tls"+suffix))
	}
	reality := "vless://" + syntheticID() + "@proxy.example.invalid:443?security=reality&type=tcp&pbk=" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "&sid=0123&fp=chrome"
	imported(t, "uri", []byte(reality))
}

func TestStableIDsAndNoCrossSourceCredentialOracle(t *testing.T) {
	a, b := proxy("http"), proxy("socks")
	first := imported(t, "singbox", document(a, b))
	a["tag"] = "Renamed"
	b["tag"] = "Other renamed"
	second := imported(t, "singbox", document(b, a))
	if first[0].ID != second[1].ID || first[1].ID != second[0].ID {
		t.Fatal("rename/reorder changed IDs")
	}
	other, e := Import("source-b", salt(), "singbox", document(a))
	if e != nil || other[0].ID == first[0].ID {
		t.Fatal("cross source identity collision")
	}
	other, e = Import("source-a", bytes.Repeat([]byte{8}, 32), "singbox", document(a))
	if e != nil || other[0].ID == first[0].ID {
		t.Fatal("private salt missing")
	}
	if _, e = Import("source-a", salt(), "singbox", document(a, a)); !errors.Is(e, ErrAmbiguous) {
		t.Fatal("ambiguous duplicates accepted")
	}
	a["password"] = "rotated-synthetic-password"
	other = imported(t, "singbox", document(a))
	if other[0].ID == first[0].ID {
		t.Fatal("credential change bypassed candidate reconciliation")
	}
}

func TestUntrustedFullConfigImportsProfilesOnly(t *testing.T) {
	root := map[string]any{"outbounds": []any{proxy("http"), map[string]any{"type": "direct", "tag": "outside"}, map[string]any{"type": "selector", "tag": "group", "outbounds": []string{"outside"}}}, "inbounds": []any{map[string]any{"type": "mixed", "listen": "0.0.0.0"}}, "route": map[string]any{"final": "outside"}, "experimental": map[string]any{"external_controller": "example.invalid:9090"}}
	b, _ := json.Marshal(root)
	p := imported(t, "singbox", b)
	if len(p) != 1 || bytes.Contains(p[0].Outbound, []byte("outside")) || bytes.Contains(p[0].Outbound, []byte("controller")) {
		t.Fatal("untrusted control metadata imported")
	}
}

func TestJSONAndURIFailClosed(t *testing.T) {
	bad := []struct{ format, raw string }{
		{"singbox", `{"outbounds":[],"outbounds":[]}`}, {"singbox", `{"outbounds":[]}`}, {"singbox", `{"outbounds":[null]}`},
		{"singbox", `{"outbounds":[{"type":"vmess"}]}`}, {"singbox", `{"outbounds":[{"type":"http","server":"proxy.example.invalid","server_port":1,"password_path":"/untrusted"}]}`},
		{"singbox", `{"outbounds":[{"type":"http","server":"proxy.example.invalid","server_port":1.5}]}`},
		{"singbox", `{"outbounds":[{"type":"http","server":"proxy.example.invalid","server_port":1,"tls":{"enabled":true,"insecure":true}}]}`},
		{"singbox", `{"outbounds":[{"type":"http","server":"proxy.example.invalid","server_port":1,"tls":{"enabled":true,"certificate_path":"/untrusted"}}]}`},
		{"singbox", `{"outbounds":[{"type":"http","server":"proxy.example.invalid","server_port":65536}]}`},
		{"singbox", `{"outbounds":[{"type":"http","server":"proxy.example.invalid","server_port":1,"username":false}]}`},
		{"uri", "<html>temporary error</html>"}, {"base64", "not!base64"}, {"uri", authURI("ssh", "proxy.example.invalid:22", "")},
		{"uri", "socks5://proxy.example.invalid"}, {"uri", "http://proxy.example.invalid:0"}, {"uri", "http://proxy.example.invalid:80?file=unsafe"},
		{"uri", "vless://" + syntheticID() + "@proxy.example.invalid:443?type=ws&type=grpc"},
		{"uri", "vless://" + syntheticID() + "@proxy.example.invalid:443?type=grpc&path=ignored"},
		{"uri", "vless://" + syntheticID() + "@proxy.example.invalid:443?security=tls&pbk=ignored"},
		{"uri", "vless://" + syntheticID() + "@proxy.example.invalid:443?security=bogus"},
		{"uri", "vless://" + syntheticID() + "@proxy.example.invalid:443?type=unsupported"},
		{"singbox", strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26)},
		{"singbox", `{"outbounds":[],"unused":1e9999}`},
	}
	for i, c := range bad {
		p, e := Import("source-a", salt(), c.format, []byte(c.raw))
		if e == nil || p != nil {
			t.Fatalf("case%d admitted invalid/partial source", i)
		}
		if strings.Contains(e.Error(), "proxy.example.invalid") || strings.Contains(e.Error(), syntheticID()) {
			t.Fatal("error disclosed source")
		}
	}
	for _, s := range []string{"", "bad/source", strings.Repeat("a", 49)} {
		if _, e := Import(s, salt(), "uri", []byte("http://proxy.example.invalid")); e == nil {
			t.Fatal("source namespace accepted")
		}
	}
	if _, e := Import("source-a", nil, "uri", []byte("http://proxy.example.invalid")); e == nil {
		t.Fatal("missing salt")
	}
	if _, e := Import("source-a", salt(), "singbox", bytes.Repeat([]byte{' '}, MaxBytes+1)); e == nil {
		t.Fatal("size limit")
	}
}

func TestXrayAndMihomo(t *testing.T) {
	x := map[string]any{"outbounds": []any{map[string]any{"protocol": "vless", "tag": "Xray", "settings": map[string]any{"vnext": []any{map[string]any{"address": "proxy.example.invalid", "port": 443, "users": []any{map[string]any{"id": syntheticID(), "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": map[string]any{"serverName": "cover.example.invalid", "alpn": []string{"h2", "h3"}}, "xhttpSettings": map[string]any{"path": "/transport", "mode": "packet-up"}}}, map[string]any{"protocol": "freedom"}}}
	raw, _ := json.Marshal(x)
	p := imported(t, "xray", raw)
	if p[0].Kind != "vless" || !bytes.Contains(p[0].Outbound, []byte("packet-up")) {
		t.Fatal("Xray transport dropped")
	}
	y := []byte("proxies:\n  - name: YAML\n    type: vless\n    server: proxy.example.invalid\n    port: 443\n    uuid: " + syntheticID() + "\n    tls: true\n    servername: cover.example.invalid\n    network: xhttp\n    xhttp-opts:\n      path: /transport\n      mode: packet-up\nrules: [MATCH,DIRECT]\n")
	p = imported(t, "mihomo", y)
	if p[0].Kind != "vless" || !bytes.Contains(p[0].Outbound, []byte("packet-up")) {
		t.Fatal("YAML transport lost")
	}
	for _, raw := range []string{"proxies: []", "proxies: !unsafe []", "proxies: &loop [*loop]", "proxies: []\nproxies: []", "proxies: []\n---\nproxies: []", "proxies: []\nunused: .nan", "proxies: []\nmerge: {<<: {unsafe: yes}}"} {
		if _, e := Import("source-a", salt(), "mihomo", []byte(raw)); e == nil {
			t.Fatal("unsafe YAML accepted")
		}
	}
}

func TestProfileCountBoundary(t *testing.T) {
	var lines []string
	for i := 0; i < MaxProfiles; i++ {
		lines = append(lines, fmt.Sprintf("http://node%d.example.invalid:80", i))
	}
	if p, e := Import("source-a", salt(), "uri", []byte(strings.Join(lines, "\n"))); e != nil || len(p) != MaxProfiles {
		t.Fatal("valid boundary")
	}
	if _, e := Import("source-a", salt(), "uri", []byte(strings.Join(append(lines, "http://overflow.example.invalid:80"), "\n"))); e == nil {
		t.Fatal("profile cap")
	}
}

func TestEquivalentProviderFormatsAndInlineSSHTrust(t *testing.T) {
	// Independent provider formats must yield the same source-scoped connection.
	uri := authURI("http", "proxy.example.invalid:443", "")
	m := proxy("http")
	m["username"] = "synthetic"
	m["password"] = "password"
	x := map[string]any{"outbounds": []any{map[string]any{"protocol": "http", "settings": map[string]any{"servers": []any{map[string]any{"address": "proxy.example.invalid", "port": 443, "users": []any{map[string]any{"user": "synthetic", "pass": "password"}}}}}}}}
	xraw, _ := json.Marshal(x)
	y := []byte("proxies:\n  - name: Other label\n    type: http\n    server: proxy.example.invalid\n    port: 443\n    username: synthetic\n    password: password\n")
	want := imported(t, "uri", []byte(uri))[0]
	for _, c := range []struct {
		format string
		raw    []byte
	}{{"singbox", document(m)}, {"xray", xraw}, {"mihomo", y}} {
		got := imported(t, c.format, c.raw)[0]
		if got.ID != want.ID || !bytes.Equal(got.Outbound, want.Outbound) {
			t.Fatal("provider conversion changed connection")
		}
	}
	for _, kind := range []string{"socks5", "ssh"} {
		fields := "    username: synthetic\n    password: password\n"
		if kind == "ssh" {
			fields += "    host-key: [ssh-ed25519 synthetic-public-key]\n"
		}
		imported(t, "mihomo", []byte("proxies:\n  - type: "+kind+"\n    server: proxy.example.invalid\n    port: 443\n"+fields))
	}
	key := proxy("ssh")
	delete(key, "password")
	key["private_key"] = []string{"synthetic-inline-key"}
	key["private_key_passphrase"] = "synthetic-passphrase"
	key["host_key_algorithms"] = []string{"ssh-ed25519"}
	key["client_version"] = "SSH-2.0-synthetic"
	imported(t, "singbox", document(key))
	for _, kind := range []string{"ws", "grpc"} {
		m := proxy("vless")
		tr := map[string]any{"type": kind}
		if kind == "ws" {
			tr["path"] = "/ws"
			tr["headers"] = map[string]any{"Host": []string{"cdn.example.invalid"}}
			tr["max_early_data"] = json.Number("1024")
			tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
		} else {
			tr["service_name"] = "service"
		}
		m["transport"] = tr
		imported(t, "singbox", document(m))
	}
}

func TestNestedSecurityAndAdapterRejections(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { m["server"] = "invalid host" }, func(m map[string]any) { m["server_port"] = json.Number("-1") },
		func(m map[string]any) { m["tls"] = true }, func(m map[string]any) { m["tls"] = map[string]any{"enabled": false} },
		func(m map[string]any) { m["tls"] = map[string]any{"enabled": true, "alpn": []any{false}} },
		func(m map[string]any) {
			m["tls"] = map[string]any{"enabled": true, "utls": map[string]any{"enabled": true, "fingerprint": false}}
		},
		func(m map[string]any) {
			m["tls"] = map[string]any{"enabled": true, "reality": map[string]any{"enabled": true, "public_key": "not-a-key"}}
		},
		func(m map[string]any) {
			m["transport"] = map[string]any{"type": "ws", "headers": map[string]any{"Host": "bad\r\nheader"}}
		},
		func(m map[string]any) { m["transport"] = map[string]any{"type": "xhttp", "mode": "unknown-mode"} },
		func(m map[string]any) { m["transport"] = map[string]any{"type": "grpc", "unrecognized": true} },
		func(m map[string]any) {
			m["transport"] = map[string]any{"type": "ws", "max_early_data": json.Number("65537")}
		},
		func(m map[string]any) { m["flow"] = "unsupported" }, func(m map[string]any) { m["packet_encoding"] = "unsupported" },
	} {
		m := proxy("vless")
		mutate(m)
		if p, e := Import("source-a", salt(), "singbox", document(m)); e == nil || p != nil {
			t.Fatal("unsafe nested field accepted")
		}
	}
	for _, raw := range []string{
		`{"outbounds":[{"protocol":"vless","settings":{"vnext":[]}}]}`,
		`{"outbounds":[{"protocol":"http","settings":{"servers":[{"address":"proxy.example.invalid","port":443}]},"streamSettings":{"network":"ws","wsSettings":{}}}]}`,
		`{"outbounds":[{"protocol":"http","settings":{"servers":[{"address":"proxy.example.invalid","port":443}]},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}`,
		`{"outbounds":[{"protocol":"http","settings":{"servers":[{"address":"proxy.example.invalid","port":443}]},"proxySettings":{"tag":"untrusted"}}]}`,
	} {
		if _, e := Import("source-a", salt(), "xray", []byte(raw)); e == nil {
			t.Fatal("unsupported Xray controls accepted")
		}
	}
	for _, raw := range []string{
		"proxies: [{type: vmess}]", "proxies: [{type: http, server: proxy.example.invalid, port: 443, unknown: value}]",
		"proxies: [{type: http, server: proxy.example.invalid, port: 443, tls: true, skip-cert-verify: true}]",
		"proxies: [{type: http, server: proxy.example.invalid, port: 443, servername: ignored.example.invalid}]",
	} {
		if _, e := Import("source-a", salt(), "mihomo", []byte(raw)); e == nil {
			t.Fatal("unsupported YAML controls accepted")
		}
	}
	if _, e := Assess([]Profile{{ID: strings.Repeat("x", 129)}}, []Profile{{ID: "safe"}}, nil); e == nil {
		t.Fatal("unbounded profile ID")
	}
}

func FuzzSubscriptionJSON(f *testing.F) {
	f.Add(document(proxy("http")))
	f.Add([]byte(`{"outbounds":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		p, e := Import("source-a", salt(), "singbox", raw)
		if e == nil {
			if len(p) < 1 || len(p) > MaxProfiles {
				t.Fatal("unbounded result")
			}
			for _, p := range p {
				if !json.Valid(p.Outbound) {
					t.Fatal("invalid output")
				}
			}
		}
	})
}
