package subscriptions

// Conversion is deliberately explicit. Xray routing, local inbounds, DNS,
// sockopts, mux and external files cannot acquire authority through import.
func fromXray(m map[string]any) (map[string]any, error) {
	protocol, e := text(m, "protocol", 32, true)
	if e != nil {
		return nil, e
	}
	if protocol == "freedom" || protocol == "blackhole" || protocol == "dns" {
		return nil, nil
	}
	if protocol != "vless" && protocol != "http" && protocol != "socks" {
		return nil, ErrUnsupported
	}
	if e = only(m, "protocol tag settings streamSettings"); e != nil {
		return nil, e
	}
	settings, e := object(m["settings"])
	if e != nil {
		return nil, e
	}
	out := map[string]any{"type": protocol}
	if v, ok := m["tag"]; ok {
		out["tag"] = v
	}
	key := "servers"
	if protocol == "vless" {
		key = "vnext"
	}
	if e = only(settings, key); e != nil {
		return nil, e
	}
	servers, ok := settings[key].([]any)
	if !ok || len(servers) != 1 {
		return nil, ErrUnsupported
	}
	server, e := object(servers[0])
	if e != nil {
		return nil, e
	}
	if e = only(server, "address port users"); e != nil {
		return nil, e
	}
	out["server"] = server["address"]
	out["server_port"] = server["port"]
	if users, ok := server["users"]; ok {
		a, ok := users.([]any)
		if !ok || len(a) != 1 {
			return nil, ErrUnsupported
		}
		user, e := object(a[0])
		if e != nil {
			return nil, e
		}
		if protocol == "vless" {
			if e = only(user, "id encryption flow email level"); e != nil {
				return nil, e
			}
			out["uuid"] = user["id"]
			if s, ok := user["flow"]; ok {
				out["flow"] = s
			}
			if s, ok := user["encryption"]; ok && s != "none" {
				out["encryption"] = s
			}
		} else {
			if e = only(user, "user pass level"); e != nil {
				return nil, e
			}
			out["username"] = user["user"]
			out["password"] = user["pass"]
		}
	}
	if protocol == "socks" {
		out["version"] = "5"
	}
	if raw, ok := m["streamSettings"]; ok {
		s, e := object(raw)
		if e != nil {
			return nil, e
		}
		if e = only(s, "network method security tlsSettings realitySettings wsSettings grpcSettings xhttpSettings"); e != nil {
			return nil, e
		}
		if _, n := s["network"]; n {
			if _, v := s["method"]; v {
				return nil, ErrInvalid
			}
		}
		network, e := text(s, "network", 16, false)
		if e != nil {
			return nil, e
		}
		if network == "" {
			network, e = text(s, "method", 16, false)
			if e != nil {
				return nil, e
			}
		}
		security, e := text(s, "security", 16, false)
		if e != nil {
			return nil, e
		}
		if security != "" && security != "none" {
			if security != "tls" && security != "reality" {
				return nil, ErrUnsupported
			}
			key := "tlsSettings"
			fields := "serverName allowInsecure alpn fingerprint"
			if security == "reality" {
				key = "realitySettings"
				fields = "serverName fingerprint publicKey shortId"
			}
			t, e := object(s[key])
			if e != nil {
				return nil, e
			}
			if e = only(t, fields); e != nil {
				return nil, e
			}
			tls := map[string]any{"enabled": true}
			for from, to := range map[string]string{"serverName": "server_name", "allowInsecure": "insecure", "alpn": "alpn"} {
				if v, ok := t[from]; ok {
					tls[to] = v
				}
			}
			if v, ok := t["fingerprint"]; ok {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": v}
			}
			if security == "reality" {
				tls["reality"] = map[string]any{"enabled": true, "public_key": t["publicKey"], "short_id": t["shortId"]}
			}
			out["tls"] = tls
		} else if s["tlsSettings"] != nil || s["realitySettings"] != nil {
			return nil, ErrInvalid
		}
		if security != "tls" && s["tlsSettings"] != nil || security != "reality" && s["realitySettings"] != nil {
			return nil, ErrUnsupported
		}
		if network != "" && network != "tcp" && network != "raw" {
			if protocol != "vless" {
				return nil, ErrUnsupported
			}
			key := ""
			fields := ""
			tr := map[string]any{"type": network}
			switch network {
			case "ws":
				key = "wsSettings"
				fields = "path headers"
			case "grpc":
				key = "grpcSettings"
				fields = "serviceName"
			case "xhttp":
				key = "xhttpSettings"
				fields = "host path mode headers"
			default:
				return nil, ErrUnsupported
			}
			v, e := object(s[key])
			if e != nil {
				return nil, e
			}
			if e = only(v, fields); e != nil {
				return nil, e
			}
			for k, x := range v {
				if k == "serviceName" {
					k = "service_name"
				}
				tr[k] = x
			}
			out["transport"] = tr
		}
		for _, kind := range []string{"ws", "grpc", "xhttp"} {
			if network != kind && s[kind+"Settings"] != nil {
				return nil, ErrUnsupported
			}
		}
	}
	return out, nil
}
