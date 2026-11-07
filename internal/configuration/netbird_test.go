package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func managedNetBird() *NetBirdNode {
	return &NetBirdNode{Tag: "home", OverlayID: "personal", ResourceID: "overlay-cloud", NetworkID: "network-a", IdentityEpoch: 1, ManagementURL: "https://overlay.example.invalid", Hostname: "test-device", Mode: "direct"}
}

func netbirdPlan() NetworkPlan {
	p := planBase()
	p.Graph.NetBird = managedNetBird()
	p.Graph.Final = "home"
	p.Network.DNSServers = map[string]DNSServer{"home-dns": {Transport: "netbird", Outbound: "home"}}
	p.Network.DNSRules = []DNSRule{{ID: "home-names", HostMatch: HostMatch{DomainSuffixes: []string{"home.example.invalid"}}, Server: "home-dns"}}
	p.Network.Rules = []RouteRule{{ID: "home-addresses", IPPrefixes: []string{"100.64.0.0/10"}, Action: "route", Outbound: "home"}}
	return p
}

func TestManagedNetBirdPortablePlanDirectAndEmergencyVLESSPreserveIdentityAndScopedDNS(t *testing.T) {
	p := netbirdPlan()
	var identity []byte
	for _, emergency := range []bool{false, true} {
		if emergency {
			p.Graph.NetBird.Mode = "vless"
			p.Graph.NetBird.Detour = "tunnel"
		}
		compiled, e := CompileNetworkPlan(context.Background(), p, defaultGraphResolver())
		if e != nil {
			t.Fatal(emergency, e)
		}
		var root struct {
			Outbounds []map[string]json.RawMessage `json:"outbounds"`
			DNS       struct {
				Servers []map[string]json.RawMessage `json:"servers"`
				Rules   []map[string]json.RawMessage `json:"rules"`
			} `json:"dns"`
		}
		if json.Unmarshal(compiled.EngineConfig, &root) != nil {
			t.Fatal("compiled network")
		}
		found := 0
		for _, node := range root.Outbounds {
			if string(node["type"]) != `"netbird"` {
				continue
			}
			found++
			if found != 1 || string(node["tag"]) != `"home"` || string(node["management_url"]) != `"https://overlay.example.invalid"` {
				t.Fatal("overlay substitution/clone")
			}
			if !emergency {
				identity = append([]byte(nil), node["managed"]...)
			} else if !bytes.Equal(identity, node["managed"]) || string(node["detour"]) != `"tunnel"` {
				t.Fatal("transport selection changed identity")
			}
			if !emergency && node["detour"] != nil {
				t.Fatal("direct overlay acquired detour")
			}
			for _, forbidden := range []string{"setup_key", "state_directory", "managed_namespace", "credential_pending", "recover_existing", "force_relay"} {
				if node[forbidden] != nil {
					t.Fatal("privileged/forced field", forbidden)
				}
			}
			var metadata map[string]any
			if json.Unmarshal(node["managed"], &metadata) != nil || metadata["setupReference"] != "" || metadata["setupVersion"] != float64(0) {
				t.Fatal("caller supplied broker reference")
			}
		}
		if found != 1 || len(root.DNS.Servers) != 2 || string(root.DNS.Servers[1]["type"]) != `"netbird"` || string(root.DNS.Servers[1]["outbound"]) != `"home"` || string(root.DNS.Rules[0]["server"]) != `"home-dns"` {
			t.Fatal("internal DNS path missing")
		}
		feature := "netbird.direct"
		if emergency {
			feature = "netbird.vless"
		}
		if !slices.Contains(compiled.RequiredEngineFeatures, feature) {
			t.Fatal("overlay module feature missing")
		}
		raw, _ := json.Marshal(p)
		decoded, e := DecodeNetworkPlan(raw)
		if e != nil || !reflect.DeepEqual(decoded, p) {
			t.Fatal("closed portable roundtrip", e)
		}
		if strings.Contains(fmt.Sprintf("%v %#v", *p.Graph.NetBird, *p.Graph.NetBird), "example.invalid") {
			t.Fatal("overlay diagnostic leak")
		}
	}
}

func TestManagedNetBirdRejectsAuthorityInjectionInvalidIdentityDetoursAndDNSFallback(t *testing.T) {
	for i, change := range []func(*NetworkPlan){
		func(p *NetworkPlan) { p.Graph.NetBird.Tag = "direct" },
		func(p *NetworkPlan) { p.Graph.NetBird.Tag = "entry" },
		func(p *NetworkPlan) { p.Graph.NetBird.ResourceID = "" },
		func(p *NetworkPlan) { p.Graph.NetBird.OverlayID = strings.Repeat("a", 65) },
		func(p *NetworkPlan) { p.Graph.NetBird.NetworkID = "foreign/path" },
		func(p *NetworkPlan) { p.Graph.NetBird.IdentityEpoch = 0 },
		func(p *NetworkPlan) { p.Graph.NetBird.IdentityEpoch = 9007199254740992 },
		func(p *NetworkPlan) { p.Graph.NetBird.ManagementURL = "http://overlay.example.invalid" },
		func(p *NetworkPlan) { p.Graph.NetBird.ManagementURL = "https://overlay.example.invalid/token" },
		func(p *NetworkPlan) {
			p.Graph.NetBird.ManagementURL = (&url.URL{Scheme: "https", Host: "overlay.example.invalid", User: url.UserPassword("fixture-user", "fixture-password")}).String()
		},
		func(p *NetworkPlan) { p.Graph.NetBird.ManagementURL = "https://OVERLAY.example.invalid:443/" },
		func(p *NetworkPlan) { p.Graph.NetBird.Hostname = "invalid.name" },
		func(p *NetworkPlan) { p.Graph.NetBird.Hostname = "-invalid" },
		func(p *NetworkPlan) { p.Graph.NetBird.Mode = "auto" },
		func(p *NetworkPlan) { p.Graph.NetBird.Detour = "exit" },
		func(p *NetworkPlan) { p.Graph.NetBird.Mode = "vless" },
		func(p *NetworkPlan) { p.Graph.NetBird.Mode = "vless"; p.Graph.NetBird.Detour = "home" },
		func(p *NetworkPlan) { p.Graph.NetBird.Mode = "vless"; p.Graph.NetBird.Detour = "missing" },
		func(p *NetworkPlan) { p.Graph.NetBird.Mode = "vless"; p.Graph.NetBird.Detour = "entry" },
		func(p *NetworkPlan) {
			p.Graph.NetBird.Mode = "vless"
			p.Graph.NetBird.Detour = "mixed"
			p.Graph.Balancers = map[string]Balancer{"mixed": {Type: "selector", Members: []string{"exit", "direct"}}}
		},
		func(p *NetworkPlan) {
			p.Graph.NetBird.Mode = "vless"
			p.Graph.NetBird.Detour = "mixed"
			p.Graph.Balancers = map[string]Balancer{"mixed": {Type: "selector", Members: []string{"exit", "home"}}}
		},
		func(p *NetworkPlan) { p.Graph.Chains["clone"] = Chain{DialOrder: []string{"exit", "home"}} },
		func(p *NetworkPlan) {
			p.Network.DNSServers["home-dns"] = DNSServer{Transport: "netbird", Outbound: "direct"}
		},
		func(p *NetworkPlan) {
			p.Network.DNSServers["home-dns"] = DNSServer{Transport: "netbird", Outbound: "missing"}
		},
		func(p *NetworkPlan) {
			p.Network.DNSServers["home-dns"] = DNSServer{Transport: "netbird", Outbound: "home", Address: "resolver.example.invalid"}
		},
		func(p *NetworkPlan) {
			p.Network.DNSServers["home-dns"] = DNSServer{Transport: "netbird", Outbound: "home", Port: 53}
		},
		func(p *NetworkPlan) {
			p.Network.DNSServers["home-dns"] = DNSServer{Transport: "netbird", Outbound: "home", ServerName: "resolver.example.invalid"}
		},
		func(p *NetworkPlan) {
			p.Network.DNSServers["home-dns"] = DNSServer{Transport: "netbird", Outbound: "home", Path: "/dns-query"}
		},
	} {
		p := netbirdPlan()
		change(&p)
		if _, e := CompileNetworkPlan(context.Background(), p, defaultGraphResolver()); e == nil {
			t.Fatal("invalid overlay compiled", i)
		}
	}
	valid, _ := json.Marshal(netbirdPlan())
	for _, field := range []string{`"setupKey":"synthetic"`, `"setupReference":"caller"`, `"stateDirectory":"/caller"`, `"forceRelay":true`, `"provider":"tailscale"`, `"mode":"direct"`} {
		raw := bytes.Replace(valid, []byte(`"overlayId":"personal"`), []byte(`"overlayId":"personal",`+field), 1)
		if _, e := DecodeNetworkPlan(raw); e == nil {
			t.Fatal("unknown/duplicate overlay field admitted")
		}
	}
}

func TestManagedNetBirdVLESSSelectorsAndHomeFirstHopRespectNativeOwnershipAndHopBounds(t *testing.T) {
	p := netbirdPlan()
	p.Graph.NetBird.Hostname = ""
	p.Graph.NetBird.Mode = "vless"
	p.Graph.NetBird.Detour = "choose"
	p.Graph.Balancers = map[string]Balancer{"choose": {Type: "selector", Members: []string{"exit", "tunnel"}, Default: "exit"}}
	if _, e := CompileNetworkPlan(context.Background(), p, defaultGraphResolver()); e != nil {
		t.Fatal("all VLESS selector", e)
	}
	p.Graph.NetBird.Mode = "direct"
	p.Graph.NetBird.Detour = ""
	p.Graph.Chains["home-proxy"] = Chain{DialOrder: []string{"home", "exit"}}
	p.Graph.Final = "home-proxy"
	if _, e := CompileNetworkPlan(context.Background(), p, defaultGraphResolver()); e != nil {
		t.Fatal("home first TCP hop", e)
	}
	for _, bad := range [][]json.RawMessage{
		{json.RawMessage(`{`)},
		{json.RawMessage(`{"type":"vless"}`)},
		{json.RawMessage(`{"type":"selector","tag":"x","outbounds":[]}`)},
		{json.RawMessage(`{"type":"selector","tag":"x","outbounds":["x"]}`)},
		{json.RawMessage(`{"type":"selector","tag":"x","outbounds":["absent"]}`)},
		{json.RawMessage(`{"type":"selector","tag":"x","outbounds":{}}`)},
	} {
		if netbirdVLESSDetour(bad, "x") == nil {
			t.Fatal("invalid native detour admitted")
		}
	}
	shared := []json.RawMessage{json.RawMessage(`{"type":"selector","tag":"root","outbounds":["shared","shared"]}`), json.RawMessage(`{"type":"selector","tag":"shared","outbounds":["leaf"]}`), json.RawMessage(`{"type":"vless","tag":"leaf"}`)}
	if netbirdVLESSDetour(shared, "root") != nil {
		t.Fatal("shared all-VLESS subtree")
	}
}
