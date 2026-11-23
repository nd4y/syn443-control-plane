package configuration

import (
	"net/netip"
	"testing"
)

func TestLiteralNetworkReviewUsesWholePrefixesAndActiveRoutes(t *testing.T) {
	// Derive generic fixtures from the standard network classes.
	private := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	shared := netip.AddrFrom4([4]byte{100, 64, 0, 1})
	prefix := func(addr netip.Addr, bits int) string {
		return netip.PrefixFrom(addr, bits).Masked().String()
	}

	for _, tc := range []struct {
		name, address, prefix, action string
		want                          LiteralNetworkImpact
	}{
		{"ipv4", private.String(), prefix(private, 24), "route", LiteralNetworkImpact{true, true}},
		{"ipv6", "fd00:1::53", "fe80::/64", "route", LiteralNetworkImpact{true, true}},
		{"shared-network", shared.String(), prefix(shared, 12), "route", LiteralNetworkImpact{true, true}},
		{"nonprivate", "192.0.2.53", "192.0.2.0/24", "route", LiteralNetworkImpact{}},
		{"public-prefix-overlap", "resolver.example.invalid", prefix(private, 7), "route", LiteralNetworkImpact{}},
		{"default-prefix", "resolver.example.invalid", "::/0", "route", LiteralNetworkImpact{}},
		{"block-action", "resolver.example.invalid", prefix(private, 8), "block", LiteralNetworkImpact{}},
		{"mapped-loopback", "::ffff:127.0.0.1", "fc00::/7", "route", LiteralNetworkImpact{true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := NetworkSettings{DNSServers: map[string]DNSServer{"resolver": {Address: tc.address}},
				Rules: []RouteRule{{Action: tc.action, IPPrefixes: []string{tc.prefix}}}}
			if got := reviewLiteralNetworks(input); got != tc.want {
				t.Fatalf("literal categories: got %+v want %+v", got, tc.want)
			}
		})
	}
}
