package configuration

import "net/netip"

// LiteralNetworkImpact reports only explicitly configured literal dependencies.
type LiteralNetworkImpact struct {
	DNSAddress  bool `json:"dnsAddress"`
	RoutePrefix bool `json:"routePrefix"`
}

func reviewLiteralNetworks(settings NetworkSettings) LiteralNetworkImpact {
	impact := LiteralNetworkImpact{}
	for _, server := range settings.DNSServers {
		if addr, err := netip.ParseAddr(server.Address); err == nil {
			addr = addr.Unmap().WithZone("")
			impact.DNSAddress = isLocalPrefix(netip.PrefixFrom(addr, addr.BitLen()))
			if impact.DNSAddress {
				break
			}
		}
	}
	for _, rule := range settings.Rules {
		if rule.Action != "route" {
			continue
		}
		for _, value := range rule.IPPrefixes {
			if prefix, err := netip.ParsePrefix(value); err == nil && isLocalPrefix(prefix) {
				impact.RoutePrefix = true
				return impact
			}
		}
	}
	return impact
}

func isLocalPrefix(prefix netip.Prefix) bool {
	addr, bits := prefix.Masked().Addr(), prefix.Bits()
	if addr.Is4In6() {
		addr, bits = addr.Unmap(), bits-96
	}
	if addr.Is4() {
		return isLocalIPv4(addr, bits)
	}
	switch {
	case addr.IsPrivate():
		return bits >= 7
	case addr.IsLinkLocalUnicast():
		return bits >= 10
	case addr.IsLoopback():
		return bits == 128
	default:
		return false
	}
}

func isLocalIPv4(addr netip.Addr, bits int) bool {
	octets := addr.As4()
	switch {
	case addr.IsLoopback():
		return bits >= 8
	case addr.IsLinkLocalUnicast():
		return bits >= 16
	case addr.IsPrivate():
		switch octets[0] {
		case 10:
			return bits >= 8
		case 172:
			return bits >= 12
		case 192:
			return bits >= 16
		}
	case octets[0] == 100 && octets[1]>>6 == 1:
		// RFC 6598 shared address space.
		return bits >= 10
	}
	return false
}
