// Package egress enforces the server-side network boundary before every dial.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrInvalid = errors.New("egress_invalid")
var ErrAddress = errors.New("egress_address_denied")
var ErrUnavailable = errors.New("egress_unavailable")

type Options struct {
	Roots    *x509.CertPool
	Networks []netip.Prefix
	// Fixture is owner-configured and only valid for a literal loopback endpoint.
	// Network/UI request fields cannot enable this option.
	Fixture bool
}

func (Options) String() string   { return "EgressOptions([redacted])" }
func (Options) GoString() string { return "EgressOptions([redacted])" }

var specialV4 = []netip.Prefix{
	netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 0, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 0, 0}), 15),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{240, 0, 0, 0}), 4),
}
var carrier = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)
var metadataV4 = netip.AddrFrom4([4]byte{100, 100, 100, 200})
var metadataV6 = netip.AddrFrom16([16]byte{0xfd, 0, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x54})

func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is6() {
		if !netip.MustParsePrefix("2000::/3").Contains(ip) {
			return false
		}
		for _, s := range []string{"2001::/32", "2001:db8::/32", "2002::/16"} {
			if netip.MustParsePrefix(s).Contains(ip) {
				return false
			}
		}
	}
	for _, p := range specialV4 {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
func permitted(ip netip.Addr, options Options) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip == metadataV4 || ip == metadataV6 || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if PublicIP(ip) {
		return true
	}
	if !(ip.IsPrivate() || carrier.Contains(ip) || options.Fixture && ip.IsLoopback()) {
		return false
	}
	for _, p := range options.Networks {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type lookup func(context.Context, string, string) ([]netip.Addr, error)

func NewTransport(endpoint string, options Options) (*http.Transport, error) {
	return newTransport(endpoint, options, net.DefaultResolver.LookupNetIP)
}
func newTransport(endpoint string, options Options, resolve lookup) (*http.Transport, error) {
	u, e := url.Parse(endpoint)
	if e != nil || len(endpoint) > 8192 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || len(options.Networks) > 16 || resolve == nil {
		return nil, ErrInvalid
	}
	host := u.Hostname()
	if strings.IndexFunc(host, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return nil, ErrInvalid
	}
	if options.Fixture {
		ip, e := netip.ParseAddr(host)
		if e != nil || !ip.IsLoopback() {
			return nil, ErrInvalid
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, ErrInvalid
	}
	for _, p := range options.Networks {
		minimum := 8
		if p.Addr().Is6() {
			minimum = 32
		}
		if !p.IsValid() || p != p.Masked() || p.Bits() < minimum {
			return nil, ErrInvalid
		}
	}
	options.Networks = append([]netip.Prefix(nil), options.Networks...)
	roots := options.Roots
	if roots != nil {
		roots = roots.Clone()
	}
	address := net.JoinHostPort(host, port)
	t := &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2, MaxResponseHeaderBytes: 32 * 1024, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != address {
			return nil, ErrAddress
		}
		ips, e := resolve(ctx, "ip", host)
		if e != nil {
			return nil, ErrUnavailable
		}
		if len(ips) == 0 || len(ips) > 8 {
			return nil, ErrAddress
		}
		for _, ip := range ips {
			if !permitted(ip, options) {
				return nil, ErrAddress
			}
		}
		for _, ip := range ips {
			if ctx.Err() != nil {
				return nil, ErrUnavailable
			}
			conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
			if e == nil {
				return conn, nil
			}
		}
		return nil, ErrUnavailable
	}
	return t, nil
}
