package egress

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func loopback() netip.Addr { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }
func fixtureOptions() Options {
	return Options{Fixture: true, Networks: []netip.Prefix{netip.PrefixFrom(loopback(), 32)}}
}

func TestAddressScopeAndMetadataDenial(t *testing.T) {
	public := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	private := netip.AddrFrom4([4]byte{10, 1, 2, 3})
	if !PublicIP(public) || PublicIP(private) || PublicIP(loopback()) || PublicIP(metadataV4) || PublicIP(metadataV6) {
		t.Fatal("public boundary")
	}
	if !permitted(private, Options{Networks: []netip.Prefix{netip.PrefixFrom(private, 32)}}) || permitted(private, Options{}) {
		t.Fatal("private requires exact owner grant")
	}
	if permitted(loopback(), Options{Networks: fixtureOptions().Networks}) || !permitted(loopback(), fixtureOptions()) {
		t.Fatal("loopback production/fixture distinction")
	}
	if permitted(metadataV4, Options{Networks: []netip.Prefix{netip.PrefixFrom(metadataV4, 32)}}) || permitted(metadataV6, Options{Networks: []netip.Prefix{netip.PrefixFrom(metadataV6, 128)}}) {
		t.Fatal("metadata exception")
	}
	for _, ip := range []netip.Addr{netip.AddrFrom4([4]byte{169, 254, 1, 1}), netip.AddrFrom4([4]byte{224, 1, 1, 1}), netip.Addr{}, netip.IPv4Unspecified(), netip.MustParseAddr("2001:db8::1")} {
		if permitted(ip, fixtureOptions()) {
			t.Fatal("special address allowed")
		}
	}
	for _, p := range specialV4 {
		if PublicIP(p.Addr()) {
			t.Fatal("special allocation became public")
		}
	}
	if !PublicIP(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("public IPv6 unavailable")
	}
}
func TestTLSAndOriginBoundaries(t *testing.T) {
	calls := atomic.Int32{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "synthetic") }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	opts := fixtureOptions()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	opts.Roots = pool
	tr, e := NewTransport(server.URL, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr}
	res, e := client.Get(server.URL)
	if e != nil {
		t.Fatal("trusted fixture connection")
	}
	res.Body.Close()
	if calls.Load() != 1 {
		t.Fatal("request not delivered")
	}
	if _, e = tr.DialContext(context.Background(), "tcp", "wrong.example.invalid:443"); !errors.Is(e, ErrAddress) {
		t.Fatal("origin changed")
	}
	opts.Fixture = false
	blocked, e := NewTransport(server.URL, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer blocked.CloseIdleConnections()
	if _, e = (&http.Client{Transport: blocked}).Get(server.URL); e == nil {
		t.Fatal("production loopback was allowed")
	}
	if calls.Load() != 1 {
		t.Fatal("forbidden dial reached fixture")
	}
	opts.Fixture = true
	opts.Roots = nil
	untrusted, e := NewTransport(server.URL, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer untrusted.CloseIdleConnections()
	if _, e = (&http.Client{Transport: untrusted}).Get(server.URL); e == nil {
		t.Fatal("TLS trust bypass")
	}
}
func TestEveryDNSAnswerAndEveryNewConnection(t *testing.T) {
	options := fixtureOptions()
	var count atomic.Int32
	resolver := func(context.Context, string, string) ([]netip.Addr, error) {
		count.Add(1)
		return []netip.Addr{loopback(), metadataV4}, nil
	}
	tr, e := newTransport("https://127.0.0.1:1", options, resolver)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = tr.DialContext(context.Background(), "tcp", "127.0.0.1:1"); !errors.Is(e, ErrAddress) {
			t.Fatal("mixed answer allowed")
		}
	}
	if count.Load() != 2 {
		t.Fatal("DNS result retained across dials")
	}
	for _, lookup := range []lookup{
		func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("synthetic-resolver-error")
		},
		func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil },
		func(context.Context, string, string) ([]netip.Addr, error) { return make([]netip.Addr, 9), nil },
	} {
		tr, e := newTransport("https://127.0.0.1:1", options, lookup)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tr.DialContext(context.Background(), "tcp", "127.0.0.1:1"); e == nil {
			t.Fatal("unbounded/unavailable resolver accepted")
		}
	}
	tr, e = newTransport("https://127.0.0.1:1", options, func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{loopback()}, nil })
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = tr.DialContext(ctx, "tcp", "127.0.0.1:1"); e == nil {
		t.Fatal("cancel ignored")
	}
}
func TestTransportConfigurationBounds(t *testing.T) {
	for _, endpoint := range []string{"http://proxy.example.invalid", "https://proxy.example.invalid:0", "https://proxy.example.invalid:65536", "https://proxy.example.invalid#fragment", "not-url", "https://"} {
		if _, e := NewTransport(endpoint, Options{}); e == nil {
			t.Fatal("invalid endpoint")
		}
	}
	if _, e := NewTransport("https://proxy.example.invalid", fixtureOptions()); e == nil {
		t.Fatal("fixture option escaped literal loopback")
	}
	for _, options := range []Options{{Networks: make([]netip.Prefix, 9)}, {Networks: []netip.Prefix{{}}}, {Networks: []netip.Prefix{netip.PrefixFrom(loopback(), 0)}}, {Networks: []netip.Prefix{netip.PrefixFrom(loopback(), 24)}}} {
		if _, e := NewTransport("https://proxy.example.invalid", options); e == nil {
			t.Fatal("unsafe/ambiguous network grant")
		}
	}
}

func TestExplicitNetworkGrantCountBoundary(t *testing.T) {
	networks := make([]netip.Prefix, 16)
	for i := range networks {
		networks[i] = netip.PrefixFrom(loopback(), 32)
	}
	tr, e := NewTransport("https://127.0.0.1", Options{Fixture: true, Networks: networks})
	if e != nil {
		t.Fatal("valid grant-count boundary")
	}
	tr.CloseIdleConnections()
	if _, e = NewTransport("https://127.0.0.1", Options{Fixture: true, Networks: append(networks, networks[0])}); e == nil {
		t.Fatal("network grant count exceeded")
	}
}
