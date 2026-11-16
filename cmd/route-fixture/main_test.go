//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These deterministic unit-only credentials are never CLI defaults or examples.
// RFC1918 values below are synthetic and are assembled, not user LAN data.
func syntheticConfig() config {
	var cfg config
	cfg.SchemaVersion = 1
	cfg.ListenIP = netip.AddrFrom4([4]byte{10, 254, 254, 10}).String()
	cfg.ExpectedPeerIP = netip.AddrFrom4([4]byte{10, 254, 254, 11}).String()
	cfg.IngressPorts.A, cfg.IngressPorts.B = 31080, 31081
	cfg.TTLSeconds = 30
	cfg.Branches.A = branchCredentials{credential{"entry-a", "unit-only-a"}, credential{"exit-a", "unit-only-a"}}
	cfg.Branches.B = branchCredentials{credential{"entry-b", "unit-only-b"}, credential{"exit-b", "unit-only-b"}}
	return cfg
}

func encodedConfig(t *testing.T, cfg config) []byte {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("could not encode synthetic fixture configuration")
	}
	return raw
}

func TestRouteFixtureConfigClosedShapeBoundsAndNoProductionLoopbackBypass(t *testing.T) {
	cfg := syntheticConfig()
	if _, err := parseConfig(encodedConfig(t, cfg)); err != nil {
		t.Fatal("valid synthetic config rejected")
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.SchemaVersion = 2 },
		func(c *config) { c.ListenIP = "127.0.0.1" },
		func(c *config) { c.ListenIP = "0.0.0.0" },
		func(c *config) { c.ListenIP = "192.0.2.80" },
		func(c *config) { c.ListenIP = "::1" },
		func(c *config) { c.ExpectedPeerIP = "127.0.0.1" },
		func(c *config) { c.ExpectedPeerIP = "192.0.2.81" },
		func(c *config) { c.IngressPorts.A = 1023 },
		func(c *config) { c.IngressPorts.B = c.IngressPorts.A },
		func(c *config) { c.TTLSeconds = 29 },
		func(c *config) { c.TTLSeconds = 3601 },
		func(c *config) { c.Branches.A.Entry.Username = "" },
		func(c *config) { c.Branches.A.Entry.Username = "bad:name" },
		func(c *config) { c.Branches.B.Exit.Password = strings.Repeat("x", 129) },
		func(c *config) { c.Branches.B.Exit.Password = "bad\nvalue" },
		func(c *config) { c.Branches.A.Exit.Password = "non-ascii-\u00e9" },
	} {
		changed := cfg
		mutate(&changed)
		if _, err := parseConfig(encodedConfig(t, changed)); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	for _, ttl := range []int{30, 3600} {
		changed := cfg
		changed.TTLSeconds = ttl
		changed.IngressPorts.A, changed.IngressPorts.B = 1024, 65535
		changed.Branches.A.Entry.Password = strings.Repeat("x", 128)
		if _, err := parseConfig(encodedConfig(t, changed)); err != nil {
			t.Fatal("valid exact boundary rejected")
		}
	}
	raw := encodedConfig(t, cfg)
	for _, invalid := range [][]byte{
		nil, bytes.Repeat([]byte(" "), maximumConfig+1),
		append(append([]byte(nil), raw...), []byte("{}")...),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1),
		bytes.Replace(raw, []byte(`"username"`), []byte(`"Username"`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"unrecognized":1`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":null`), 1),
		bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1.0`), 1),
		bytes.Replace(raw, []byte(`"ttlSeconds":30`), []byte(`"ttlSeconds":3e1`), 1),
		bytes.Replace(raw, []byte(`"a":31080`), []byte(`"a":65536`), 1),
		bytes.Replace(raw, []byte(`"username":"entry-a"`), []byte(`"username":null`), 1),
		bytes.Replace(raw, []byte(`"username":"entry-a"`), []byte(`"username":[]`), 1),
		bytes.Replace(raw, []byte(`"password":"unit-only-a"`), []byte(`"password":"unit-only-a","password":"unit-only-a"`), 1),
	} {
		if _, err := parseConfig(invalid); err == nil {
			t.Fatal("open, duplicate, case-collapsed, null or malformed JSON accepted")
		}
	}
}

func TestRouteFixtureConfigFileMustBeOwnedRegularExact0600AndBounded(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "runtime.json")
	raw := encodedConfig(t, syntheticConfig())
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal("owned 0600 file rejected")
	}
	for _, mode := range []os.FileMode{0644, 0640, 0400, 0700, 0600 | os.ModeSetuid, 0600 | os.ModeSetgid, 0600 | os.ModeSticky} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("non-0600 permissions accepted")
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{directory, link, fifo, filepath.Join(directory, "absent.json")} {
		if _, err := loadConfig(invalid); err == nil {
			t.Fatal("non-owned regular file path accepted")
		}
	}
	for _, size := range []int{0, maximumConfig + 1} {
		if err := os.WriteFile(path, bytes.Repeat([]byte(" "), size), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("unbounded config accepted")
		}
	}
}

func loopbackFixture(t *testing.T, change func(*config)) *fixture {
	t.Helper()
	cfg := syntheticConfig()
	// Unit seam only: parseConfig above must reject this production input.
	cfg.ListenIP, cfg.ExpectedPeerIP = "127.0.0.1", "127.0.0.1"
	cfg.IngressPorts.A, cfg.IngressPorts.B = 0, 0
	if change != nil {
		change(&cfg)
	}
	f, err := startFixture(context.Background(), cfg)
	if err != nil {
		t.Fatal("unit-only fixture did not start")
	}
	t.Cleanup(f.Close)
	awaitFixture(t, func() bool { return len(f.slots) == 5 && f.counters.ActiveAccepted.Load() == 0 })
	return f
}

func awaitFixture(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("fixture condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func dialIngress(t *testing.T, f *fixture, index int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", f.branches[index].address.String(), time.Second)
	if err != nil {
		t.Fatal("could not reach owned ingress")
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func socksAuthenticate(t *testing.T, conn net.Conn, cred credential) {
	t.Helper()
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal("SOCKS greeting failed")
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{5, 2}) {
		t.Fatal("RFC1929 was not mandatory")
	}
	auth := append([]byte{1, byte(len(cred.Username))}, []byte(cred.Username)...)
	auth = append(auth, byte(len(cred.Password)))
	auth = append(auth, []byte(cred.Password)...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatal("SOCKS authentication write failed")
	}
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{1, 0}) {
		t.Fatal("correct synthetic credentials rejected")
	}
}

func socksTunnel(t *testing.T, f *fixture, index int) net.Conn {
	t.Helper()
	conn := dialIngress(t, f, index)
	b := f.branches[index]
	socksAuthenticate(t, conn, b.credentials.Entry)
	request := append([]byte{5, 1, 0, 1}, b.virtualExit[:]...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal("SOCKS destination write failed")
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatal("designated virtual exit was not mapped")
	}
	return conn
}

func connectHeader(cred credential) string {
	return "CONNECT " + virtualTarget + " HTTP/1.1\r\nHost: " + virtualTarget + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password)) + "\r\n\r\n"
}

func proofRequest(nonce string) string {
	return "GET /proof/" + nonce + " HTTP/1.1\r\nHost: " + virtualTarget + "\r\n\r\n"
}

func readConnectSuccess(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil || line != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatal("HTTP exit did not establish CONNECT")
	}
	if blank, err := reader.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatal("unexpected CONNECT success framing")
	}
}

func httpTunnel(t *testing.T, f *fixture, index int) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn := socksTunnel(t, f, index)
	if _, err := io.WriteString(conn, connectHeader(f.branches[index].credentials.Exit)); err != nil {
		t.Fatal("HTTP CONNECT write failed")
	}
	reader := bufio.NewReader(conn)
	readConnectSuccess(t, reader)
	return conn, reader
}

func proof(t *testing.T, f *fixture, index int, nonce string) {
	t.Helper()
	conn := socksTunnel(t, f, index)
	defer conn.Close()
	proofOnTunnel(t, f, index, nonce, conn)
}

func proofOnTunnel(t *testing.T, f *fixture, index int, nonce string, conn net.Conn) {
	t.Helper()
	// One write deliberately pipelines the target request with CONNECT. Both
	// proxy layers must preserve their bufio-prefetched bytes.
	if _, err := io.WriteString(conn, connectHeader(f.branches[index].credentials.Exit)+proofRequest(nonce)); err != nil {
		t.Fatal("two-hop request write failed")
	}
	reader := bufio.NewReader(conn)
	readConnectSuccess(t, reader)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal("target response missing")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil || response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/json" || string(body) != `{"nonce":"`+nonce+`"}` {
		t.Fatal("actual two-hop nonce proof did not match")
	}
}

func TestRouteFixtureRealTwoHopTCPAuthExactDestinationsAndPrefetchedNonce(t *testing.T) {
	f := loopbackFixture(t, nil)
	for index, nonce := range []string{"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"} {
		proof(t, f, index, nonce)
		awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	}
	snapshot := f.snapshot("status")
	if snapshot.SOCKSAuth != 2 || snapshot.HTTPAuth != 2 || snapshot.Proofs != 2 || snapshot.Accepted != 6 || snapshot.ActiveAccepted != 0 {
		t.Fatal("not all actual protocol stages completed")
	}
	for _, listener := range []*net.TCPListener{f.target, f.branches[0].exit, f.branches[1].exit} {
		if !listener.Addr().(*net.TCPAddr).IP.IsLoopback() || listener.Addr().(*net.TCPAddr).Port == 0 {
			t.Fatal("an internal stage escaped its loopback ephemeral listener")
		}
	}
}

func TestRouteFixtureTwoConcurrentNonceFlowsCompleteWithinStrictEightReservations(t *testing.T) {
	f := loopbackFixture(t, nil)
	var workers sync.WaitGroup
	for index := range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			proof(t, f, index, strings.Repeat(string(rune('a'+index)), 32))
		}()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		f.Close()
		workers.Wait()
		t.Fatal("strict accept reservations deadlocked two nonce flows")
	}
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	if f.counters.Proofs.Load() != 2 || f.counters.Accepted.Load() != 6 {
		t.Fatal("both real TCP chains did not reach the common target")
	}
}

func TestRouteFixtureWrongSourceAndSOCKSNoAuthCannotReachExit(t *testing.T) {
	f := loopbackFixture(t, func(cfg *config) { cfg.ExpectedPeerIP = "127.0.0.2" })
	conn := dialIngress(t, f, 0)
	if _, err := conn.Write([]byte{5, 1, 2}); err == nil {
		var reply [2]byte
		if _, err := conn.Read(reply[:]); err == nil {
			t.Fatal("wrong source was allowed to negotiate")
		}
	}
	awaitFixture(t, func() bool { return f.counters.Rejected.Load() > 0 })
	if f.counters.Accepted.Load() != 0 || f.counters.SOCKSAuth.Load() != 0 {
		t.Fatal("wrong source acquired an accepted slot")
	}
	f.Close()
	f = loopbackFixture(t, nil)
	conn = dialIngress(t, f, 0)
	_, _ = conn.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{5, 255}) {
		t.Fatal("unauthenticated SOCKS mode was not rejected")
	}
	_ = conn.Close()
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	if f.counters.HTTPAuth.Load() != 0 || f.counters.Accepted.Load() != 1 {
		t.Fatal("unauthenticated request reached an internal listener")
	}
}

func TestRouteFixtureWrongSOCKSCredentialsCommandsTypesAndDestinationCannotDial(t *testing.T) {
	f := loopbackFixture(t, nil)
	conn := dialIngress(t, f, 0)
	_, _ = conn.Write([]byte{5, 1, 2})
	var reply [2]byte
	_, _ = io.ReadFull(conn, reply[:])
	_, _ = conn.Write([]byte{1, 1, 'x', 1, 'x'})
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{1, 1} {
		t.Fatal("wrong SOCKS credentials were accepted")
	}
	_ = conn.Close()
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	base := append([]byte{5, 1, 0, 1}, f.branches[0].virtualExit[:]...)
	for _, mutate := range []func([]byte){
		func(b []byte) { b[1] = 2 }, func(b []byte) { b[1] = 3 },
		func(b []byte) { b[3] = 3 }, func(b []byte) { b[3] = 4 },
		func(b []byte) { b[2] = 1 }, func(b []byte) { b[7] = 81 },
		func(b []byte) { b[9]++ },
	} {
		conn := dialIngress(t, f, 0)
		socksAuthenticate(t, conn, f.branches[0].credentials.Entry)
		request := append([]byte(nil), base...)
		mutate(request)
		_, _ = conn.Write(request)
		if _, err := conn.Read(reply[:]); err == nil {
			t.Fatal("unsupported SOCKS request returned success")
		}
		_ = conn.Close()
		awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	}
	if f.counters.HTTPAuth.Load() != 0 || f.counters.Proofs.Load() != 0 || f.counters.Accepted.Load() != 8 {
		t.Fatal("unsupported SOCKS destination reached another accepted stage")
	}
}

func TestRouteFixtureHTTPConnectRejectsAmbiguousInjectedUnauthorizedAndUnboundedHeaders(t *testing.T) {
	f := loopbackFixture(t, nil)
	valid := connectHeader(f.branches[0].credentials.Exit)
	for _, invalid := range []string{
		strings.Replace(valid, "CONNECT ", "GET ", 1),
		strings.Replace(valid, virtualTarget, "192.0.2.84:44383", 1),
		strings.Replace(valid, "Host: "+virtualTarget, "Host: 192.0.2.84:44383", 1),
		strings.Replace(valid, "Host:", "Host :", 1),
		strings.Replace(valid, "Host: "+virtualTarget+"\r\n", "Host: "+virtualTarget+"\r\nhOsT: "+virtualTarget+"\r\n", 1),
		strings.Replace(valid, "Proxy-Authorization:", " Proxy-Authorization:", 1),
		strings.Replace(valid, "\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n", 1),
		strings.Replace(valid, "\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n", 1),
		strings.Replace(valid, "\r\n\r\n", "\r\nTrailer: Host\r\n\r\n", 1),
		strings.Replace(valid, "\r\n\r\n", "\r\nUnknown: synthetic\r\n\r\n", 1),
		strings.Replace(valid, "\r\n", "\n", 1),
		strings.Replace(valid, "Basic ", "Basic invalid", 1),
		strings.Replace(valid, "\r\n\r\n", "\r\nUser-Agent: "+strings.Repeat("x", maximumHeaders)+"\r\n\r\n", 1),
		strings.Replace(valid, "\r\n\r\n", "\r\npRoXy-AuThOrIzAtIoN: Basic synthetic\r\n\r\n", 1),
	} {
		conn := socksTunnel(t, f, 0)
		_, _ = io.WriteString(conn, invalid)
		var response [1]byte
		if _, err := conn.Read(response[:]); err == nil {
			t.Fatal("invalid CONNECT yielded a successful response")
		}
		_ = conn.Close()
		awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	}
	if f.counters.HTTPAuth.Load() != 0 || f.counters.Proofs.Load() != 0 {
		t.Fatal("invalid HTTP request reached target")
	}
}

func TestRouteFixtureTargetOnlyEchoesExactNonceAndSupportsEmptyTCPHealth(t *testing.T) {
	f := loopbackFixture(t, nil)
	conn := dialIngress(t, f, 0)
	_ = conn.Close()
	awaitFixture(t, func() bool { return f.counters.EmptyHealth.Load() == 1 && f.counters.ActiveAccepted.Load() == 0 })
	conn = socksTunnel(t, f, 0)
	_ = conn.Close()
	awaitFixture(t, func() bool { return f.counters.EmptyHealth.Load() == 2 && f.counters.ActiveAccepted.Load() == 0 })
	conn, _ = httpTunnel(t, f, 0)
	_ = conn.Close()
	awaitFixture(t, func() bool { return f.counters.EmptyHealth.Load() == 3 && f.counters.ActiveAccepted.Load() == 0 })
	for _, request := range []string{
		proofRequest("0123456789abcdef0123456789abcde"),
		proofRequest("0123456789abcdef0123456789abcdeG"),
		strings.Replace(proofRequest(strings.Repeat("a", 32)), "GET ", "POST ", 1),
		strings.Replace(proofRequest(strings.Repeat("a", 32)), "HTTP/1.1", "HTTP/1.0", 1),
		proofRequest(strings.Repeat("a", 32)) + "body",
	} {
		conn, reader := httpTunnel(t, f, 0)
		_, _ = io.WriteString(conn, request)
		var response [1]byte
		if _, err := reader.Read(response[:]); err == nil {
			t.Fatal("invalid target request returned proof")
		}
		_ = conn.Close()
		awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	}
	if f.counters.Proofs.Load() != 0 {
		t.Fatal("invalid nonce was counted as proof")
	}
}

func TestRouteFixtureBranchDisableClosesOwnedTrafficReopensSameAddressAndFencesOldGeneration(t *testing.T) {
	f := loopbackFixture(t, nil)
	proof(t, f, 0, strings.Repeat("a", 32))
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	old, _ := httpTunnel(t, f, 0)
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 3 })
	preserved := socksTunnel(t, f, 1)
	address := f.branches[0].address.String()
	oldGeneration := f.branches[0].generation
	if f.controlSignal(syscall.SIGUSR1) != "a_disabled" {
		t.Fatal("disable A failed")
	}
	var buffer [1]byte
	if _, err := old.Read(buffer[:]); err == nil {
		t.Fatal("disabled branch retained actual traffic")
	}
	_ = old.Close()
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 2 })
	if conn, err := net.DialTimeout("tcp4", address, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("disabled ingress still listens")
	}
	proofOnTunnel(t, f, 1, strings.Repeat("b", 32), preserved)
	_ = preserved.Close()
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	if f.controlSignal(syscall.SIGUSR2) != "a_enabled" || f.branches[0].address.String() != address {
		t.Fatal("A did not reopen its exact address")
	}
	if conn, err := f.dialOwned(f.branches[0], oldGeneration, f.branches[0].exit.Addr()); err == nil {
		f.releaseDial(conn)
		t.Fatal("old generation acquired a new outbound")
	}
	for _, other := range []net.Addr{f.branches[1].exit.Addr(), &net.TCPAddr{IP: net.IPv4(192, 0, 2, 84), Port: 44383}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}} {
		if conn, err := f.dialOwned(f.branches[0], f.branches[0].generation, other); err == nil {
			f.releaseDial(conn)
			t.Fatal("derived dial accepted a non-owned destination")
		}
	}
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	if f.controlSignal(syscall.SIGHUP) != "b_disabled" {
		t.Fatal("disable B failed")
	}
	proof(t, f, 0, strings.Repeat("c", 32))
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	if f.controlSignal(syscall.SIGHUP) != "b_enabled" {
		t.Fatal("B did not reopen")
	}
	if snapshot := f.snapshot("status"); snapshot.Proofs != 3 || !snapshot.AEnabled || !snapshot.BEnabled || snapshot.AGeneration != 3 || snapshot.BGeneration != 3 {
		t.Fatal("branch lifecycle counters did not reflect A-B-A proof")
	}
}

func TestRouteFixtureInternalAcceptRequiresPairedDialAndRejectsQueuedOldGeneration(t *testing.T) {
	f := loopbackFixture(t, nil)
	// Knowledge of the exit credentials is insufficient for an unaffiliated
	// local TCP client: only the fixture's exact owned dial can enter this stage.
	unpaired, err := net.DialTimeout("tcp4", f.branches[0].exit.Addr().String(), time.Second)
	if err != nil {
		t.Fatal("could not create synthetic unpaired connection")
	}
	defer unpaired.Close()
	_ = unpaired.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(unpaired, connectHeader(f.branches[0].credentials.Exit)+proofRequest(strings.Repeat("e", 32)))
	started := time.Now()
	var response [1]byte
	_, err = unpaired.Read(response[:])
	if err == nil {
		t.Fatal("unpaired internal TCP client reached HTTP CONNECT")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() || time.Since(started) > 3*time.Second {
		t.Fatal("unpaired accept wait was not bounded independently")
	}
	_ = unpaired.Close()
	oldGeneration := f.branches[0].generation
	queued, err := net.DialTimeout("tcp4", f.target.Addr().String(), time.Second)
	if err != nil {
		t.Fatal("could not create synthetic queued target connection")
	}
	defer f.releaseDial(queued)
	_ = queued.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(queued, proofRequest(strings.Repeat("f", 32)))
	if f.controlSignal(syscall.SIGUSR1) != "a_disabled" || f.controlSignal(syscall.SIGUSR2) != "a_enabled" {
		t.Fatal("could not advance the branch generation")
	}
	// Deliberately inject an obsolete internal handoff after reopen. Production
	// dialOwned rejects this at publication as well; the accept-side fence must
	// independently reject a queued connection containing already-buffered GET.
	key := connectionKey{queued.LocalAddr().String(), queued.RemoteAddr().String()}
	f.mu.Lock()
	obsolete := ownedConnection{f.branches[0], oldGeneration}
	f.owned[queued] = obsolete
	f.dialLinks[key] = ownedDial{obsolete, queued}
	close(f.linkChanged)
	f.linkChanged = make(chan struct{})
	f.mu.Unlock()
	if _, err := queued.Read(response[:]); err == nil {
		t.Fatal("queued old-generation target request returned a nonce")
	}
	f.releaseDial(queued)
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	if f.counters.HTTPAuth.Load() != 0 || f.counters.Proofs.Load() != 0 || f.counters.StaleOwnership.Load() != 1 || f.ctx.Err() != nil {
		t.Fatal("unpaired or stale target ownership reached application data")
	}
	proof(t, f, 0, strings.Repeat("a", 32))
}

type closeObserver struct {
	net.Conn
	beforeClose func()
}

func (c *closeObserver) Close() error { c.beforeClose(); return c.Conn.Close() }

func TestRouteFixtureDialLinkRemovedBeforeDescriptorReleaseAndOldCleanupCannotEraseReplacement(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	f := &fixture{owned: make(map[net.Conn]ownedConnection), dialLinks: make(map[connectionKey]ownedDial), linkChanged: make(chan struct{})}
	key := connectionKey{left.LocalAddr().String(), left.RemoteAddr().String()}
	observed := false
	underlying := &closeObserver{Conn: left, beforeClose: func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, found := f.dialLinks[key]; found {
			t.Error("numeric tuple was still published when the descriptor could be released")
		}
		observed = true
	}}
	old := &linkedConnection{Conn: underlying, fixture: f, key: key}
	f.dialLinks[key] = ownedDial{conn: old}
	f.owned[old] = ownedConnection{}
	if old.Close() != nil || !observed {
		t.Fatal("derived close did not retire its binding first")
	}
	newLeft, newRight := net.Pipe()
	defer newLeft.Close()
	defer newRight.Close()
	replacement := &linkedConnection{Conn: newLeft, fixture: f, key: key}
	f.mu.Lock()
	f.dialLinks[key] = ownedDial{conn: replacement}
	f.mu.Unlock()
	f.releaseDial(old)
	f.mu.Lock()
	kept := f.dialLinks[key].conn == replacement
	f.mu.Unlock()
	if !kept {
		t.Fatal("late cleanup erased a later tuple owner")
	}
	_ = replacement.Close()
}

func TestRouteFixtureGlobalEightAcceptedSlotsIncludeUnauthenticatedAndInternalStages(t *testing.T) {
	f := loopbackFixture(t, nil)
	// Four other idle listeners reserve permits before Accept. Four unauth
	// ingress clients exhaust the remaining capacity; there is no ninth
	// transient accepted FD, and no unbounded goroutine waiting for a permit.
	clients := make([]net.Conn, 0, 4)
	for range 4 {
		clients = append(clients, dialIngress(t, f, 0))
	}
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 4 && len(f.slots) == maximumAccepted })
	extra := dialIngress(t, f, 0)
	_ = extra.SetDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = extra.Write([]byte{5, 1, 2})
	var response [1]byte
	if _, err := extra.Read(response[:]); err == nil {
		t.Fatal("saturated listener negotiated without an accepted permit")
	}
	_ = extra.Close()
	if snapshot := f.snapshot("status"); snapshot.ActiveAccepted+int64(snapshot.ReservedAccept) > maximumAccepted || snapshot.ReservedAccept < 0 {
		t.Fatal("physical accepted slot ceiling exceeded")
	}
	for _, conn := range clients {
		_ = conn.Close()
	}
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	conn := socksTunnel(t, f, 0)
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 2 })
	_, _ = io.WriteString(conn, connectHeader(f.branches[0].credentials.Exit))
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 3 })
	f.Close()
	if f.counters.ActiveAccepted.Load() != 0 || len(f.slots) != 0 {
		t.Fatal("shutdown returned while accepted slots remained owned")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.owned) != 0 || len(f.dialLinks) != 0 {
		t.Fatal("shutdown leaked accepted or derived outbound sockets")
	}
}

type heldReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *heldReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func TestRouteFixtureRelayJoinsBothCopyWorkersBeforeReturningOnCancellation(t *testing.T) {
	left, client := net.Pipe()
	right, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	reader := &heldReader{started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(reader.release) }) }
	defer release()
	f := &fixture{}
	done := make(chan error, 1)
	go func() { done <- f.relay(left, reader, right, right) }()
	<-reader.started
	_ = target.Close()
	select {
	case <-done:
		t.Fatal("relay returned before the second physical copy worker exited")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not join the released worker")
	}
}

func TestRouteFixtureAggregateTrafficBudgetClosesActualTCPConnection(t *testing.T) {
	// Exercise the shared relay budget itself over real TCP, independently of
	// the stricter fixed-target HTTP protocol's much smaller header limit.
	pair := func() (*net.TCPConn, *net.TCPConn) {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal("could not create owned unit TCP pair")
		}
		defer listener.Close()
		client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal("could not dial owned unit TCP pair")
		}
		server, err := listener.AcceptTCP()
		if err != nil {
			_ = client.Close()
			t.Fatal("could not accept owned unit TCP pair")
		}
		for _, conn := range []*net.TCPConn{client, server} {
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			t.Cleanup(func() { _ = conn.Close() })
		}
		return server, client
	}
	left, client := pair()
	right, target := pair()
	f := &fixture{}
	var workers sync.WaitGroup
	workers.Add(1)
	done := make(chan error, 1)
	go func() { defer workers.Done(); done <- f.relay(left, left, right, right) }()
	defer func() {
		_ = client.Close()
		_ = target.Close()
		_ = left.Close()
		_ = right.Close()
		workers.Wait()
	}()
	for _, direction := range [][2]*net.TCPConn{{client, target}, {target, client}} {
		if _, err := direction[0].Write([]byte("duplex")); err != nil {
			t.Fatal("real TCP warm-up write failed")
		}
		var received [6]byte
		if _, err := io.ReadFull(direction[1], received[:]); err != nil || string(received[:]) != "duplex" {
			t.Fatal("relay did not preserve both directions")
		}
	}
	received := make(chan int64, 2)
	for _, conn := range []*net.TCPConn{client, target} {
		workers.Add(2)
		go func() {
			defer workers.Done()
			_, _ = conn.Write(bytes.Repeat([]byte("x"), maximumTransfer+1))
			_ = conn.CloseWrite()
		}()
		go func() {
			defer workers.Done()
			count, _ := io.Copy(io.Discard, conn)
			received <- count
		}()
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("aggregate quota did not close the actual relay")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("quota did not bound real TCP copying")
	}
	workers.Wait()
	observed := uint64(12 + <-received + <-received)
	if observed > f.counters.Transferred.Load() || f.counters.Transferred.Load() > maximumRelayed || maximumRelayed+maximumHeaders+1024 > maximumTransfer {
		t.Fatal("aggregate payload and reserved framing exceeded one MiB")
	}
}

func TestRouteFixtureTTLClosesAllListenersConnectionsAndRejectsReenable(t *testing.T) {
	f := loopbackFixture(t, func(cfg *config) { cfg.TTLSeconds = 1 })
	conn := socksTunnel(t, f, 0)
	_, _ = io.WriteString(conn, connectHeader(f.branches[0].credentials.Exit))
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 3 })
	select {
	case <-f.done:
	case <-time.After(3 * time.Second):
		t.Fatal("TTL did not finish owned cleanup")
	}
	for _, b := range f.branches {
		if opened, err := net.DialTimeout("tcp4", b.address.String(), time.Second); err == nil {
			_ = opened.Close()
			t.Fatal("TTL left ingress listening")
		}
	}
	if f.setBranch(0, true) == nil || f.counters.ActiveAccepted.Load() != 0 || len(f.slots) != 0 {
		t.Fatal("expired fixture resumed or retained physical slots")
	}
	if snapshot := f.snapshot("status"); snapshot.AEnabled || snapshot.BEnabled {
		t.Fatal("expired status claims a listening branch")
	}
}

func TestRouteFixtureUnauthenticatedReadDeadlineClosesBeforeIndependentTTL(t *testing.T) {
	f := loopbackFixture(t, func(cfg *config) { cfg.TTLSeconds = 60 })
	conn, err := net.DialTimeout("tcp4", f.branches[0].address.String(), time.Second)
	if err != nil {
		t.Fatal("owned ingress unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(35 * time.Second))
	started := time.Now()
	var buffer [1]byte
	_, err = conn.Read(buffer[:])
	if err == nil {
		t.Fatal("unauthenticated idle socket produced data")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("only the client's later deadline bounded the idle connection")
	}
	if elapsed := time.Since(started); elapsed < 29*time.Second || elapsed > 34*time.Second || f.ctx.Err() != nil {
		t.Fatal("connection was not bounded by its independent 30-second deadline")
	}
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
}

func TestRouteFixtureStatusAndRejectedCLIOnlyExposeFixedCounters(t *testing.T) {
	cfg := syntheticConfig()
	for _, value := range []any{cfg, &cfg, cfg.Branches.A, &cfg.Branches.A, cfg.Branches.A.Entry, &cfg.Branches.A.Entry} {
		if strings.Contains(fmt.Sprintf("%v %#v", value, value), cfg.Branches.A.Entry.Password) {
			t.Fatal("formatting disclosed credentials")
		}
	}
	f := loopbackFixture(t, nil)
	proof(t, f, 0, strings.Repeat("d", 32))
	awaitFixture(t, func() bool { return f.counters.ActiveAccepted.Load() == 0 })
	raw, err := json.Marshal(f.snapshot("status"))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{cfg.Branches.A.Entry.Username, cfg.Branches.A.Entry.Password, "127.0.0.1", virtualTarget, strings.Repeat("d", 32), "error", "nonce"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("status disclosed private or unstructured data")
		}
	}
	for _, args := range [][]string{{}, {"-unknown", "private-value"}, {"-config", "/synthetic/absent-private-path"}, {"-config", "missing", "private-extra"}} {
		var output bytes.Buffer
		if run(args, &output) != 2 || output.String() != "{\"event\":\"configuration_rejected\"}\n" {
			t.Fatal("CLI error echoed private input or an unbounded error")
		}
	}
}
