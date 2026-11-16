//go:build linux

// route-fixture is a short-lived, source-restricted LAN acceptance fixture.
// It has no arbitrary dial, DNS, Internet proxy or credential-rendering mode.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maximumConfig   = 8192
	maximumHeaders  = 8192
	maximumTransfer = 1 << 20
	// Reserve the maximum HTTP header and more than the entire SOCKS framing
	// plus success replies. Thus framing + both relayed directions stay below
	// one MiB on each accepted TCP connection, not just on its payload.
	maximumRelayed    = maximumTransfer - maximumHeaders - 1024
	maximumAccepted   = 8
	connectionTimeout = 30 * time.Second
	virtualTarget     = "192.0.2.83:44383"
)

var errRejected = errors.New("fixture request rejected")

type credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type branchCredentials struct {
	Entry credential `json:"entry"`
	Exit  credential `json:"exit"`
}

type config struct {
	SchemaVersion  int    `json:"schemaVersion"`
	ListenIP       string `json:"listenIP"`
	ExpectedPeerIP string `json:"expectedPeerIP"`
	IngressPorts   struct {
		A uint16 `json:"a"`
		B uint16 `json:"b"`
	} `json:"ingressPorts"`
	TTLSeconds int `json:"ttlSeconds"`
	Branches   struct {
		A branchCredentials `json:"a"`
		B branchCredentials `json:"b"`
	} `json:"branches"`
}

// String and GoString deliberately redact credentials and network identifiers.
func (config) String() string              { return "route-fixture config [redacted]" }
func (config) GoString() string            { return "route-fixture config [redacted]" }
func (credential) String() string          { return "credential [redacted]" }
func (credential) GoString() string        { return "credential [redacted]" }
func (branchCredentials) String() string   { return "branch credentials [redacted]" }
func (branchCredentials) GoString() string { return "branch credentials [redacted]" }

func closedJSON(dec *json.Decoder, depth int) (any, error) {
	if depth > 5 {
		return nil, errRejected
	}
	token, err := dec.Token()
	if err != nil || token == nil {
		return nil, errRejected
	}
	if delim, ok := token.(json.Delim); ok {
		if delim != '{' {
			return nil, errRejected
		}
		object := make(map[string]any)
		for dec.More() {
			keyToken, err := dec.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || len(object) >= 8 {
				return nil, errRejected
			}
			if _, exists := object[key]; exists {
				return nil, errRejected
			}
			value, err := closedJSON(dec, depth+1)
			if err != nil {
				return nil, errRejected
			}
			object[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errRejected
		}
		return object, nil
	}
	switch token.(type) {
	case string, json.Number:
		return token, nil
	default:
		return nil, errRejected
	}
}

func exactObject(value any, keys ...string) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, found := object[key]; !found {
			return nil, false
		}
	}
	return object, true
}

func parseConfig(raw []byte) (config, error) {
	var result config
	if len(raw) == 0 || len(raw) > maximumConfig {
		return result, errRejected
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	value, err := closedJSON(decoder, 0)
	if err != nil {
		return result, errRejected
	}
	if _, err := decoder.Token(); err != io.EOF {
		return result, errRejected
	}
	root, ok := exactObject(value, "schemaVersion", "listenIP", "expectedPeerIP", "ingressPorts", "ttlSeconds", "branches")
	if !ok {
		return result, errRejected
	}
	if _, ok := exactObject(root["ingressPorts"], "a", "b"); !ok {
		return result, errRejected
	}
	branches, ok := exactObject(root["branches"], "a", "b")
	if !ok {
		return result, errRejected
	}
	for _, id := range []string{"a", "b"} {
		branch, ok := exactObject(branches[id], "entry", "exit")
		if !ok {
			return result, errRejected
		}
		for _, role := range []string{"entry", "exit"} {
			if _, ok := exactObject(branch[role], "username", "password"); !ok {
				return result, errRejected
			}
		}
	}
	owned, err := json.Marshal(value)
	if err != nil || json.Unmarshal(owned, &result) != nil {
		return config{}, errRejected
	}
	privateIPv4 := func(raw string) bool {
		address, err := netip.ParseAddr(raw)
		return err == nil && address.Is4() && address.IsPrivate() && address.String() == raw && !address.IsLoopback() && !address.IsUnspecified()
	}
	if result.SchemaVersion != 1 || !privateIPv4(result.ListenIP) || !privateIPv4(result.ExpectedPeerIP) || result.IngressPorts.A < 1024 || result.IngressPorts.B < 1024 || result.IngressPorts.A == result.IngressPorts.B || result.TTLSeconds < 30 || result.TTLSeconds > 3600 {
		return config{}, errRejected
	}
	for _, branch := range []branchCredentials{result.Branches.A, result.Branches.B} {
		for _, cred := range []credential{branch.Entry, branch.Exit} {
			if !validCredential(cred) {
				return config{}, errRejected
			}
		}
	}
	return result, nil
}

func validCredential(cred credential) bool {
	for _, value := range []string{cred.Username, cred.Password} {
		if len(value) == 0 || len(value) > 128 {
			return false
		}
		for _, char := range []byte(value) {
			if char < 33 || char > 126 {
				return false
			}
		}
	}
	return !strings.Contains(cred.Username, ":")
}

func loadConfig(path string) (config, error) {
	var empty config
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Size() <= 0 || before.Size() > maximumConfig {
		return empty, errRejected
	}
	// Lstat alone has a replacement race: a substituted FIFO could block
	// Open, or a symlink could read a different private inode. Linux flags
	// reject following links and keep a substituted special-file open bounded.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, errRejected
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0600 || after.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return empty, errRejected
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return empty, errRejected
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumConfig+1))
	if err != nil {
		return empty, errRejected
	}
	return parseConfig(raw)
}

type counters struct {
	Accepted       atomic.Uint64
	Rejected       atomic.Uint64
	SOCKSAuth      atomic.Uint64
	HTTPAuth       atomic.Uint64
	Proofs         atomic.Uint64
	EmptyHealth    atomic.Uint64
	Transferred    atomic.Uint64
	StaleOwnership atomic.Uint64
	ActiveAccepted atomic.Int64
}

type status struct {
	Event          string `json:"event"`
	Accepted       uint64 `json:"accepted"`
	Rejected       uint64 `json:"rejected"`
	SOCKSAuth      uint64 `json:"socksAuth"`
	HTTPAuth       uint64 `json:"httpAuth"`
	Proofs         uint64 `json:"proofs"`
	EmptyHealth    uint64 `json:"emptyHealth"`
	Transferred    uint64 `json:"transferred"`
	StaleOwnership uint64 `json:"staleOwnership"`
	ActiveAccepted int64  `json:"activeAccepted"`
	ReservedAccept int    `json:"reservedAccept"`
	AEnabled       bool   `json:"aEnabled"`
	BEnabled       bool   `json:"bEnabled"`
	AGeneration    uint64 `json:"aGeneration"`
	BGeneration    uint64 `json:"bGeneration"`
}

type ownedConnection struct {
	branch     *branch
	generation uint64
}

type connectionKey struct {
	local  string
	remote string
}

type ownedDial struct {
	owner ownedConnection
	conn  net.Conn
}

// Remove the tuple binding BEFORE releasing the TCP descriptor. Otherwise a
// later connection reusing its numeric addresses could inherit an old link.
// Every derived socket is returned through this wrapper, including relay and
// cancellation closes; half-close retains the still-live TCP identity.
type linkedConnection struct {
	net.Conn
	fixture  *fixture
	key      connectionKey
	once     sync.Once
	closeErr error
}

func (c *linkedConnection) Close() error {
	c.once.Do(func() {
		c.fixture.mu.Lock()
		if link, present := c.fixture.dialLinks[c.key]; present && link.conn == c {
			delete(c.fixture.dialLinks, c.key)
			close(c.fixture.linkChanged)
			c.fixture.linkChanged = make(chan struct{})
		}
		c.fixture.mu.Unlock()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *linkedConnection) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errRejected
}

type branch struct {
	credentials branchCredentials
	virtualExit [6]byte
	exit        *net.TCPListener
	ingress     *net.TCPListener
	ingressStop chan struct{}
	ingressDone <-chan struct{}
	address     *net.TCPAddr
	enabled     bool
	generation  uint64
}

type fixture struct {
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	mu          sync.Mutex
	control     sync.Mutex
	closing     bool
	wg          sync.WaitGroup
	slots       chan struct{}
	owned       map[net.Conn]ownedConnection
	dialLinks   map[connectionKey]ownedDial
	linkChanged chan struct{}
	expected    netip.Addr
	target      *net.TCPListener
	branches    [2]*branch
	counters    counters
}

// startFixture is an unexported construction seam. Production main reaches it
// only through loadConfig; tests may construct loopback config without changing
// the production parser or adding a bypass flag.
func startFixture(parent context.Context, cfg config) (*fixture, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(cfg.TTLSeconds)*time.Second)
	f := &fixture{ctx: ctx, cancel: cancel, done: make(chan struct{}), slots: make(chan struct{}, maximumAccepted), owned: make(map[net.Conn]ownedConnection), dialLinks: make(map[connectionKey]ownedDial), linkChanged: make(chan struct{})}
	f.expected, _ = netip.ParseAddr(cfg.ExpectedPeerIP)
	f.branches = [2]*branch{
		{credentials: cfg.Branches.A, virtualExit: [6]byte{192, 0, 2, 80, 82, 88}, enabled: true, generation: 1},
		{credentials: cfg.Branches.B, virtualExit: [6]byte{192, 0, 2, 81, 82, 89}, enabled: true, generation: 1},
	}
	var err error
	f.target, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err == nil {
		for index, port := range []uint16{cfg.IngressPorts.A, cfg.IngressPorts.B} {
			b := f.branches[index]
			b.exit, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				break
			}
			b.ingress, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(cfg.ListenIP), Port: int(port)})
			if err != nil {
				break
			}
			b.address = cloneAddress(b.ingress.Addr().(*net.TCPAddr))
			b.ingressStop = make(chan struct{})
		}
	}
	if err != nil {
		cancel()
		f.closeListeners()
		return nil, errRejected
	}
	f.startAccept(f.target, nil, 0, nil, f.handleTarget)
	for _, b := range f.branches {
		f.startAccept(b.exit, b, 0, nil, func(conn net.Conn) error { return f.handleHTTP(b, conn) })
		f.startIngress(b)
	}
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		f.closing = true
		for _, b := range f.branches {
			b.enabled = false
			b.generation++
		}
		f.closeListeners()
		connections := make([]net.Conn, 0, len(f.owned))
		for conn := range f.owned {
			connections = append(connections, conn)
		}
		f.mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		f.wg.Wait()
		close(f.done)
	}()
	return f, nil
}

func cloneAddress(address *net.TCPAddr) *net.TCPAddr {
	return &net.TCPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port}
}

func (f *fixture) closeListeners() {
	if f.target != nil {
		_ = f.target.Close()
	}
	for _, b := range f.branches {
		if b != nil {
			if b.ingress != nil {
				_ = b.ingress.Close()
			}
			if b.exit != nil {
				_ = b.exit.Close()
			}
		}
	}
}

func (f *fixture) Close() { f.cancel(); <-f.done }

func (f *fixture) startIngress(b *branch) {
	generation := b.generation
	b.ingressDone = f.startAccept(b.ingress, b, generation, b.ingressStop, func(conn net.Conn) error { return f.handleSOCKS(b, generation, conn) })
}

func (f *fixture) startAccept(listener *net.TCPListener, b *branch, generation uint64, stopped <-chan struct{}, handler func(net.Conn) error) <-chan struct{} {
	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer close(done)
		defer f.wg.Done()
		for {
			// Reserve BEFORE Accept, including an idle listener's pending call.
			// Cancellation releases a reservation only after actual Accept exit.
			select {
			case f.slots <- struct{}{}:
			case <-f.ctx.Done():
				return
			case <-stopped:
				return
			}
			conn, err := listener.AcceptTCP()
			if err != nil {
				<-f.slots
				return
			}
			if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
				_ = conn.Close()
				<-f.slots
				f.counters.Rejected.Add(1)
				continue
			}
			owner := ownedConnection{b, generation}
			var paired net.Conn
			if generation == 0 {
				var linked bool
				var link ownedDial
				link, linked = f.internalOwner(conn, b)
				if !linked {
					_ = conn.Close()
					<-f.slots
					f.counters.Rejected.Add(1)
					continue
				}
				owner, paired = link.owner, link.conn
			}
			f.mu.Lock()
			valid := !f.closing && f.ctx.Err() == nil && owner.branch != nil && owner.branch.enabled && owner.generation == owner.branch.generation
			if generation == 0 {
				link, present := f.dialLinks[connectionKey{conn.RemoteAddr().String(), conn.LocalAddr().String()}]
				valid = valid && present && link.conn == paired && link.owner == owner && f.owned[paired] == owner
			}
			if generation != 0 {
				remote, ok := netip.AddrFromSlice(conn.RemoteAddr().(*net.TCPAddr).IP)
				valid = valid && ok && remote.Unmap() == f.expected
			}
			if !valid {
				f.mu.Unlock()
				f.counters.Rejected.Add(1)
				_ = conn.Close()
				<-f.slots
				continue
			}
			f.owned[conn] = owner
			f.counters.Accepted.Add(1)
			f.counters.ActiveAccepted.Add(1)
			f.wg.Add(1)
			f.mu.Unlock()
			go func() {
				defer f.wg.Done()
				defer func() {
					_ = conn.Close()
					f.mu.Lock()
					delete(f.owned, conn)
					f.counters.ActiveAccepted.Add(-1)
					<-f.slots
					f.mu.Unlock()
				}()
				if err := handler(conn); err != nil {
					f.counters.Rejected.Add(1)
				}
			}()
		}
	}()
	return done
}

func (f *fixture) setBranch(index int, enabled bool) error {
	f.control.Lock()
	defer f.control.Unlock()
	f.mu.Lock()
	b := f.branches[index]
	if f.closing || f.ctx.Err() != nil {
		f.mu.Unlock()
		return errRejected
	}
	if b.enabled == enabled {
		f.mu.Unlock()
		return nil
	}
	if !enabled {
		b.enabled = false
		b.generation++
		close(b.ingressStop)
		_ = b.ingress.Close()
		b.ingress = nil
		connections := make([]net.Conn, 0, len(f.owned))
		for conn, owner := range f.owned {
			if owner.branch == b {
				connections = append(connections, conn)
			}
		}
		done := b.ingressDone
		f.mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		// Never hold mu while joining a loop that may be validating an Accept.
		// The control lock prevents repeated disable/reopen from accumulating
		// old accept goroutines while their reservations are still owned.
		<-done
		return nil
	}
	listener, err := net.ListenTCP("tcp4", cloneAddress(b.address))
	if err != nil {
		f.mu.Unlock()
		return errRejected
	}
	b.ingress = listener
	b.ingressStop = make(chan struct{})
	b.generation++
	b.enabled = true
	f.startIngress(b)
	f.mu.Unlock()
	return nil
}

func (f *fixture) snapshot(event string) status {
	f.mu.Lock()
	defer f.mu.Unlock()
	active := f.counters.ActiveAccepted.Load()
	return status{Event: event, Accepted: f.counters.Accepted.Load(), Rejected: f.counters.Rejected.Load(), SOCKSAuth: f.counters.SOCKSAuth.Load(), HTTPAuth: f.counters.HTTPAuth.Load(), Proofs: f.counters.Proofs.Load(), EmptyHealth: f.counters.EmptyHealth.Load(), Transferred: f.counters.Transferred.Load(), StaleOwnership: f.counters.StaleOwnership.Load(), ActiveAccepted: active, ReservedAccept: len(f.slots) - int(active), AEnabled: f.branches[0].enabled, BEnabled: f.branches[1].enabled, AGeneration: f.branches[0].generation, BGeneration: f.branches[1].generation}
}

func (f *fixture) controlSignal(incoming os.Signal) string {
	index, enable, event := 0, false, "a_disabled"
	switch incoming {
	case syscall.SIGUSR1:
	case syscall.SIGUSR2:
		enable, event = true, "a_enabled"
	case syscall.SIGHUP:
		index = 1
		f.mu.Lock()
		enable = !f.branches[1].enabled
		f.mu.Unlock()
		if enable {
			event = "b_enabled"
		} else {
			event = "b_disabled"
		}
	case syscall.SIGWINCH:
		return "status"
	default:
		return "switch_rejected"
	}
	if f.setBranch(index, enable) != nil {
		return "switch_rejected"
	}
	return event
}

func (f *fixture) dialOwned(b *branch, generation uint64, address net.Addr) (net.Conn, error) {
	// address is supplied only from an owned loopback listener, never wire data.
	f.mu.Lock()
	tcp, ok := address.(*net.TCPAddr)
	valid := !f.closing && f.ctx.Err() == nil && b != nil && b.enabled && b.generation == generation && ok && tcp != nil && tcp.IP.IsLoopback()
	destination := ""
	if valid {
		destination = address.String()
		valid = destination == b.exit.Addr().String() || destination == f.target.Addr().String()
	}
	f.mu.Unlock()
	if !valid {
		return nil, errRejected
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(f.ctx, "tcp4", destination)
	if err != nil {
		return nil, errRejected
	}
	if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
		_ = conn.Close()
		return nil, errRejected
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing || !b.enabled || b.generation != generation || f.ctx.Err() != nil {
		_ = conn.Close()
		return nil, errRejected
	}
	key := connectionKey{conn.LocalAddr().String(), conn.RemoteAddr().String()}
	if _, present := f.dialLinks[key]; present || len(f.dialLinks) >= maximumAccepted {
		_ = conn.Close()
		return nil, errRejected
	}
	owner := ownedConnection{b, generation}
	linked := &linkedConnection{Conn: conn, fixture: f, key: key}
	f.owned[linked] = owner
	f.dialLinks[key] = ownedDial{owner, linked}
	close(f.linkChanged)
	f.linkChanged = make(chan struct{})
	return linked, nil
}

// TCP establishment can precede the caller returning from DialContext. Wait
// for that exact owned dial tuple, never for bytes or identity supplied on the
// wire. This also fences queued pre-disable exit/target accepts after reopen.
// The wait runs in the existing accept loop and retains its reserved permit.
func (f *fixture) internalOwner(conn net.Conn, expected *branch) (ownedDial, bool) {
	key := connectionKey{conn.RemoteAddr().String(), conn.LocalAddr().String()}
	deadline := time.Now().Add(2 * time.Second)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		f.mu.Lock()
		if f.closing || f.ctx.Err() != nil || !time.Now().Before(deadline) || expected != nil && !expected.enabled {
			f.mu.Unlock()
			return ownedDial{}, false
		}
		link, found := f.dialLinks[key]
		changed := f.linkChanged
		if found {
			owner := link.owner
			if owner.branch != nil && owner.generation != owner.branch.generation {
				f.counters.StaleOwnership.Add(1)
			}
			valid := owner.branch != nil && owner.branch.enabled && owner.generation == owner.branch.generation && link.conn != nil && f.owned[link.conn] == owner && (expected == nil || owner.branch == expected)
			f.mu.Unlock()
			return link, valid
		}
		f.mu.Unlock()
		select {
		case <-f.ctx.Done():
			return ownedDial{}, false
		case <-timer.C:
			return ownedDial{}, false
		case <-changed:
		}
	}
}

func (f *fixture) releaseDial(conn net.Conn) {
	key := connectionKey{conn.LocalAddr().String(), conn.RemoteAddr().String()}
	_ = conn.Close()
	f.mu.Lock()
	delete(f.owned, conn)
	if link, exists := f.dialLinks[key]; exists && link.conn == conn {
		delete(f.dialLinks, key)
		close(f.linkChanged)
		f.linkChanged = make(chan struct{})
	}
	f.mu.Unlock()
}

func authenticate(expected credential, username, password []byte) bool {
	want := sha256.Sum256([]byte(expected.Username + "\x00" + expected.Password))
	owned := make([]byte, 0, len(username)+len(password)+1)
	owned = append(owned, username...)
	owned = append(owned, 0)
	owned = append(owned, password...)
	got := sha256.Sum256(owned)
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

func (f *fixture) handleSOCKS(b *branch, generation uint64, conn net.Conn) error {
	reader := bufio.NewReaderSize(conn, maximumHeaders)
	version, err := reader.ReadByte()
	if err == io.EOF {
		f.counters.EmptyHealth.Add(1)
		return nil
	}
	if err != nil || version != 5 {
		return errRejected
	}
	count, err := reader.ReadByte()
	if err != nil || count == 0 {
		return errRejected
	}
	methods := make([]byte, int(count))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return errRejected
	}
	if !strings.ContainsRune(string(methods), 2) {
		_, _ = conn.Write([]byte{5, 255})
		return errRejected
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return errRejected
	}
	readString := func() ([]byte, error) {
		size, err := reader.ReadByte()
		if err != nil || size == 0 || size > 128 {
			return nil, errRejected
		}
		value := make([]byte, int(size))
		_, err = io.ReadFull(reader, value)
		return value, err
	}
	authVersion, err := reader.ReadByte()
	if err != nil || authVersion != 1 {
		return errRejected
	}
	username, err := readString()
	if err != nil {
		return errRejected
	}
	password, err := readString()
	if err != nil || !authenticate(b.credentials.Entry, username, password) {
		_, _ = conn.Write([]byte{1, 1})
		return errRejected
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return errRejected
	}
	f.counters.SOCKSAuth.Add(1)
	var request [4]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil || request != [4]byte{5, 1, 0, 1} {
		return errRejected
	}
	var destination [6]byte
	if _, err := io.ReadFull(reader, destination[:]); err != nil || subtle.ConstantTimeCompare(destination[:], b.virtualExit[:]) != 1 {
		return errRejected
	}
	upstream, err := f.dialOwned(b, generation, b.exit.Addr())
	if err != nil {
		return errRejected
	}
	defer f.releaseDial(upstream)
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return errRejected
	}
	return f.relay(conn, reader, upstream, upstream)
}

func readHeaders(reader *bufio.Reader) (string, map[string]string, error) {
	total := 0
	line := func() (string, error) {
		raw, err := reader.ReadSlice('\n')
		total += len(raw)
		if total > maximumHeaders || len(raw) > maximumHeaders || err != nil || len(raw) < 2 || raw[len(raw)-2] != '\r' {
			if total == 0 && err == io.EOF {
				return "", io.EOF
			}
			return "", errRejected
		}
		for _, char := range raw[:len(raw)-2] {
			if char < 32 || char > 126 {
				return "", errRejected
			}
		}
		return string(raw[:len(raw)-2]), nil
	}
	request, err := line()
	if err != nil {
		return "", nil, err
	}
	headers := make(map[string]string)
	for {
		field, err := line()
		if err != nil {
			return "", nil, errRejected
		}
		if field == "" {
			return request, headers, nil
		}
		key, value, found := strings.Cut(field, ":")
		if !found || len(key) == 0 || len(headers) >= 16 {
			return "", nil, errRejected
		}
		for _, char := range key {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char == '-') {
				return "", nil, errRejected
			}
		}
		key = strings.ToLower(key)
		if _, duplicate := headers[key]; duplicate {
			return "", nil, errRejected
		}
		switch key {
		case "host", "proxy-authorization", "user-agent", "proxy-connection", "connection", "accept":
		default:
			return "", nil, errRejected
		}
		value = strings.Trim(value, " ")
		if value == "" || (key == "connection" || key == "proxy-connection") && !strings.EqualFold(value, "keep-alive") {
			return "", nil, errRejected
		}
		headers[key] = value
	}
}

func basicCredential(header string, cred credential) bool {
	if !strings.HasPrefix(header, "Basic ") || len(header) > 512 {
		return false
	}
	encoded := header[len("Basic "):]
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
		return false
	}
	username, password, found := strings.Cut(string(raw), ":")
	return found && authenticate(cred, []byte(username), []byte(password))
}

func (f *fixture) handleHTTP(b *branch, conn net.Conn) error {
	reader := bufio.NewReaderSize(conn, maximumHeaders)
	request, headers, err := readHeaders(reader)
	if err == io.EOF {
		f.counters.EmptyHealth.Add(1)
		return nil
	}
	if err != nil || request != "CONNECT "+virtualTarget+" HTTP/1.1" || headers["host"] != virtualTarget || !basicCredential(headers["proxy-authorization"], b.credentials.Exit) {
		return errRejected
	}
	f.mu.Lock()
	owner, present := f.owned[conn]
	f.mu.Unlock()
	if !present || owner.branch != b {
		return errRejected
	}
	f.counters.HTTPAuth.Add(1)
	upstream, err := f.dialOwned(b, owner.generation, f.target.Addr())
	if err != nil {
		return errRejected
	}
	defer f.releaseDial(upstream)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return errRejected
	}
	return f.relay(conn, reader, upstream, upstream)
}

func (f *fixture) handleTarget(conn net.Conn) error {
	reader := bufio.NewReaderSize(conn, maximumHeaders)
	request, headers, err := readHeaders(reader)
	if err == io.EOF {
		f.counters.EmptyHealth.Add(1)
		return nil
	}
	parts := strings.Split(request, " ")
	if err != nil || len(parts) != 3 || parts[0] != "GET" || parts[2] != "HTTP/1.1" || headers["host"] != virtualTarget || len(parts[1]) != len("/proof/")+32 || !strings.HasPrefix(parts[1], "/proof/") {
		return errRejected
	}
	nonce := parts[1][len("/proof/"):]
	for _, char := range nonce {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return errRejected
		}
	}
	if headers["proxy-authorization"] != "" || reader.Buffered() != 0 {
		return errRejected
	}
	body := []byte(`{"nonce":"` + nonce + `"}`)
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := io.WriteString(conn, response); err != nil {
		return errRejected
	}
	if _, err := conn.Write(body); err != nil {
		return errRejected
	}
	f.counters.Proofs.Add(1)
	return nil
}

// The transfer quota is shared by both directions of one accepted tunnel.
// A slot is released by its handler only after both copy workers have exited.
func (f *fixture) relay(left net.Conn, leftReader io.Reader, right net.Conn, rightReader io.Reader) error {
	var transferred atomic.Int64
	var closeOnce sync.Once
	closeBoth := func() { closeOnce.Do(func() { _ = left.Close(); _ = right.Close() }) }
	results := make(chan error, 2)
	copyOne := func(destination net.Conn, source io.Reader) {
		buffer := make([]byte, 16*1024)
		var outcome error
		for {
			read, readErr := source.Read(buffer)
			if read > 0 {
				if transferred.Add(int64(read)) > maximumRelayed {
					outcome = errRejected
					break
				}
				written, writeErr := destination.Write(buffer[:read])
				f.counters.Transferred.Add(uint64(written))
				if writeErr != nil || written != read {
					outcome = errRejected
					break
				}
				if transferred.Load() == maximumRelayed {
					outcome = errRejected
					break
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					outcome = errRejected
				} else if half, ok := destination.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
				} else {
					outcome = errRejected
				}
				break
			}
		}
		if outcome != nil {
			closeBoth()
		}
		results <- outcome
	}
	go copyOne(right, leftReader)
	go copyOne(left, rightReader)
	first, second := <-results, <-results
	closeBoth()
	if first != nil || second != nil {
		return errRejected
	}
	return nil
}

func run(args []string, output io.Writer) int {
	flags := flag.NewFlagSet("route-fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "owner-only runtime configuration")
	if flags.Parse(args) != nil || *path == "" || flags.NArg() != 0 {
		_, _ = io.WriteString(output, "{\"event\":\"configuration_rejected\"}\n")
		return 2
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		_, _ = io.WriteString(output, "{\"event\":\"configuration_rejected\"}\n")
		return 2
	}
	f, err := startFixture(context.Background(), cfg)
	if err != nil {
		_, _ = io.WriteString(output, "{\"event\":\"start_rejected\"}\n")
		return 2
	}
	defer f.Close()
	encode := func(event string) { _ = json.NewEncoder(output).Encode(f.snapshot(event)) }
	encode("ready")
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP, syscall.SIGWINCH)
	defer signal.Stop(signals)
	for {
		select {
		case <-f.done:
			encode("expired")
			return 0
		case incoming := <-signals:
			switch incoming {
			case syscall.SIGTERM, syscall.SIGINT:
				f.Close()
				encode("stopped")
				return 0
			case syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP, syscall.SIGWINCH:
				encode(f.controlSignal(incoming))
			}
		}
	}
}

func main() {
	defer func() {
		if recover() != nil {
			_, _ = fmt.Fprintln(os.Stdout, `{"event":"runtime_rejected"}`)
			os.Exit(2)
		}
	}()
	os.Exit(run(os.Args[1:], os.Stdout))
}
