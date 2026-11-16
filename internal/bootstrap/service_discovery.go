package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const ServiceDiscoveryConfigLimit = 262144
const ServiceDiscoveryPath = "/.well-known/syn443/bootstrap/"

type serviceDiscoveryConfig struct {
	SchemaVersion int      `json:"schemaVersion"`
	PublicAnchor  Anchor   `json:"publicAnchor"`
	Descriptors   []string `json:"descriptors"`
}

type publicServiceDescriptor struct {
	manifest  string
	issued    int64
	notBefore int64
	expires   int64
}

// ServiceDiscovery serves only a fixed, owner-configured set of public signed
// descriptors. It owns its input and has no signer, credentials, DB or fetcher.
type ServiceDiscovery struct {
	services map[string]publicServiceDescriptor
	clock    func() time.Time
	mu       sync.Mutex
	last     time.Time
	credit   time.Duration
}

func (*ServiceDiscovery) String() string   { return "ServiceDiscovery([redacted])" }
func (*ServiceDiscovery) GoString() string { return "ServiceDiscovery([redacted])" }

func discoveryClock(now time.Time) bool {
	return now.UTC().Year() >= 1970 && now.UTC().Year() <= 9999 && now.Unix() > 0
}

// ParseServiceDiscovery is a strict owner-document entry point. Callers must
// read a bounded regular owner-only file before calling it. No root is obtained
// from a request; the public anchor is explicit operator configuration.
func ParseServiceDiscovery(raw []byte, clock func() time.Time) (*ServiceDiscovery, error) {
	var config serviceDiscoveryConfig
	if len(raw) == 0 || len(raw) > ServiceDiscoveryConfigLimit || clock == nil ||
		identity.DecodeOperatorDocument(raw, &config) != nil || config.SchemaVersion != 1 ||
		config.PublicAnchor.Validate() != nil || len(config.Descriptors) < 1 || len(config.Descriptors) > 32 {
		return nil, ErrUntrusted
	}
	// The generic owner decoder rejects unknown/case-variant/duplicate members;
	// this shape also makes every field required and rejects null string defaults.
	var document map[string]json.RawMessage
	var anchor map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil || len(document) != 3 ||
		json.Unmarshal(document["publicAnchor"], &anchor) != nil || len(anchor) != 4 {
		return nil, ErrUntrusted
	}
	for _, name := range []string{"id", "spki", "epoch", "lastTransition"} {
		if value, ok := anchor[name]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrUntrusted
		}
	}
	// Signed validity and HTTP Date use wall time. Drop any monotonic reading
	// before retaining the wall-clock high-water mark.
	now := clock().Round(0).UTC()
	if !discoveryClock(now) {
		return nil, ErrUntrusted
	}
	result := &ServiceDiscovery{services: make(map[string]publicServiceDescriptor, len(config.Descriptors)),
		clock: clock, last: now, credit: 8 * time.Second}
	for _, manifest := range config.Descriptors {
		if len(manifest) < 1 || len(manifest) > MaxManifest {
			return nil, ErrUntrusted
		}
		descriptor, _, err := VerifyDescriptor(manifest, config.PublicAnchor, Floor{}, now)
		if err != nil {
			return nil, ErrUntrusted
		}
		if _, duplicate := result.services[descriptor.ServiceID]; duplicate {
			return nil, ErrUntrusted
		}
		result.services[strings.Clone(descriptor.ServiceID)] = publicServiceDescriptor{
			manifest: strings.Clone(manifest), issued: descriptor.IssuedAt, notBefore: descriptor.NotBefore, expires: descriptor.Expires}
	}
	return result, nil
}

// One token costs 250ms of credit; the module holds at most 32 tokens. A clock
// rollback neither moves the high-water mark nor refills/admits a request.
func (d *ServiceDiscovery) admit() (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Sample inside the same small lock: concurrent requests must not mistake
	// an earlier, preempted sample for a rollback after a later sample won.
	now := d.clock().Round(0).UTC()
	if !discoveryClock(now) || now.Before(d.last) {
		return now, false
	}
	delta := now.Sub(d.last)
	if delta > 8*time.Second {
		delta = 8 * time.Second
	}
	d.credit += delta
	if d.credit > 8*time.Second {
		d.credit = 8 * time.Second
	}
	d.last = now
	if d.credit < 250*time.Millisecond {
		return now, false
	}
	d.credit -= 250 * time.Millisecond
	return now, true
}

func discoveryRequest(r *http.Request) (string, bool) {
	u := r.URL
	if r.Method != http.MethodGet || u == nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		r.RequestURI != "" && r.RequestURI != u.Path || r.ContentLength != 0 ||
		len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.Body != nil && r.Body != http.NoBody {
		return "", false
	}
	for key, values := range r.Header {
		if strings.EqualFold(key, "Transfer-Encoding") || strings.EqualFold(key, "Trailer") ||
			strings.EqualFold(key, "Content-Length") && (len(values) != 1 || values[0] != "0") {
			return "", false
		}
	}
	id := strings.TrimPrefix(u.Path, ServiceDiscoveryPath)
	return id, u.Path == ServiceDiscoveryPath+id && identifier.MatchString(id)
}

// Wrap intercepts only this module's path namespace. Disabled modules return
// the exact original handler, and all unrelated requests retain its behavior.
func (d *ServiceDiscovery) Wrap(next http.Handler) http.Handler {
	if d == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil || r.URL.Path != strings.TrimSuffix(ServiceDiscoveryPath, "/") && !strings.HasPrefix(r.URL.Path, ServiceDiscoveryPath) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Context().Err() != nil {
			return
		}
		now, admitted := d.admit()
		status := http.StatusNotFound
		var body string
		if !admitted {
			status = http.StatusTooManyRequests
		} else if id, valid := discoveryRequest(r); valid {
			if value, found := d.services[id]; found && value.notBefore <= now.Unix() && value.issued <= now.Unix()+30 && value.expires > now.Unix() {
				status, body = http.StatusOK, value.manifest
			}
		}
		if r.Context().Err() != nil {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if discoveryClock(now) {
			w.Header().Set("Date", now.UTC().Format(http.TimeFormat))
		}
		if status == http.StatusOK {
			w.Header().Set("Content-Type", "application/jose")
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	})
}
