package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type serviceStartupFallback struct{}

func (*serviceStartupFallback) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("X-Existing", "exact")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("existing-api-bytes"))
}

func serviceStartupDocument(t *testing.T) ([]byte, string, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic root generation failed")
	}
	spki, err := bootstrap.Public(&key.PublicKey)
	if err != nil {
		t.Fatal("synthetic root encoding failed")
	}
	root := bootstrap.Anchor{ID: "service-discovery-offline", SPKI: spki, Epoch: 1}
	online, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic publication key generation failed")
	}
	publication, err := bootstrap.Public(&online.PublicKey)
	if err != nil {
		t.Fatal("synthetic publication key encoding failed")
	}
	now := time.Unix(1800000000, 0)
	descriptor := bootstrap.Descriptor{SchemaVersion: 1, Audience: "syn443-client-bootstrap", RootEpoch: 1, Revision: 2,
		ServiceID: "startup-service", Issuer: "https://identity.example.invalid/realms/device", ClientID: "syn443-android",
		APIOrigin: "https://api.example.invalid", Roots: map[string]string{"online": publication}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	manifest, err := bootstrap.SignDescriptor(descriptor, root, key, now)
	if err != nil {
		t.Fatal("synthetic descriptor signing failed")
	}
	raw, err := json.Marshal(struct {
		SchemaVersion int              `json:"schemaVersion"`
		PublicAnchor  bootstrap.Anchor `json:"publicAnchor"`
		Descriptors   []string         `json:"descriptors"`
	}{1, root, []string{manifest}})
	if err != nil {
		t.Fatal("synthetic public configuration encoding failed")
	}
	return raw, manifest, now
}

func TestServiceDiscoveryStartupAbsentPreservesOriginalAndRequiresNoOtherDependency(t *testing.T) {
	var environment []string
	started := 0
	marker := errors.New("ordinary_startup_result")
	err := withServiceDiscoveryStartup(func(name string) string { environment = append(environment, name); return "" },
		func(string, int64) ([]byte, error) { t.Fatal("absent module read a file"); return nil, nil },
		func() time.Time { t.Fatal("absent module accessed clock"); return time.Time{} },
		func(module *bootstrap.ServiceDiscovery) error {
			started++
			if module != nil {
				t.Fatal("absent configuration enabled module")
			}
			existing := &serviceStartupFallback{}
			if module.Wrap(existing) != existing {
				t.Fatal("disabled module replaced existing handler")
			}
			reply := httptest.NewRecorder()
			module.Wrap(existing).ServeHTTP(reply, httptest.NewRequest(http.MethodGet, bootstrap.ServiceDiscoveryPath+"unchanged", nil))
			if reply.Code != http.StatusAccepted || reply.Body.String() != "existing-api-bytes" || reply.Header().Get("X-Existing") != "exact" {
				t.Fatal("disabled module changed old HTTP bytes")
			}
			return marker
		})
	if !errors.Is(err, marker) || started != 1 || !reflect.DeepEqual(environment, []string{"SYN443_SERVICE_DESCRIPTOR_CONFIG"}) {
		t.Fatal("absent module changed ordinary startup/dependencies")
	}
}

func TestServiceDiscoveryStartupRejectsExplicitConfigurationBeforeOrdinaryInitialization(t *testing.T) {
	raw, manifest, now := serviceStartupDocument(t)
	directory := t.TempDir()
	valid := filepath.Join(directory, "public-descriptors.json")
	if err := os.WriteFile(valid, raw, 0600); err != nil {
		t.Fatal(err)
	}
	started := 0
	var events []string
	getenv := func(name string) string {
		if name != "SYN443_SERVICE_DESCRIPTOR_CONFIG" {
			t.Fatal("module read unrelated credentials/environment")
		}
		events = append(events, "env")
		return valid
	}
	read := func(path string, maximum int64) ([]byte, error) {
		events = append(events, "file")
		if path != valid || maximum != bootstrap.ServiceDiscoveryConfigLimit {
			t.Fatal("owner file bound/path changed")
		}
		return enrollment.PrivateFile(path, maximum)
	}
	start := func(module *bootstrap.ServiceDiscovery) error {
		started++
		events = append(events, "ordinary")
		if module == nil {
			t.Fatal("valid explicit module missing")
		}
		reply := httptest.NewRecorder()
		module.Wrap(&serviceStartupFallback{}).ServeHTTP(reply, httptest.NewRequest(http.MethodGet, bootstrap.ServiceDiscoveryPath+"startup-service", nil))
		if reply.Code != http.StatusOK || reply.Body.String() != manifest {
			t.Fatal("validated module not passed to actual handler wrapper")
		}
		return nil
	}
	if err := withServiceDiscoveryStartup(getenv, read, func() time.Time { events = append(events, "clock"); return now }, start); err != nil || started != 1 {
		t.Fatal("valid startup module rejected")
	}
	if !reflect.DeepEqual(events[:4], []string{"env", "file", "clock", "ordinary"}) {
		t.Fatal("ordinary startup ran before descriptor validation")
	}
	// Exercise the actual owner-only file loader. Explicit malformed files never
	// fall through to ordinary configuration, DB connection or IdP initialization.
	bad := filepath.Join(directory, "bad.json")
	wide := filepath.Join(directory, "wide.json")
	if err := os.WriteFile(bad, []byte(`{"schemaVersion":1,"publicAnchor":null,"descriptors":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wide, bytes.Repeat([]byte(" "), bootstrap.ServiceDiscoveryConfigLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(directory, "world-readable.json")
	if err := os.WriteFile(public, raw, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{bad, wide, public, link, directory, filepath.Join(directory, "missing"), " "} {
		before := started
		err := withServiceDiscoveryStartup(func(name string) string {
			if name != "SYN443_SERVICE_DESCRIPTOR_CONFIG" {
				t.Fatal("unexpected dependency lookup")
			}
			return path
		}, enrollment.PrivateFile, func() time.Time { return now }, start)
		if !errors.Is(err, identity.ErrInvalid) || started != before {
			t.Fatal("invalid explicit module reached unrelated startup")
		}
	}
	padded := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), bootstrap.ServiceDiscoveryConfigLimit-len(raw))...)
	if err := os.WriteFile(valid, padded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := withServiceDiscoveryStartup(getenv, read, func() time.Time { return now }, start); err != nil {
		t.Fatal("exact owner-file byte boundary rejected")
	}
	if err := withServiceDiscoveryStartup(getenv, func(string, int64) ([]byte, error) { return nil, errors.New("private path must not escape") }, func() time.Time { return now }, start); err != identity.ErrInvalid {
		t.Fatal("file failure was not finite")
	}
	if withServiceDiscoveryStartup(nil, read, func() time.Time { return now }, start) != identity.ErrInvalid ||
		withServiceDiscoveryStartup(getenv, nil, func() time.Time { return now }, start) != identity.ErrInvalid ||
		withServiceDiscoveryStartup(getenv, read, nil, start) != identity.ErrInvalid ||
		withServiceDiscoveryStartup(getenv, read, func() time.Time { return now }, nil) != identity.ErrInvalid {
		t.Fatal("missing startup dependency admitted")
	}
}
