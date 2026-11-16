package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/deviceprovisioning"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func configurationQueueFixture(t *testing.T) (deviceprovisioning.ConfigurationRuntimeConfig, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c := deviceprovisioning.ConfigurationRuntimeConfig{ControlOrigin: "https://control.example.invalid", Issuer: "https://identity.example.invalid/realms/admin",
		Audience: "syn443-control-api", ClientIDs: []string{"syn443-control-web", "syn443-control-mobile"}, AssuranceACR: "urn:syn443:loa:2",
		LayerEncryptionKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{41}, 32)),
		SourceEncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{51}, 32)),
		Roots:               map[string]string{"preview-root": base64.StdEncoding.EncodeToString(public)}}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c, err = deviceprovisioning.ParseConfigurationRuntime(encoded)
	if err != nil {
		t.Fatal("synthetic real runtime was not valid")
	}
	return c, key
}

func TestConfigurationQueueModePreflightIsExactAndRejectsBeforeUnrelatedInputs(t *testing.T) {
	for _, mode := range []string{"auto", "disabled", "External", "EMBEDDED", " external", "external ", "embedded\n"} {
		t.Run(fmt.Sprintf("unknown-%q", mode), func(t *testing.T) {
			var names []string
			plan, err := readConfigurationStartup(func(name string) string { names = append(names, name); return mode },
				func(string) (deviceprovisioning.ConfigurationRuntimeConfig, error) {
					t.Fatal("invalid mode reached configuration file")
					return deviceprovisioning.ConfigurationRuntimeConfig{}, nil
				})
			if err == nil || plan != nil || strings.Join(names, ",") != "SYN443_CONFIGURATION_QUEUE_MODE" {
				t.Fatal("invalid mode reached unrelated startup or silently fell back")
			}
		})
	}
	for _, mode := range []string{"embedded", "external"} {
		var names []string
		plan, err := readConfigurationStartup(func(name string) string {
			names = append(names, name)
			if name == "SYN443_CONFIGURATION_QUEUE_MODE" {
				return mode
			}
			return ""
		},
			func(string) (deviceprovisioning.ConfigurationRuntimeConfig, error) {
				t.Fatal("mode without config reached a file read")
				return deviceprovisioning.ConfigurationRuntimeConfig{}, nil
			})
		if err == nil || plan != nil || strings.Join(names, ",") != "SYN443_CONFIGURATION_QUEUE_MODE,SYN443_CONFIGURATION_CONFIG" {
			t.Fatal("explicit mode did not require its configuration before unrelated startup")
		}
	}
	if plan, err := readConfigurationStartup(nil, nil); err == nil || plan != nil {
		t.Fatal("nil environment source accepted")
	}
}

func TestConfigurationQueueRuntimeUsesTheRealOwnedClosedConfigurationReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX configuration ownership is checked in Actions")
	}
	c, _ := configurationQueueFixture(t)
	raw, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "configuration.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	env := func(name string) string {
		switch name {
		case "SYN443_CONFIGURATION_QUEUE_MODE":
			return "external"
		case "SYN443_CONFIGURATION_CONFIG":
			return path
		}
		t.Fatal("unrelated environment input read during mode preflight")
		return ""
	}
	plan, err := readConfigurationStartup(env, deviceprovisioning.ReadConfigurationRuntime)
	if err != nil || plan == nil || plan.mode != configurationQueueExternal || plan.config.ControlOrigin != c.ControlOrigin {
		t.Fatal("real owned runtime did not produce external authority plan")
	}
	for _, secret := range []string{c.LayerEncryptionKey, c.SourceEncryptionKey, path} {
		if strings.Contains(fmt.Sprintf("%v %#v", plan, plan), secret) {
			t.Fatal("startup diagnostic exposed configuration")
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if plan, err := readConfigurationStartup(env, deviceprovisioning.ReadConfigurationRuntime); err == nil || plan != nil {
		t.Fatal("readable-by-others configuration enabled managed authority")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	bad := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"queueMode":"embedded"}`)...)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if plan, err := readConfigurationStartup(env, deviceprovisioning.ReadConfigurationRuntime); err == nil || plan != nil {
		t.Fatal("unknown configuration member gained a fallback")
	}
}

// These seams assert construction, exact dependencies and environment access.
// They do not simulate SQL roles, provider discovery or queue publication;
// those remain covered by the real existing deviceprovisioning suites.
type configurationQueueWiring struct {
	db              *sql.DB
	layers          *enrollment.Store
	sources         *catalog.Store
	roots           map[string]*ecdsa.PublicKey
	preview, device *ecdsa.PrivateKey
	verifier        *configurationQueueNeverVerifier
	calls           []string
	keyEnvironment  []string
}

type configurationQueueNeverVerifier struct{}

func (*configurationQueueNeverVerifier) Verify(context.Context, string, time.Time) (identity.Principal, error) {
	panic("startup wiring must never impersonate an administrative authorization")
}

func configurationQueueDependencies(t *testing.T, c deviceprovisioning.ConfigurationRuntimeConfig, preview *ecdsa.PrivateKey) (*configurationQueueWiring, configurationStartupDependencies) {
	t.Helper()
	w := &configurationQueueWiring{db: new(sql.DB), preview: preview, verifier: &configurationQueueNeverVerifier{}}
	var err error
	w.device, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	layerKey, _ := base64.StdEncoding.DecodeString(c.LayerEncryptionKey)
	sourceKey, _ := base64.StdEncoding.DecodeString(c.SourceEncryptionKey)
	w.layers, err = enrollment.NewStore(w.db, layerKey)
	if err != nil {
		t.Fatal(err)
	}
	w.sources, err = catalog.NewStore(w.db, sourceKey)
	if err != nil {
		t.Fatal(err)
	}
	w.roots, err = c.PublicRoots()
	if err != nil {
		t.Fatal(err)
	}
	roleInput := func(ctx context.Context, input deviceprovisioning.ConfigurationRuntimeConfig, db *sql.DB) {
		t.Helper()
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second || ctx.Err() != nil || db != w.db || input.LayerEncryptionKey != c.LayerEncryptionKey || input.SourceEncryptionKey != c.SourceEncryptionKey {
			t.Fatal("guarded stores did not retain their bounded startup dependencies")
		}
	}
	return w, configurationStartupDependencies{
		layers: func(ctx context.Context, input deviceprovisioning.ConfigurationRuntimeConfig, db *sql.DB) (*enrollment.Store, error) {
			roleInput(ctx, input, db)
			w.calls = append(w.calls, "layers")
			return w.layers, nil
		},
		sources: func(ctx context.Context, input deviceprovisioning.ConfigurationRuntimeConfig, db *sql.DB) (*catalog.Store, error) {
			roleInput(ctx, input, db)
			w.calls = append(w.calls, "sources")
			return w.sources, nil
		},
		roots: func(input deviceprovisioning.ConfigurationRuntimeConfig) (map[string]*ecdsa.PublicKey, error) {
			w.calls = append(w.calls, "roots")
			return input.PublicRoots()
		},
		admins: func(ctx context.Context, input deviceprovisioning.ConfigurationRuntimeConfig) (catalog.VerifierGroup, error) {
			w.calls = append(w.calls, "admins")
			if ctx.Err() != nil || input.Issuer != c.Issuer || input.Audience != "syn443-control-api" {
				t.Fatal("administrative verifier borrowed device authority")
			}
			return catalog.VerifierGroup{w.verifier}, nil
		},
		key: func(path string) (*ecdsa.PrivateKey, error) {
			w.calls = append(w.calls, "preview-key")
			if path != "synthetic-preview-key" {
				t.Fatal("wrong preview-key dependency")
			}
			return preview, nil
		},
	}
}

func (w *configurationQueueWiring) publisher() *enrollment.Publisher {
	return &enrollment.Publisher{Store: &enrollment.Store{DB: w.db}, Key: w.device, KeyID: "ordinary-policy-key"}
}

func (w *configurationQueueWiring) getenv(name string) string {
	w.keyEnvironment = append(w.keyEnvironment, name)
	switch name {
	case "SYN443_CONFIGURATION_SIGNING_KEY_FILE":
		return "synthetic-preview-key"
	case "SYN443_CONFIGURATION_KEY_ID":
		return "preview-root"
	}
	return ""
}

func TestConfigurationQueueExternalInstallsActualAuthorityWithoutAdminOrPreviewKeyReads(t *testing.T) {
	c, preview := configurationQueueFixture(t)
	w, dependencies := configurationQueueDependencies(t, c, preview)
	dependencies.admins = func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig) (catalog.VerifierGroup, error) {
		t.Fatal("external mode discovered admin IdP")
		return nil, nil
	}
	dependencies.key = func(string) (*ecdsa.PrivateKey, error) {
		t.Fatal("external mode opened preview private key")
		return nil, nil
	}
	plan := &configurationStartup{mode: configurationQueueExternal, config: c}
	p := w.publisher()
	queue, err := plan.install(context.Background(), p, func(string) string { t.Fatal("external mode read preview signer environment"); return "" }, dependencies)
	if err != nil || queue != nil || strings.Join(w.calls, ",") != "layers,sources,roots" {
		t.Fatal("external mode did not exclusively install guarded device authority")
	}
	authority, ok := p.Configurations.(*deviceprovisioning.NetworkAuthority)
	if !ok || authority == nil || authority.Sources != w.sources {
		t.Fatal("external mode disabled managed source/layer authority")
	}
	layers, ok := authority.Layers.(*deviceprovisioning.SQLNetworkLayers)
	if !ok || layers.Store != w.layers || layers.ControlOrigin != c.ControlOrigin || !layers.Roots["preview-root"].Equal(&preview.PublicKey) {
		t.Fatal("external mode lost exact public preview verification dependencies")
	}
	if p.Key != w.device || p.Key == preview || p.KeyID != "ordinary-policy-key" {
		t.Fatal("external mode changed the ordinary device signer")
	}
}

func TestConfigurationQueueDefaultAndExplicitEmbeddedRetainPublisherAndKeyValidation(t *testing.T) {
	for _, mode := range []string{"", "embedded"} {
		c, preview := configurationQueueFixture(t)
		plan, err := readConfigurationStartup(func(name string) string {
			if name == "SYN443_CONFIGURATION_QUEUE_MODE" {
				return mode
			}
			return "synthetic-config"
		},
			func(string) (deviceprovisioning.ConfigurationRuntimeConfig, error) { return c, nil })
		if err != nil || plan == nil || plan.mode != configurationQueueEmbedded {
			t.Fatal("default embedded mode changed")
		}
		w, dependencies := configurationQueueDependencies(t, c, preview)
		p := w.publisher()
		queue, err := plan.install(context.Background(), p, w.getenv, dependencies)
		if err != nil || queue == nil || p.Configurations == nil || strings.Join(w.calls, ",") != "layers,sources,roots,admins,preview-key" ||
			strings.Join(w.keyEnvironment, ",") != "SYN443_CONFIGURATION_SIGNING_KEY_FILE,SYN443_CONFIGURATION_KEY_ID" {
			t.Fatal("embedded dependency order or ownership changed")
		}
		if queue.Store != w.layers || queue.Sources != w.sources || queue.Key != preview || queue.KeyID != "preview-root" || queue.Origin != c.ControlOrigin || queue.AssuranceACR != c.AssuranceACR || p.Key != w.device {
			t.Fatal("embedded publisher changed key/store/audience compartments")
		}
		verifiers, ok := queue.Verifier.(catalog.VerifierGroup)
		if !ok || len(verifiers) != 1 || verifiers[0] != w.verifier {
			t.Fatal("embedded publisher lost its independent admin verifier")
		}
	}
}

func TestConfigurationQueueDependencyFailuresNeverInstallPartialOrFallbackAuthority(t *testing.T) {
	for _, stage := range []string{"layers", "sources", "roots", "admins", "key", "nil-layer", "nil-source", "nil-roots", "nil-admin", "nil-key", "unknown-key", "mismatched-key"} {
		t.Run(stage, func(t *testing.T) {
			c, preview := configurationQueueFixture(t)
			w, dependencies := configurationQueueDependencies(t, c, preview)
			failure := errors.New("synthetic_startup_failure")
			switch stage {
			case "layers":
				dependencies.layers = func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig, *sql.DB) (*enrollment.Store, error) {
					return nil, failure
				}
			case "sources":
				dependencies.sources = func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig, *sql.DB) (*catalog.Store, error) {
					return nil, failure
				}
			case "roots":
				dependencies.roots = func(deviceprovisioning.ConfigurationRuntimeConfig) (map[string]*ecdsa.PublicKey, error) {
					return nil, failure
				}
			case "admins":
				dependencies.admins = func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig) (catalog.VerifierGroup, error) {
					return nil, failure
				}
			case "key":
				dependencies.key = func(string) (*ecdsa.PrivateKey, error) { return nil, failure }
			case "nil-layer":
				dependencies.layers = func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig, *sql.DB) (*enrollment.Store, error) {
					return nil, nil
				}
			case "nil-source":
				dependencies.sources = func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig, *sql.DB) (*catalog.Store, error) {
					return nil, nil
				}
			case "nil-roots":
				dependencies.roots = func(deviceprovisioning.ConfigurationRuntimeConfig) (map[string]*ecdsa.PublicKey, error) {
					return nil, nil
				}
			case "nil-admin":
				dependencies.admins = func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig) (catalog.VerifierGroup, error) {
					return nil, nil
				}
			case "nil-key":
				dependencies.key = func(string) (*ecdsa.PrivateKey, error) { return nil, nil }
			case "mismatched-key":
				dependencies.key = func(string) (*ecdsa.PrivateKey, error) { return w.device, nil }
			}
			getenv := w.getenv
			if stage == "unknown-key" {
				getenv = func(name string) string {
					if name == "SYN443_CONFIGURATION_KEY_ID" {
						return "unknown-root"
					}
					return w.getenv(name)
				}
			}
			p := w.publisher()
			queue, err := (&configurationStartup{mode: configurationQueueEmbedded, config: c}).install(context.Background(), p, getenv, dependencies)
			if err == nil || queue != nil || p.Configurations != nil {
				t.Fatal("failed embedded startup installed partial authority or silently selected external mode")
			}
			if p.Key != w.device {
				t.Fatal("configuration failure changed the device signer")
			}
		})
	}
}

func TestConfigurationQueueExternalStillRequiresOrdinaryDeviceSigningKey(t *testing.T) {
	c, preview := configurationQueueFixture(t)
	w, dependencies := configurationQueueDependencies(t, c, preview)
	p := w.publisher()
	p.Key = nil
	plan := &configurationStartup{mode: configurationQueueExternal, config: c}
	if queue, err := plan.install(context.Background(), p, w.getenv, dependencies); err == nil || queue != nil || p.Configurations != nil || len(w.calls) != 0 || len(w.keyEnvironment) != 0 {
		t.Fatal("external queue mode bypassed the ordinary mandatory signer")
	}
	p.Key = w.device
	if queue, err := plan.install(context.Background(), p, nil, dependencies); err != nil || queue != nil || p.Configurations == nil {
		t.Fatal("valid device signer unexpectedly required a preview signer")
	}
}

func TestConfigurationQueueCancellationAndInvalidConstructionCannotPublishAuthority(t *testing.T) {
	for _, stage := range []string{"before", "layers", "roots", "unknown-mode", "nil-context"} {
		t.Run(stage, func(t *testing.T) {
			c, preview := configurationQueueFixture(t)
			w, dependencies := configurationQueueDependencies(t, c, preview)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plan := &configurationStartup{mode: configurationQueueExternal, config: c}
			switch stage {
			case "before":
				cancel()
			case "layers":
				original := dependencies.layers
				dependencies.layers = func(ctx context.Context, c deviceprovisioning.ConfigurationRuntimeConfig, db *sql.DB) (*enrollment.Store, error) {
					layers, err := original(ctx, c, db)
					cancel()
					return layers, err
				}
			case "roots":
				original := dependencies.roots
				dependencies.roots = func(c deviceprovisioning.ConfigurationRuntimeConfig) (map[string]*ecdsa.PublicKey, error) {
					roots, err := original(c)
					cancel()
					return roots, err
				}
			case "unknown-mode":
				plan.mode = "unknown"
			case "nil-context":
				ctx = nil
			}
			p := w.publisher()
			if queue, err := plan.install(ctx, p, w.getenv, dependencies); err == nil || queue != nil || p.Configurations != nil {
				t.Fatal("cancelled or invalid startup installed a usable authority")
			}
			if (stage == "before" || stage == "unknown-mode" || stage == "nil-context") && len(w.calls) != 0 {
				t.Fatal("invalid startup reached a dependency")
			}
		})
	}
}

func TestConfigurationQueueAbsentConfigPreservesNilOrdinaryAuthorityAndReadsNoDependencies(t *testing.T) {
	plan, err := readConfigurationStartup(func(string) string { return "" }, nil)
	if err != nil || plan != nil {
		t.Fatal("ordinary device-only startup no longer defaults to absent configuration")
	}
	c, preview := configurationQueueFixture(t)
	w, dependencies := configurationQueueDependencies(t, c, preview)
	p := w.publisher()
	queue, err := plan.install(context.Background(), p, func(string) string { t.Fatal("absent configuration read a signing variable"); return "" }, dependencies)
	if err != nil || queue != nil || p.Configurations != nil || p.Key != w.device || len(w.calls) != 0 {
		t.Fatal("absent configuration installed a typed-nil authority or changed ordinary device publication")
	}
}
