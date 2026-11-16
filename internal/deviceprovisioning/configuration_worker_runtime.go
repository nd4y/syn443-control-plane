package deviceprovisioning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// A separate owner-only process file. No enrollment encryption key, grants,
// invitation authority, overlay token or compiled-policy fallback is accepted.
type ConfigurationWorkerRuntimeConfig struct {
	Database      string                     `json:"database"`
	Configuration ConfigurationRuntimeConfig `json:"configuration"`
}

func (ConfigurationWorkerRuntimeConfig) String() string {
	return "ConfigurationWorkerRuntime([redacted])"
}
func (c ConfigurationWorkerRuntimeConfig) GoString() string { return c.String() }

func ParseConfigurationWorkerRuntime(raw []byte) (ConfigurationWorkerRuntimeConfig, error) {
	var c ConfigurationWorkerRuntimeConfig
	if len(raw) == 0 || len(raw) > 65536 || identity.Decode(raw, &c, true) != nil || len(c.Database) == 0 || len(c.Database) > 4096 {
		return ConfigurationWorkerRuntimeConfig{}, enrollment.ErrDenied
	}
	if c.Configuration.validate() != nil {
		return ConfigurationWorkerRuntimeConfig{}, enrollment.ErrDenied
	}
	parsed, e := pgx.ParseConfig(c.Database)
	if e != nil {
		return ConfigurationWorkerRuntimeConfig{}, enrollment.ErrDenied
	}
	// This new runtime supports exactly one DB endpoint. In particular, a
	// loopback primary cannot lend its plaintext exception to a remote fallback.
	for _, fallback := range parsed.Fallbacks {
		if fallback.Host != parsed.Host || fallback.Port != parsed.Port {
			return ConfigurationWorkerRuntimeConfig{}, enrollment.ErrDenied
		}
	}
	// Reuse the existing strict pgx/TLS/fallback/connect-timeout implementation.
	// sql.OpenDB is lazy: parsing does not connect or perform administrative I/O.
	// This temporary store receives ONLY the source key, never an identity key.
	s, e := catalog.OpenStore(catalog.RuntimeConfig{Database: c.Database, EncryptionKey: c.Configuration.SourceEncryptionKey})
	if e != nil {
		return ConfigurationWorkerRuntimeConfig{}, enrollment.ErrDenied
	}
	_ = s.DB.Close()
	return c, nil
}

func ReadConfigurationWorkerRuntime(path string) (ConfigurationWorkerRuntimeConfig, error) {
	raw, e := enrollment.PrivateFile(path, 65536)
	if e != nil {
		return ConfigurationWorkerRuntimeConfig{}, enrollment.ErrDenied
	}
	return ParseConfigurationWorkerRuntime(raw)
}

// ConfigurationWorker owns only its DB handle and the existing independent
// administrative receipt consumer. It never creates enrollment.Publisher.
type ConfigurationWorker struct{ publisher *ConfigurationPublisher }

func (*ConfigurationWorker) String() string     { return "ConfigurationWorker([redacted])" }
func (w *ConfigurationWorker) GoString() string { return w.String() }

func configurationWorkerSigningKey(c ConfigurationRuntimeConfig, keyID string, key *ecdsa.PrivateKey) error {
	if key == nil || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 || key.X == nil || key.Y == nil {
		return enrollment.ErrDenied
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return enrollment.ErrDenied
	}
	roots, e := c.PublicRoots()
	if e != nil || roots[keyID] == nil || !roots[keyID].Equal(&key.PublicKey) {
		return enrollment.ErrDenied
	}
	return nil
}

func OpenConfigurationWorker(ctx context.Context, c ConfigurationWorkerRuntimeConfig, keyID string, key *ecdsa.PrivateKey, transport http.RoundTripper) (*ConfigurationWorker, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, enrollment.ErrDenied
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	if _, e = ParseConfigurationWorkerRuntime(raw); e != nil || configurationWorkerSigningKey(c.Configuration, keyID, key) != nil {
		return nil, enrollment.ErrDenied
	}
	initial, e := catalog.OpenStore(catalog.RuntimeConfig{Database: c.Database, EncryptionKey: c.Configuration.SourceEncryptionKey})
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	worker, e := configurationWorkerFromDB(ctx, c.Configuration, initial.DB, keyID, key, transport)
	if e != nil {
		_ = initial.DB.Close()
		return nil, e
	}
	return worker, nil
}

// Internal construction seam; even an injected DB must pass the same existing
// publisher-role guards before discovery or any administrative receipt access.
func configurationWorkerFromDB(ctx context.Context, c ConfigurationRuntimeConfig, db *sql.DB, keyID string, key *ecdsa.PrivateKey, transport http.RoundTripper) (*ConfigurationWorker, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || c.validate() != nil || configurationWorkerSigningKey(c, keyID, key) != nil {
		return nil, enrollment.ErrDenied
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	layers, e := c.LayerStore(startup, db, true)
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	sources, e := c.SourceStore(startup, db)
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	admins, e := c.AdminVerifier(startup, transport)
	if e != nil || startup.Err() != nil {
		return nil, enrollment.ErrUnavailable
	}
	roots, e := c.PublicRoots()
	if e != nil {
		return nil, enrollment.ErrDenied
	}
	return &ConfigurationWorker{publisher: &ConfigurationPublisher{Store: layers, Sources: sources, Verifier: admins,
		Origin: c.ControlOrigin, AssuranceACR: c.AssuranceACR, KeyID: keyID, Key: key, Roots: roots}}, nil
}

func (w *ConfigurationWorker) Now(ctx context.Context, wall time.Time) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || w == nil || w.publisher == nil || w.publisher.Store == nil || wall.IsZero() {
		return time.Time{}, enrollment.ErrDenied
	}
	return w.publisher.Store.Now(ctx, wall)
}

func (w *ConfigurationWorker) RunOnce(ctx context.Context, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || w == nil || w.publisher == nil || now.IsZero() {
		return enrollment.ErrDenied
	}
	return w.publisher.RunOnce(ctx, now)
}

func (w *ConfigurationWorker) Close() error {
	if w == nil || w.publisher == nil || w.publisher.Store == nil || w.publisher.Store.DB == nil {
		return nil
	}
	return w.publisher.Store.DB.Close()
}
