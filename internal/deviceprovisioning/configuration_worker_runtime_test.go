package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
)

func configurationWorkerFixture(t *testing.T) (ConfigurationWorkerRuntimeConfig, *ecdsa.PrivateKey) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	public, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	c := ConfigurationWorkerRuntimeConfig{Database: "host=127.0.0.1 port=1 user=syn443_identity_publisher password=synthetic-password dbname=syn443 sslmode=disable", Configuration: runtimeConfiguration(t)}
	c.Configuration.Roots = map[string]string{"worker-root": base64.StdEncoding.EncodeToString(public)}
	return c, key
}

func TestConfigurationWorkerRuntimeClosedKeysAndExistingDSNGuards(t *testing.T) {
	c, _ := configurationWorkerFixture(t)
	raw, _ := json.Marshal(c)
	if _, e := ParseConfigurationWorkerRuntime(raw); e != nil {
		t.Fatal("valid separate runtime rejected")
	}
	secure := c
	secure.Database = "host=db.example.invalid port=5432 user=syn443_identity_publisher password=synthetic-password dbname=syn443 sslmode=verify-full"
	secureRaw, _ := json.Marshal(secure)
	if _, e := ParseConfigurationWorkerRuntime(secureRaw); e != nil {
		t.Fatal("single verified-TLS remote endpoint rejected")
	}
	for _, unknown := range []string{"identityEncryptionKey", "enrollment", "grants", "invitation", "overlay", "networkAuthority"} {
		var value map[string]any
		_ = json.Unmarshal(raw, &value)
		value[unknown] = "synthetic-forbidden-material"
		bad, _ := json.Marshal(value)
		if _, e := ParseConfigurationWorkerRuntime(bad); e == nil {
			t.Fatal("unrelated authority material admitted")
		}
	}
	for _, bad := range [][]byte{
		nil, bytes.Repeat([]byte{' '}, 65537),
		append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"database":"duplicate"}`)...),
		bytes.Replace(raw, []byte(`"database"`), []byte(`"Database"`), 1),
		bytes.Replace(raw, []byte(`"configuration":{`), []byte(`"configuration":null,"unrecognized":{`), 1),
	} {
		if _, e := ParseConfigurationWorkerRuntime(bad); e == nil {
			t.Fatal("ambiguous or unbounded runtime admitted")
		}
	}
	for _, dsn := range []string{"", "not-a-dsn", strings.Repeat("x", 4097),
		"postgres://user@db.example.invalid/syn443?sslmode=disable",
		"postgres://user@db.example.invalid/syn443?sslmode=require",
		"host=127.0.0.1,db.example.invalid port=5432 user=user dbname=syn443 sslmode=disable",
		"host=127.0.0.1 port=5432,5433 user=user dbname=syn443 sslmode=disable",
		"host=db.example.invalid port=5432 user=user dbname=syn443 sslmode=prefer",
		"host=/tmp user=user dbname=syn443 sslmode=disable"} {
		bad := c
		bad.Database = dsn
		encoded, _ := json.Marshal(bad)
		if _, e := ParseConfigurationWorkerRuntime(encoded); e == nil {
			t.Fatal("DSN escaped the existing TLS/private-endpoint guards")
		}
	}
	for _, secret := range []string{c.Database, c.Configuration.LayerEncryptionKey, c.Configuration.SourceEncryptionKey} {
		if strings.Contains(fmt.Sprintf("%v %#v", c, c), secret) {
			t.Fatal("runtime diagnostic exposed private configuration")
		}
	}
}

func TestConfigurationWorkerRuntimeOwnerOnlyFileAndSigningKeyMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX owner permissions are verified in Actions")
	}
	c, key := configurationWorkerFixture(t)
	raw, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "worker.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadConfigurationWorkerRuntime(path); e != nil {
		t.Fatal("owned separate runtime rejected")
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadConfigurationWorkerRuntime(path); e == nil {
		t.Fatal("world-readable runtime accepted")
	}
	if e := configurationWorkerSigningKey(c.Configuration, "worker-root", key); e != nil {
		t.Fatal("matching read-only signing key rejected")
	}
	other, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, item := range []struct {
		id  string
		key *ecdsa.PrivateKey
	}{
		{"unknown-root", key}, {"worker-root", other}, {"worker-root", nil},
		{"worker-root", &ecdsa.PrivateKey{PublicKey: key.PublicKey}},
		{"worker-root", &ecdsa.PrivateKey{PublicKey: key.PublicKey, D: other.D}},
	} {
		if e := configurationWorkerSigningKey(c.Configuration, item.id, item.key); e == nil {
			t.Fatal("missing, mismatched or invalid private signing key accepted")
		}
		if worker, e := OpenConfigurationWorker(context.Background(), c, item.id, item.key, nil); e == nil || worker != nil {
			t.Fatal("key mismatch reached a live worker")
		}
	}
}

// This driver answers only fixed role/clock metadata. It cannot create a
// transaction, read a receipt, compile a configuration or simulate publication.
type configurationWorkerConnector struct {
	role        string
	queries     atomic.Int32
	clockCancel context.CancelFunc
}
type configurationWorkerDriver struct{}
type configurationWorkerConn struct{ owner *configurationWorkerConnector }
type configurationWorkerRows struct {
	values []driver.Value
	read   bool
}

func (c *configurationWorkerConnector) Connect(context.Context) (driver.Conn, error) {
	return &configurationWorkerConn{c}, nil
}
func (*configurationWorkerConnector) Driver() driver.Driver { return configurationWorkerDriver{} }
func (configurationWorkerDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("fixture connector required")
}
func (*configurationWorkerConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("fixture permits no statements")
}
func (*configurationWorkerConn) Close() error { return nil }
func (*configurationWorkerConn) Begin() (driver.Tx, error) {
	return nil, errors.New("fixture permits no publication")
}
func (r *configurationWorkerRows) Columns() []string {
	columns := make([]string, len(r.values))
	for i := range columns {
		columns[i] = fmt.Sprintf("fixed%d", i)
	}
	return columns
}
func (*configurationWorkerRows) Close() error { return nil }
func (r *configurationWorkerRows) Next(dst []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	copy(dst, r.values)
	return nil
}
func (c *configurationWorkerConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.owner.queries.Add(1)
	row := func(values ...driver.Value) (driver.Rows, error) {
		return &configurationWorkerRows{values: values}, nil
	}
	switch {
	case strings.HasPrefix(query, "SELECT current_user,session_user,"):
		if strings.Contains(query, "(SELECT count(*)") {
			return row(c.owner.role, c.owner.role, false, int64(0))
		}
		return row(c.owner.role, c.owner.role, false)
	case strings.HasPrefix(query, "SELECT has_table_privilege(current_user,$1::text") && len(args) == 1:
		table, _ := args[0].Value.(string)
		switch table {
		case "managed_configuration_previews", "managed_configuration_versions", "managed_configuration_layer_versions":
			return row(true, true, false, false)
		case "managed_configuration_heads", "managed_configuration_layer_heads":
			return row(true, true, true, false)
		case "managed_configuration_assignments":
			return row(true, true, true, true)
		case "managed_configuration_drafts", "managed_configuration_draft_ops":
			return row(false, false, false, false)
		}
	case strings.Contains(query, "'managed_configuration_requests','INSERT'"):
		return row(false, true, false, false)
	case strings.Contains(query, "'identity_policy_activation','outcome'"):
		return row(false, false)
	case strings.Contains(query, "'identity_devices','publication_source_policy_revision'"):
		return row(true, true, true)
	case strings.HasPrefix(query, "UPDATE identity_clock SET second=GREATEST"):
		if c.owner.clockCancel != nil {
			c.owner.clockCancel()
		}
		return row(int64(1_800_000_001))
	}
	return nil, errors.New("fixture rejected nonmetadata query")
}

func TestConfigurationWorkerRuntimeRejectsWrongRoleAndCancellationBeforeAdminDiscovery(t *testing.T) {
	c, key := configurationWorkerFixture(t)
	for _, role := range []string{"syn443_control_api", "syn443_source_worker", "postgres"} {
		connector := &configurationWorkerConnector{role: role}
		db := sql.OpenDB(connector)
		worker, e := configurationWorkerFromDB(context.Background(), c.Configuration, db, "worker-root", key, nil)
		_ = db.Close()
		if e == nil || worker != nil || connector.queries.Load() != 1 {
			t.Fatal("wrong SQL role reached administrative provider discovery")
		}
	}
	connector := &configurationWorkerConnector{role: "syn443_identity_publisher"}
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if worker, e := configurationWorkerFromDB(ctx, c.Configuration, db, "worker-root", key, nil); e == nil || worker != nil || connector.queries.Load() != 0 {
		t.Fatal("cancelled startup consumed SQL or provider work")
	}
}

func TestConfigurationWorkerRuntimeUsesLayerOnlyStoreAndPinnedAdminTLSProvider(t *testing.T) {
	c, key := configurationWorkerFixture(t)
	idp := newConfigurationAdminOIDCFixture(t)
	c.Configuration.Issuer = idp.adminIssuer
	connector := &configurationWorkerConnector{role: "syn443_identity_publisher"}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { _ = db.Close() })
	worker, e := configurationWorkerFromDB(context.Background(), c.Configuration, db, "worker-root", key, idp.server.Client().Transport)
	if e != nil {
		t.Fatal("bounded independent worker startup rejected", e)
	}
	t.Cleanup(func() { _ = worker.Close() })
	if worker.publisher.Store.DB != db || worker.publisher.Sources.DB != db || worker.publisher.Key != key ||
		worker.publisher.Origin != c.Configuration.ControlOrigin || worker.publisher.AssuranceACR != c.Configuration.AssuranceACR {
		t.Fatal("independent administrative authority was not retained")
	}
	layerKey, _ := base64.StdEncoding.DecodeString(c.Configuration.LayerEncryptionKey)
	sourceKey, _ := base64.StdEncoding.DecodeString(c.Configuration.SourceEncryptionKey)
	layers, _ := enrollment.NewStore(db, layerKey)
	wrong, _ := enrollment.NewStore(db, sourceKey)
	protected := worker.publisher.Store.Seal([]byte("synthetic-layer-only"), "owned-test-aad")
	if opened, e := layers.Open(protected, "owned-test-aad"); e != nil || string(opened) != "synthetic-layer-only" {
		t.Fatal("layer store received the wrong key compartment")
	}
	if _, e := wrong.Open(protected, "owned-test-aad"); e == nil {
		t.Fatal("source encryption key can open layer state")
	}
	now, e := worker.Now(context.Background(), time.Unix(1_800_000_000, 0))
	if e != nil || now.Unix() != 1_800_000_001 {
		t.Fatal("worker did not use the database's identity clock")
	}
	if idp.adminMetadata.Load() != 4 || idp.deviceMetadata.Load() != 0 {
		t.Fatal("worker borrowed device issuer discovery")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	queries := connector.queries.Load()
	if e := worker.RunOnce(ctx, now); e == nil || connector.queries.Load() != queries {
		t.Fatal("cancelled tick reached a receipt")
	}
}

func TestConfigurationWorkerClockPreservesSubsecondWallAndRapidPreviewOrdering(t *testing.T) {
	var clock configurationWorkerClock
	floor := time.Unix(1_800_000_000, 0).UTC()
	wall := floor.Add(125 * time.Millisecond)
	observed := time.Now() // Add preserves its monotonic component in these vectors.
	first, e := clock.advance(floor, wall, observed)
	if e != nil || !first.Equal(wall) {
		t.Fatal("SQL second discarded current wall precision", e)
	}
	previewIssued := first.Add(37 * time.Millisecond)
	// A nearly static/rolled-back wall still cannot rewind actual elapsed work.
	second, e := clock.advance(floor, wall.Add(time.Millisecond), observed.Add(40*time.Millisecond))
	if e != nil || !second.Equal(first.Add(40*time.Millisecond)) || second.Before(previewIssued) || !floor.Before(previewIssued) {
		t.Fatal("rapid second tick moved before its already issued preview", e)
	}
}

func TestConfigurationWorkerClockAnchorsFutureFloorAndContinuesAcrossWallAndDBRollback(t *testing.T) {
	var clock configurationWorkerClock
	floor := time.Unix(1_800_000_000, 0).UTC()
	observed := time.Now()
	first, e := clock.advance(floor, floor.Add(-time.Hour), observed)
	if e != nil || !first.Equal(floor) {
		t.Fatal("ahead-of-wall SQL floor did not anchor trusted time", e)
	}
	second, e := clock.advance(floor, floor.Add(-30*time.Minute), observed.Add(37*time.Millisecond))
	if e != nil || !second.Equal(floor.Add(37*time.Millisecond)) {
		t.Fatal("same SQL floor stopped elapsed time", e)
	}
	rolled := floor.Add(-10 * time.Second)
	third, e := clock.advance(rolled, rolled.Add(500*time.Millisecond), observed.Add(42*time.Millisecond))
	if e != nil || !third.Equal(floor.Add(42*time.Millisecond)) {
		t.Fatal("wall/database rollback rewound time or invented elapsed time", e)
	}
	unchanged, e := clock.advance(rolled, rolled.Add(501*time.Millisecond), observed.Add(42*time.Millisecond))
	if e != nil || !unchanged.Equal(third) {
		t.Fatal("zero elapsed observation fabricated a clock increment", e)
	}
	forward := floor.Add(time.Hour)
	jumped, e := clock.advance(forward, forward.Add(125*time.Millisecond), observed.Add(43*time.Millisecond))
	if e != nil || !jumped.Equal(forward.Add(125*time.Millisecond)) {
		t.Fatal("existing trusted wall-forward semantics changed", e)
	}
	continued, e := clock.advance(rolled, rolled, observed.Add(44*time.Millisecond))
	if e != nil || !continued.Equal(jumped.Add(time.Millisecond)) {
		t.Fatal("later rollback escaped the actual elapsed bound", e)
	}
}

func TestConfigurationWorkerClockNegativeElapsedSealsAndCancelledDBNowDoesNotUpdate(t *testing.T) {
	floor := time.Unix(1_800_000_001, 0).UTC()
	observed := time.Now()
	var clock configurationWorkerClock
	if _, e := clock.advance(floor, floor.Add(125*time.Millisecond), observed); e != nil {
		t.Fatal(e)
	}
	before := clock
	if _, e := clock.advance(floor, floor, observed.Add(-time.Nanosecond)); e == nil || !clock.invalid || !clock.trusted.Equal(before.trusted) || !clock.observed.Equal(before.observed) {
		t.Fatal("negative monotonic delta reset or extended a trusted clock")
	}
	if _, e := clock.advance(floor.Add(time.Hour), floor.Add(time.Hour), observed.Add(time.Hour)); e == nil {
		t.Fatal("sealed clock was reset by a later valid observation")
	}
	connector := &configurationWorkerConnector{role: "syn443_identity_publisher"}
	db := sql.OpenDB(connector)
	defer db.Close()
	store, e := enrollment.NewStore(db, bytes.Repeat([]byte{91}, 32))
	if e != nil {
		t.Fatal(e)
	}
	worker := &ConfigurationWorker{publisher: &ConfigurationPublisher{Store: store}, clock: before}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := worker.Now(ctx, floor.Add(time.Second)); e == nil || worker.clock != before || connector.queries.Load() != 0 {
		t.Fatal("already cancelled DB observation mutated clock state")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	connector.clockCancel = cancel
	if _, e := worker.Now(ctx, floor.Add(time.Second)); e == nil || worker.clock != before || connector.queries.Load() != 1 {
		t.Fatal("cancellation during the SQL clock request committed local time")
	}
}
