package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
)

func TestBrokerRuntimeSQLCatalogUsesSeparateKeyAndClosedOwnerBootstrap(t *testing.T) {
	identityKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32))
	resourceKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))
	base := BrokerRuntimeConfig{Database: "postgres://fixture@127.0.0.1/test?sslmode=disable", EncryptionKey: identityKey, ResourceCatalog: true, ResourceEncryptionKey: resourceKey}
	path := filepath.Join(t.TempDir(), "catalog.json")
	write := func(c BrokerRuntimeConfig) {
		t.Helper()
		raw, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(base)
	loaded, e := ReadBrokerRuntimeConfig(path)
	if e != nil || !loaded.ResourceCatalog || len(loaded.Resources) != 0 {
		t.Fatal("SQL resource bootstrap", e)
	}
	db, e := sql.Open("pgx", base.Database)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	resolver, e := loaded.ResourceResolver(&Store{DB: db})
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := resolver.(*BrokerResourceCatalog); !ok {
		t.Fatal("SQL resource mode ignored")
	}
	if _, e = loaded.ResourceResolver(nil); e == nil {
		t.Fatal("missing SQL catalog database")
	}
	for _, mutate := range []func(*BrokerRuntimeConfig){
		func(c *BrokerRuntimeConfig) { c.ResourceEncryptionKey = "invalid" },
		func(c *BrokerRuntimeConfig) { c.ResourceEncryptionKey = c.EncryptionKey },
		func(c *BrokerRuntimeConfig) { c.EncryptionKey = resourceKey + "\n" },
		func(c *BrokerRuntimeConfig) { c.Resources = []BrokerResource{brokerResourceExample()} },
		func(c *BrokerRuntimeConfig) { c.ResourceCatalog = false },
	} {
		c := base
		mutate(&c)
		write(c)
		if _, e = ReadBrokerRuntimeConfig(path); e == nil {
			t.Fatal("ambiguous or shared-key resource authority")
		}
		if _, e = c.ResourceResolver(&Store{DB: db}); e == nil {
			t.Fatal("resolver bypassed protected bootstrap checks")
		}
	}
	legacy := BrokerRuntimeConfig{Resources: []BrokerResource{brokerResourceExample()}}
	if _, e = legacy.ResourceResolver(nil); e != nil {
		t.Fatal("legacy isolated bootstrap broken", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", base, base), resourceKey) {
		t.Fatal("resource key in diagnostics")
	}
}

func brokerResourceExample() BrokerResource {
	return BrokerResource{ResourceID: "resource-a", Revision: 1, AccountID: "account-a", APIOrigin: "https://api.example.invalid", ManagementOrigin: "https://overlay.example.invalid", NetworkID: "tenant", Groups: []string{"group-a"}, Token: "synthetic-netbird-management-token"}
}
func resourceScopeExample(r BrokerResource) BrokerScope {
	return BrokerScope{Binding: overlay.CredentialBinding{Address: overlay.Address{ResourceID: r.ResourceID, ManagementURL: r.ManagementOrigin, NetworkID: r.NetworkID}}, ResourceRevision: r.Revision, Account: r.AccountID, Groups: append([]string(nil), r.Groups...)}
}
func TestBrokerResourcesPinAccountNetworkRevisionGroupsAndDoNotExposeSecrets(t *testing.T) {
	r := brokerResourceExample()
	input := []BrokerResource{r}
	resources, e := NewBrokerResources(input, false)
	if e != nil {
		t.Fatal(e)
	}
	b := resourceScopeExample(r)
	input[0].Groups[0] = "changed-after-construction"
	c, close, e := resources.Resolve(context.Background(), b)
	if e != nil {
		t.Fatal("immutable resource", e)
	}
	close()
	id, account := c.Authority()
	if id != r.ResourceID || account != r.AccountID {
		t.Fatal("resource binding")
	}
	for _, mutate := range []func(*BrokerScope){func(v *BrokerScope) { v.ResourceRevision++ }, func(v *BrokerScope) { v.Account = "foreign" }, func(v *BrokerScope) { v.Binding.Address.NetworkID = "foreign" }, func(v *BrokerScope) { v.Binding.Address.ManagementURL = "https://foreign.example.invalid" }, func(v *BrokerScope) { v.Groups = []string{"foreign"} }, func(v *BrokerScope) { v.Binding.Address.ResourceID = "foreign" }, func(v *BrokerScope) { v.Groups = nil }, func(v *BrokerScope) { v.Binding.Address.ManagementURL = "invalid" }} {
		wrong := b
		mutate(&wrong)
		if _, _, e = resources.Resolve(context.Background(), wrong); e == nil {
			t.Fatal("foreign resource resolved")
		}
	}
	var absent *BrokerResources
	if _, _, e = absent.Resolve(context.Background(), b); e == nil {
		t.Fatal("missing resource registry accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, _, e = resources.Resolve(ctx, b); e == nil {
			t.Fatal("cancelled resource operation accepted")
		}
	}
	diagnostic := fmt.Sprintf("%v %#v %v %#v", r, r, resources, resources)
	if strings.Contains(diagnostic, r.Token) || strings.Contains(diagnostic, r.AccountID) {
		t.Fatal("resource default diagnostics leaked")
	}
}
func TestBrokerResourceBootstrapRejectsInvalidOrAmbiguousOperatorInput(t *testing.T) {
	r := brokerResourceExample()
	for _, list := range [][]BrokerResource{nil, make([]BrokerResource, 17), {r, r}} {
		if _, e := NewBrokerResources(list, false); e == nil {
			t.Fatal("unbounded/duplicate resources")
		}
	}
	for _, mutate := range []func(*BrokerResource){
		func(v *BrokerResource) { v.Revision = 0 }, func(v *BrokerResource) { v.ManagementOrigin += "/" }, func(v *BrokerResource) { v.AccountID = "" }, func(v *BrokerResource) { v.Groups = nil }, func(v *BrokerResource) { v.Groups = []string{"a", "a"} }, func(v *BrokerResource) { v.Groups = []string{"../a"} }, func(v *BrokerResource) { v.AllowedNetworks = []string{"invalid"} }, func(v *BrokerResource) { v.RootCA = "invalid" }, func(v *BrokerResource) { v.RootCA = "   " }, func(v *BrokerResource) {
			v.RootCA = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}))
		}, func(v *BrokerResource) {
			v.RootCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}))
		}, func(v *BrokerResource) { v.Token = "" }, func(v *BrokerResource) { v.APIOrigin = "http://api.example.invalid" },
	} {
		v := r
		mutate(&v)
		if _, e := NewBrokerResources([]BrokerResource{v}, false); e == nil {
			t.Fatal("invalid provider bootstrap accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "broker.json")
	write := func(raw []byte) {
		t.Helper()
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	c := BrokerRuntimeConfig{Database: "postgres://fixture@127.0.0.1/test?sslmode=disable", EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Resources: []BrokerResource{r}}
	raw, _ := json.Marshal(c)
	write(raw)
	if _, e := ReadBrokerRuntimeConfig(path); e != nil {
		t.Fatal("private bootstrap", e)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c, c), c.EncryptionKey) {
		t.Fatal("bootstrap default diagnostics leaked key")
	}
	for _, raw := range [][]byte{[]byte(`{"unknown":true}`), []byte(`{"resources":[],"resources":[]}`), []byte(`{"database":"x","encryptionKey":"invalid"}`)} {
		write(raw)
		if _, e := ReadBrokerRuntimeConfig(path); e == nil {
			t.Fatal("malformed private bootstrap accepted")
		}
	}
	c.Database = ""
	raw, _ = json.Marshal(c)
	write(raw)
	if _, e := ReadBrokerRuntimeConfig(path); e == nil {
		t.Fatal("missing database accepted")
	}
	c.Database = "fixture"
	c.Resources = nil
	raw, _ = json.Marshal(c)
	write(raw)
	if _, e := ReadBrokerRuntimeConfig(path); e == nil {
		t.Fatal("missing resources accepted")
	}
	if _, e := ReadBrokerRuntimeConfig(path + "-absent"); e == nil {
		t.Fatal("missing owner file accepted")
	}
}
func TestBrokerResourceResolverUsesActualTLSAndExactlyThePinnedProvider(t *testing.T) {
	now := time.Unix(1800000000, 0)
	var bytes [16]byte
	if _, e := rand.Read(bytes[:]); e != nil {
		t.Fatal(e)
	}
	v := hex.EncodeToString(bytes[:])
	secret := v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
	var calls atomic.Int32
	r := brokerResourceExample()
	tag := identity.Hash([]byte("operation"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("Authorization") != "Token "+r.Token {
			t.Error("provider authentication mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/api/accounts" {
			json.NewEncoder(w).Encode([]map[string]string{{"id": r.AccountID}})
			return
		}
		if request.URL.Path != "/api/setup-keys" || request.Method != "POST" {
			t.Error("unexpected provider operation")
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "key-a", "name": "syn443-" + tag, "key": secret, "type": "one-off", "valid": true, "revoked": false, "used_times": 0, "usage_limit": 1, "auto_groups": r.Groups, "expires": now.Add(24 * time.Hour)})
	}))
	defer server.Close()
	r.APIOrigin = server.URL
	r.RootCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	r.AllowedNetworks = []string{"127.0.0.1/32"}
	resources, e := NewBrokerResources([]BrokerResource{r}, true)
	if e != nil {
		t.Fatal(e)
	}
	provider, close, e := resources.Resolve(context.Background(), resourceScopeExample(r))
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	result, e := provider.CreateOneOff(context.Background(), tag, r.Groups, now)
	if e != nil || result.Secret != secret || calls.Load() != 2 {
		t.Fatal("actual pinned TLS issuance", e)
	}
}
