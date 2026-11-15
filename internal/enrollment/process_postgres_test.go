//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func privateJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("private fixture file")
	}
}
func startProcess(t *testing.T, binary string, env []string) (stop func(), logs *bytes.Buffer) {
	t.Helper()
	absolute, e := filepath.Abs(filepath.Join(os.Getenv("SYN443_TEST_BINARY_DIR"), binary))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(absolute); e != nil {
		t.Fatal("fixture binary missing")
	}
	cmd := exec.Command(absolute)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PGPASSWORD=") || strings.HasPrefix(entry, "POSTGRES_PASSWORD=") || strings.HasPrefix(entry, "SYN443_TEST_DATABASE=") || strings.HasPrefix(entry, "SYN443_TEST_ADMIN_PASSWORD=") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, env...)
	logs = &bytes.Buffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if e = cmd.Start(); e != nil {
		t.Fatal("fixture process failed to start")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	t.Cleanup(stop)
	return stop, logs
}

func TestActualAPIPublisherProcessesAndRestart(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "https-with-loopback-identity-fixture"
		}
		t.Run(name, func(t *testing.T) { actualAPIPublisherProcessesAndRestart(t, secure) })
	}
}
func TestActualManagedAPIPublisherAndProviderWorkerProcesses(t *testing.T) {
	actualAPIPublisherProcessesAndRestart(t, true, true)
}
func actualAPIPublisherProcessesAndRestart(t *testing.T, secure bool, managed ...bool) {
	withBroker := len(managed) == 1 && managed[0]
	f := newFixture(t, 1)
	f.now = time.Now().UTC().Truncate(time.Second)
	rsaKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var issuer string
	idp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/test/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/protocol/openid-connect/certs"})
		case "/realms/test/protocol/openid-connect/certs":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture", "n": b64.EncodeToString(rsaKey.N.Bytes()), "e": "AQAB"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = "http://" + idp.Listener.Addr().String() + "/realms/test"
	idp.Start()
	defer idp.Close()
	f.grant.Issuer = issuer
	f.grant.Until = f.now.Unix() + 7200
	if withBroker {
		engine := []byte(`{"outbounds":[{"type":"netbird","tag":"home","management_url":"https://overlay.example.invalid","managed":{"overlayId":"home","resourceId":"fixture-resource","networkId":"fixture-network","identityEpoch":1,"setupReference":"caller-reference-is-not-authority","setupVersion":1}}],"route":{"final":"home"}}`)
		engine = []byte(strings.Replace(string(engine), "caller-reference-is-not-authority", random(), 1))
		sum := sha256.Sum256(engine)
		f.grant.Template.EngineConfigB64 = b64.EncodeToString(engine)
		f.grant.Template.ContentHash = fmt.Sprintf("%x", sum)
		f.grant.OverlayGroups = map[string][]string{"fixture-resource": {"group-a"}}
	}
	if e = Authorize(context.Background(), fixtureOwner, f.grant, f.now); e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	origin := "http://" + address
	if secure {
		origin = "https://" + address
	}
	public, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	config := Config{Listen: address, Origin: origin, Issuer: issuer, Audience: "syn443-api", ClientID: "syn443-android", Database: fixtureAPIDSN, EncryptionKey: base64.StdEncoding.EncodeToString(f.encryption), Roots: map[string]string{"fixture-root": base64.StdEncoding.EncodeToString(public)}, FixtureHTTP: true}
	if withBroker {
		config.OverlayServiceID = "fixture-service"
		config.OverlayBrokerEnabled = true
	}
	dir := t.TempDir()
	apiFile := filepath.Join(dir, "api.json")
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if secure {
		fixture := httptest.NewTLSServer(http.NotFoundHandler())
		certificate := fixture.TLS.Certificates[0]
		fixture.Close()
		config.Certificate = filepath.Join(dir, "server.crt")
		config.CertificateKey = filepath.Join(dir, "server.key")
		keyDER, e := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if e != nil {
			t.Fatal("fixture TLS key")
		}
		if os.WriteFile(config.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600) != nil || os.WriteFile(config.CertificateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600) != nil {
			t.Fatal("fixture TLS files")
		}
		cert, e := x509.ParseCertificate(certificate.Certificate[0])
		if e != nil {
			t.Fatal("fixture certificate")
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	}
	privateJSON(t, apiFile, config)
	stopAPI, apiLog := startProcess(t, "enrollment-api", []string{"SYN443_ENROLLMENT_CONFIG=" + apiFile})
	ready := false
	for i := 0; i < 50; i++ {
		r, e := client.Get(origin + "/v1/device/policy")
		if e == nil {
			r.Body.Close()
			if r.StatusCode == 401 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("API readiness failed")
	}
	k := key(t)
	thumb, _ := identity.PublicJWK(&k.PublicKey).Thumbprint()
	jwtHeader, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "fixture", "typ": "JWT"})
	jwtClaims, _ := json.Marshal(map[string]any{"iss": issuer, "sub": f.grant.Subject, "aud": "syn443-api", "azp": "syn443-android", "iat": time.Now().Unix(), "exp": time.Now().Unix() + 300, "cnf": map[string]string{"jkt": thumb}})
	input := b64.EncodeToString(jwtHeader) + "." + b64.EncodeToString(jwtClaims)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sum[:])
	token := input + "." + b64.EncodeToString(sig)
	call := func(method, path, token, nonce, proof string, body []byte) (int, http.Header, []byte) {
		t.Helper()
		if proof == "" {
			proof = signed(t, k, method, origin+path, token, nonce, body, time.Now())
		}
		req, _ := http.NewRequest(method, origin+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", proof)
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
		}
		r, e := client.Do(req)
		if e != nil {
			t.Fatal("API transport failed")
		}
		defer r.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(r.Body, 524289))
		if e != nil || len(raw) > 524288 {
			t.Fatal("API response limit")
		}
		return r.StatusCode, r.Header, raw
	}
	caps := []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}
	if withBroker {
		caps = append(caps, "overlay.credentials.v1")
	}
	raw, _ := json.Marshal(Request{random(), identity.PublicJWK(&k.PublicKey), caps})
	status, h, _ := call("POST", "/v1/devices/enroll", token, "", "", raw)
	if status != 401 || h.Get("DPoP-Nonce") == "" {
		t.Fatal("real nonce challenge")
	}
	status, _, response := call("POST", "/v1/devices/enroll", token, h.Get("DPoP-Nonce"), "", raw)
	if status != 200 {
		t.Fatal("real enrollment failed", status)
	}
	var session Session
	if identity.Decode(response, &session, true) != nil {
		t.Fatal("real session response")
	}
	proof := signed(t, k, "GET", origin+"/v1/device/policy", session.AccessToken, session.Nonce, nil, time.Now())
	status, _, _ = call("GET", "/v1/device/policy", session.AccessToken, session.Nonce, proof, nil)
	if status != 202 {
		t.Fatal("pending assignment")
	}
	stopAPI()
	if bytes.Contains(apiLog.Bytes(), []byte(token)) || bytes.Contains(apiLog.Bytes(), []byte(session.AccessToken)) {
		t.Fatal("API token in process output")
	}
	stopAPI, _ = startProcess(t, "enrollment-api", []string{"SYN443_ENROLLMENT_CONFIG=" + apiFile})
	defer stopAPI()
	ready = false
	for i := 0; i < 50; i++ {
		r, e := client.Get(origin + "/v1/device/policy")
		if e == nil {
			r.Body.Close()
			if r.StatusCode == 401 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("API restart readiness")
	}
	status, _, _ = call("GET", "/v1/device/policy", session.AccessToken, session.Nonce, proof, nil)
	if status != 401 {
		t.Fatal("proof replay survived process restart")
	}
	status, _, _ = call("GET", "/v1/device/policy", session.AccessToken, session.Nonce, "", nil)
	if status != 202 {
		t.Fatal("durable device session lost")
	}
	workerFile := filepath.Join(dir, "worker.json")
	config.Database = fixturePublisherDSN
	privateJSON(t, workerFile, config)
	grantFile := filepath.Join(dir, "grants.json")
	privateJSON(t, grantFile, []Grant{f.grant})
	keyFile := filepath.Join(dir, "signing.pem")
	der, _ := x509.MarshalPKCS8PrivateKey(f.key)
	if os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600) != nil {
		t.Fatal("private signer fixture")
	}
	workerEnv := []string{"SYN443_ENROLLMENT_CONFIG=" + workerFile, "SYN443_ENROLLMENT_GRANTS=" + grantFile, "SYN443_POLICY_SIGNING_KEY_FILE=" + keyFile, "SYN443_POLICY_KEY_ID=fixture-root"}
	if withBroker {
		metadataFile := filepath.Join(dir, "overlay-metadata.json")
		privateJSON(t, metadataFile, []BrokerPolicyResource{{ResourceID: "fixture-resource", Revision: 1, AccountID: "account-a", ManagementOrigin: "https://overlay.example.invalid", NetworkID: "fixture-network", Groups: []string{"group-a"}}})
		workerEnv = append(workerEnv, "SYN443_OVERLAY_POLICY_RESOURCES="+metadataFile)
	}
	stopWorker, workerLog := startProcess(t, "enrollment-worker", workerEnv)
	var bundle []byte
	published := false
	for i := 0; i < 40; i++ {
		status, _, bundle = call("GET", "/v1/device/policy", session.AccessToken, session.Nonce, "", nil)
		if status == 200 {
			published = true
			break
		}
		if status != 202 {
			t.Fatal("publication failed", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !published {
		t.Fatal("publication worker did not deliver")
	}
	if _, e = policy.VerifyBound(string(bundle), map[string]*ecdsa.PublicKey{"fixture-root": &f.key.PublicKey}, session.DeviceID, thumb, time.Now()); e != nil {
		t.Fatal("real signed publication")
	}
	if withBroker {
		payload, e := policy.VerifyBound(string(bundle), map[string]*ecdsa.PublicKey{"fixture-root": &f.key.PublicKey}, session.DeviceID, thumb, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		engine, _ := base64.RawURLEncoding.DecodeString(payload.EngineConfigB64)
		var doc struct {
			Outbounds []struct {
				Managed ManagedOverlayReference `json:"managed"`
			} `json:"outbounds"`
		}
		if json.Unmarshal(engine, &doc) != nil || len(doc.Outbounds) != 1 {
			t.Fatal("actual materialized engine")
		}
		ref := doc.Outbounds[0].Managed
		binding := overlay.CredentialBinding{Address: overlay.Address{ServiceID: config.OverlayServiceID, OwnerTag: overlayOwner(config.OverlayServiceID, issuer, f.grant.Subject), DeviceID: session.DeviceID, OverlayID: ref.OverlayID, Provider: "netbird", ResourceID: ref.ResourceID, NetworkID: ref.NetworkID, IdentityEpoch: ref.IdentityEpoch, ManagementURL: "https://overlay.example.invalid"}, KeyThumbprint: thumb, Reference: ref.SetupReference, Version: ref.SetupVersion, SecurityEpoch: payload.SecurityEpoch, OfflineUntilMs: payload.OfflineUntilMs}
		namespace, _ := overlay.Namespace(binding.Address)
		request, _ := json.Marshal(OverlayRequest{random(), namespace, ref.SetupReference, ref.SetupVersion})
		status, _, _ = call("POST", "/v1/device/overlay/fetch", session.AccessToken, session.Nonce, "", request)
		if status != 202 {
			t.Fatal("reserved process grant was not pending", status)
		}
		var creates atomic.Int32
		var idValue [16]byte
		if _, e = rand.Read(idValue[:]); e != nil {
			t.Fatal(e)
		}
		setup := fmt.Sprintf("%x-%x-%x-%x-%x", idValue[:4], idValue[4:6], idValue[6:8], idValue[8:10], idValue[10:])
		var operationName string
		var providerExpiry time.Time
		var providerMu sync.Mutex
		provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			providerMu.Lock()
			defer providerMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/accounts" {
				json.NewEncoder(w).Encode([]map[string]string{{"id": "account-a"}})
				return
			}
			if r.Method == "POST" && r.URL.Path == "/api/setup-keys" {
				creates.Add(1)
				var body struct {
					Name string `json:"name"`
				}
				if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body) != nil {
					w.WriteHeader(400)
					return
				}
				operationName = body.Name
				providerExpiry = time.Now().UTC().Add(24 * time.Hour)
			}
			if r.URL.Path != "/api/setup-keys" && r.URL.Path != "/api/setup-keys/key-a" {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"id": "key-a", "name": operationName, "key": setup, "type": "one-off", "valid": true, "revoked": false, "used_times": 0, "usage_limit": 1, "auto_groups": []string{"group-a"}, "expires": providerExpiry})
		}))
		defer provider.Close()
		providerConfig := BrokerRuntimeConfig{Database: fixtureBrokerDSN, EncryptionKey: config.EncryptionKey, FixtureLoopback: true, Resources: []BrokerResource{{ResourceID: "fixture-resource", Revision: 1, AccountID: "account-a", APIOrigin: provider.URL, ManagementOrigin: "https://overlay.example.invalid", NetworkID: "fixture-network", Groups: []string{"group-a"}, Token: "synthetic-netbird-management-token", RootCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})), AllowedNetworks: []string{"127.0.0.1/32"}}}}
		providerFile := filepath.Join(dir, "provider-worker.json")
		privateJSON(t, providerFile, providerConfig)
		stopProvider, providerLog := startProcess(t, "overlay-worker", []string{"SYN443_OVERLAY_BROKER_CONFIG=" + providerFile})
		var delivered OverlayReply
		ready := false
		for i := 0; i < 7; i++ {
			status, _, response = call("POST", "/v1/device/overlay/fetch", session.AccessToken, session.Nonce, "", request)
			if status == 200 {
				if json.Unmarshal(response, &delivered) != nil {
					t.Fatal("actual overlay reply")
				}
				ready = true
				break
			}
			if status != 202 {
				t.Fatal("actual overlay delivery denied", status)
			}
			time.Sleep(2 * time.Second)
		}
		stopProvider()
		stopWorker()
		if !ready || creates.Load() != 1 {
			t.Fatal("actual provider/publisher pipeline did not deliver exactly once")
		}
		credential, e := overlay.VerifyCredential(delivered.Envelope, map[string]*ecdsa.PublicKey{"fixture-root": &f.key.PublicKey}, binding, time.Now())
		if e != nil || credential.Value != setup {
			t.Fatal("actual addressed credential invalid", e)
		}
		if strings.Contains(providerLog.String(), setup) || strings.Contains(workerLog.String(), setup) || strings.Contains(providerLog.String(), providerConfig.Resources[0].Token) {
			t.Fatal("provider/credential secret in process diagnostics")
		}
	}
	stopWorker()
	if strings.Contains(workerLog.String(), token) || strings.Contains(workerLog.String(), f.grant.Template.EngineConfigB64) {
		t.Fatal("worker private payload in output")
	}
}
