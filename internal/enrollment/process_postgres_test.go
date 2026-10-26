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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
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
	public, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	config := Config{Listen: address, Origin: origin, Issuer: issuer, Audience: "syn443-api", ClientID: "syn443-android", Database: fixtureAPIDSN, EncryptionKey: base64.StdEncoding.EncodeToString(f.encryption), Roots: map[string]string{"fixture-root": base64.StdEncoding.EncodeToString(public)}, FixtureHTTP: true}
	dir := t.TempDir()
	apiFile := filepath.Join(dir, "api.json")
	privateJSON(t, apiFile, config)
	stopAPI, apiLog := startProcess(t, "enrollment-api", []string{"SYN443_ENROLLMENT_CONFIG=" + apiFile})
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
	raw, _ := json.Marshal(Request{random(), identity.PublicJWK(&k.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}})
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
	stopWorker, workerLog := startProcess(t, "enrollment-worker", []string{"SYN443_ENROLLMENT_CONFIG=" + workerFile, "SYN443_ENROLLMENT_GRANTS=" + grantFile, "SYN443_POLICY_SIGNING_KEY_FILE=" + keyFile, "SYN443_POLICY_KEY_ID=fixture-root"})
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
	stopWorker()
	if !published {
		t.Fatal("publication worker did not deliver")
	}
	if _, e = policy.VerifyBound(string(bundle), map[string]*ecdsa.PublicKey{"fixture-root": &f.key.PublicKey}, session.DeviceID, thumb, time.Now()); e != nil {
		t.Fatal("real signed publication")
	}
	if strings.Contains(workerLog.String(), token) || strings.Contains(workerLog.String(), f.grant.Template.EngineConfigB64) {
		t.Fatal("worker private payload in output")
	}
}
