//go:build keycloak

package keycloak_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

// The shell harness creates this database and removes its whole container on exit.
func issuanceDatabases(t *testing.T) (owner, api, publisher *sql.DB) {
	t.Helper()
	u, err := url.Parse(os.Getenv("SYN443_TEST_DATABASE"))
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() == "" ||
		u.User.Username() != "postgres" || u.Path != "/postgres" || u.RawQuery != "sslmode=disable" {
		t.Fatal("temporary loopback database required")
	}
	open := func(endpoint string) *sql.DB {
		db, err := sql.Open("pgx", endpoint)
		if err != nil {
			t.Fatal("open fixture role")
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	owner = open(u.String())
	if _, err := owner.ExecContext(t.Context(), enrollment.Schema); err != nil {
		t.Fatal("install identity schema", err)
	}
	role := func(name string) *sql.DB {
		password := random()
		var statement string
		if err := owner.QueryRowContext(t.Context(), `SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOBYPASSRLS PASSWORD %L',$1::text,$2::text)`, name, password).Scan(&statement); err != nil {
			t.Fatal("prepare fixture role")
		}
		if _, err := owner.ExecContext(t.Context(), statement); err != nil {
			t.Fatal("create fixture role")
		}
		dsn := *u
		dsn.User = url.UserPassword(name, password)
		return open(dsn.String())
	}
	api, publisher = role("syn443_identity_api"), role("syn443_identity_publisher")
	if _, err := owner.ExecContext(t.Context(), "CREATE ROLE syn443_overlay_worker NOLOGIN NOINHERIT NOBYPASSRLS"); err != nil {
		t.Fatal("create fixture overlay role")
	}
	if _, err := owner.ExecContext(t.Context(), enrollment.Roles); err != nil {
		t.Fatal("apply runtime permissions", err)
	}
	return owner, api, publisher
}

func issuanceGrant(f *fixture, tag string) enrollment.Grant {
	// Distinct usable policies make an accidental shared template observable.
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"` + tag + `"}],"route":{"final":"` + tag + `"}}`)
	sum := sha256.Sum256(engine)
	return enrollment.Grant{Issuer: f.issuer, Subject: f.userID, DeviceLimit: 2, Until: time.Now().Add(time.Hour).Unix(),
		Template: policy.Payload{Operation: "configure", SchemaVersion: 1, Revision: 1, Audience: "syn443-device", AlgorithmRevision: "m1-local-v1",
			RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"},
			EngineConfigB64:      base64.RawURLEncoding.EncodeToString(engine), ContentHash: hex.EncodeToString(sum[:]),
			Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.org/generate_204", Required: true}}}}}
}

type issuedDevice struct {
	key     *ecdsa.PrivateKey
	session enrollment.Session
	thumb   string
	content string
}

func (d issuedDevice) request(t *testing.T, server *httptest.Server, method, path, token, nonce string, body []byte) reply {
	t.Helper()
	uri := server.URL + path
	claims := identity.ProofClaims{Jti: random(), Htm: method, Htu: uri, Ath: identity.Hash([]byte(token)), Nonce: nonce, Iat: time.Now().Unix()}
	req, err := http.NewRequestWithContext(t.Context(), method, uri, bytes.NewReader(body))
	if err != nil {
		t.Fatal("create device request")
	}
	if method == http.MethodPost {
		claims.RequestHash = identity.Hash(body)
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", signFixtureProof(t, d.key, claims))
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal("device request failed")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(raw) > 65536 {
		t.Fatal("device response size")
	}
	return reply{res.StatusCode, res.Header, raw}
}

func enrollWithKeycloak(t *testing.T, f *fixture, server *httptest.Server, grant enrollment.Grant) issuedDevice {
	t.Helper()
	const client, redirect = "syn443-android", "syn443://oauth/callback"
	code, verifier, _ := f.login(client, redirect)
	result := f.redeem(client, redirect, code, verifier)
	requireStatus(t, result, http.StatusOK)
	tokens := object(t, result.body)
	token, ok := tokens["access_token"].(string)
	if !ok || tokens["token_type"] != "DPoP" {
		t.Fatal("key-bound mobile token required")
	}
	key := identity.PublicJWK(&f.mobileKey.PublicKey)
	thumb, err := key.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	device := issuedDevice{key: f.mobileKey, thumb: thumb, content: grant.Template.EngineConfigB64}
	raw, err := json.Marshal(enrollment.Request{RequestID: random(), Key: key, Capabilities: grant.Template.RequiredCapabilities})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/devices/enroll"
	challenge := device.request(t, server, http.MethodPost, path, token, "", raw)
	requireStatus(t, challenge, http.StatusUnauthorized)
	nonce := challenge.headers.Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("missing enrollment challenge")
	}
	result = device.request(t, server, http.MethodPost, path, token, nonce, raw)
	requireStatus(t, result, http.StatusOK)
	if identity.Decode(result.body, &device.session, true) != nil || device.session.DeviceID == "" || device.session.Nonce == "" {
		t.Fatal("invalid device session")
	}
	return device
}

func TestTwoOwnersReceiveOnlyTheirAssignedDevicePolicies(t *testing.T) {
	const path = "/v1/device/policy"
	alice, bob := setup(t), setup(t)
	if alice.userID == bob.userID {
		t.Fatal("distinct Keycloak owners required")
	}
	db, apiDB, publisherDB := issuanceDatabases(t)
	var storageKey [32]byte
	if _, err := rand.Read(storageKey[:]); err != nil {
		t.Fatal(err)
	}
	apiStore, err := enrollment.NewStore(apiDB, storageKey[:])
	if err != nil {
		t.Fatal(err)
	}
	publisherStore, err := enrollment.NewStore(publisherDB, storageKey[:])
	if err != nil {
		t.Fatal(err)
	}
	provider, err := identity.NewProvider(t.Context(), alice.issuer, "syn443-api", "syn443-android", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "fixture-root"
	roots := map[string]*ecdsa.PublicKey{keyID: &signingKey.PublicKey}
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	api, err := enrollment.NewAPI(apiStore, provider, origin, roots, true)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = api
	server.Start()
	t.Cleanup(server.Close)
	a, b := issuanceGrant(alice, "personal-a"), issuanceGrant(bob, "personal-b")
	grants := make(map[string]enrollment.Grant)
	for _, g := range []enrollment.Grant{a, b} {
		if err := enrollment.Authorize(t.Context(), db, g, time.Now()); err != nil {
			t.Fatal(err)
		}
		grants[enrollment.Owner(g.Issuer, g.Subject)] = g
	}
	devices := []issuedDevice{enrollWithKeycloak(t, alice, server, a), enrollWithKeycloak(t, alice, server, a), enrollWithKeycloak(t, bob, server, b)}
	ids, thumbs := map[string]bool{}, map[string]bool{}
	for _, d := range devices {
		if ids[d.session.DeviceID] || thumbs[d.thumb] {
			t.Fatal("distinct device bindings required")
		}
		ids[d.session.DeviceID], thumbs[d.thumb] = true, true
	}
	publisher := enrollment.Publisher{Store: publisherStore, Verifier: provider, Grants: grants, KeyID: keyID, Key: signingKey, Origin: origin}
	// Use the same effective time as the running enrollment worker and API.
	// Signing against the raw fractional second can put notBefore ahead of
	// the durable identity clock on the first policy GET.
	publishedAt, err := publisherStore.Now(t.Context(), time.Now())
	if err != nil {
		t.Fatal("publisher clock", err)
	}
	if err := publisher.RunOnce(t.Context(), publishedAt); err != nil {
		t.Fatal(err)
	}
	t.Run("key_bound_publications", func(t *testing.T) {
		for _, d := range devices {
			res := d.request(t, server, http.MethodGet, path, d.session.AccessToken, d.session.Nonce, nil)
			requireStatus(t, res, http.StatusOK)
			payload, err := policy.VerifyBound(string(res.body), roots, d.session.DeviceID, d.thumb, time.Now())
			if err != nil || payload.EngineConfigB64 != d.content || payload.Revision != 1 || payload.NotBeforeMs != publishedAt.UnixMilli() {
				t.Fatal("incorrect personal policy")
			}
			for _, other := range devices {
				if other.thumb == d.thumb {
					continue
				}
				if _, err := policy.VerifyBound(string(res.body), roots, other.session.DeviceID, other.thumb, time.Now()); err == nil {
					t.Fatal("incorrect audience accepted a device policy")
				}
			}
		}
	})
	t.Run("other_device_keys_denied", func(t *testing.T) {
		for _, d := range devices {
			for _, other := range devices {
				if other.thumb == d.thumb {
					continue
				}
				res := other.request(t, server, http.MethodGet, path, d.session.AccessToken, d.session.Nonce, nil)
				requireStatus(t, res, http.StatusForbidden)
				if object(t, res.body)["code"] != "access_denied" {
					t.Fatal("expected fixed denial without a policy")
				}
			}
		}
	})
}
