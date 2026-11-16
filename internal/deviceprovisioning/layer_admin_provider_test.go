package deviceprovisioning

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Two realms on a real TLS IdP intentionally share a signing key, kid and
// subject. Acceptance must depend on the pinned issuer, not those coincidences.
type configurationAdminOIDCFixture struct {
	server                        *httptest.Server
	key                           *rsa.PrivateKey
	adminIssuer, deviceIssuer     string
	adminMetadata, deviceMetadata atomic.Int32
}

func newConfigurationAdminOIDCFixture(t *testing.T) *configurationAdminOIDCFixture {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	f := &configurationAdminOIDCFixture{key: key}
	jwks, e := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "synthetic-oidc-key", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
	}}})
	if e != nil {
		t.Fatal(e)
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Method != http.MethodGet {
			http.Error(w, "invalid fixture transport", http.StatusBadRequest)
			return
		}
		var issuer string
		switch {
		case strings.HasPrefix(r.URL.Path, "/realms/admin/"):
			issuer = "https://" + r.Host + "/realms/admin"
			f.adminMetadata.Add(1)
		case strings.HasPrefix(r.URL.Path, "/realms/device/"):
			issuer = "https://" + r.Host + "/realms/device"
			f.deviceMetadata.Add(1)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/admin/.well-known/openid-configuration", "/realms/device/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/protocol/openid-connect/certs"})
		case "/realms/admin/protocol/openid-connect/certs", "/realms/device/protocol/openid-connect/certs":
			_, _ = w.Write(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	f.adminIssuer = f.server.URL + "/realms/admin"
	f.deviceIssuer = f.server.URL + "/realms/device"
	t.Cleanup(f.server.Close)
	return f
}

func (f *configurationAdminOIDCFixture) token(t *testing.T, issuer, client, subject, thumbprint string, now time.Time) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "synthetic-oidc-key"})
	claims, e := json.Marshal(map[string]any{
		"iss": issuer, "sub": subject, "aud": "syn443-control-api", "azp": client,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(),
		"acr": "urn:syn443:loa:2", "amr": []string{"otp"}, "scope": "openid syn443.control",
		"cnf": map[string]string{"jkt": thumbprint},
	})
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	hash := sha256.Sum256([]byte(input))
	signature, e := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, hash[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + enc.EncodeToString(signature)
}

func TestConfigurationAdminVerifierPinsIndependentTLSIssuer(t *testing.T) {
	f := newConfigurationAdminOIDCFixture(t)
	c := runtimeConfiguration(t)
	c.Issuer = f.adminIssuer
	ctx := context.Background()
	if _, e := c.AdminVerifier(ctx, nil); e == nil {
		t.Fatal("default production transport trusted an untrusted TLS fixture")
	}
	providers, e := c.AdminVerifier(ctx, f.server.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	thumb := identity.Hash([]byte("synthetic-device-proof-key"))
	for _, client := range c.ClientIDs {
		valid := f.token(t, f.adminIssuer, client, "synthetic-subject", thumb, now)
		principal, e := providers.Verify(ctx, valid, now)
		if e != nil || principal.Issuer != f.adminIssuer || principal.Subject != "synthetic-subject" || principal.Thumbprint != thumb || !principal.HasScope("syn443.control") || principal.MFAUntil(c.AssuranceACR, now) <= now.Unix() {
			t.Fatal("pinned admin realm token was not independently verified", e)
		}
		// Same key/kid/audience/client/subject/proof key; only issuer differs.
		foreign := f.token(t, f.deviceIssuer, client, "synthetic-subject", thumb, now)
		if _, e := providers.Verify(ctx, foreign, now); e == nil {
			t.Fatal("device issuer borrowed administrative authority")
		}
	}
	if f.adminMetadata.Load() != int32(2*len(c.ClientIDs)) || f.deviceMetadata.Load() != 0 {
		t.Fatal("provider fell back to or discovered an unpinned device issuer")
	}
	if _, e := c.AdminVerifier(nil, f.server.Client().Transport); e == nil {
		t.Fatal("nil runtime scope admitted")
	}
}
