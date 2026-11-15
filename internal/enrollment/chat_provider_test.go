package enrollment

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type chatIssuerTransport func(*http.Request) (*http.Response, error)

func (f chatIssuerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func chatIssuerConfig() Config {
	return Config{Issuer: "https://id.example.invalid/realms/devices", Audience: "device-api", ClientID: "device-android", ChatEnabled: true,
		ChatWebOrigin: "https://panel.example.invalid", ChatWebClientID: "support-web", ChatWebAudience: "support-api"}
}

func TestChatProviderPinsOnlyTheConfiguredIssuerAndRejectsForeignTokens(t *testing.T) {
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	encode := base64.RawURLEncoding.EncodeToString
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"fixture","n":"%s","e":"%s"}]}`, encode(k.N.Bytes()), encode(big.NewInt(int64(k.E)).Bytes()))
	now := time.Unix(1800000000, 0)
	for _, override := range []string{"", "https://id.example.invalid/realms/operators", "http://127.0.0.1:17845/realms/operators"} {
		t.Run(override, func(t *testing.T) {
			c := chatIssuerConfig()
			c.ChatWebIssuer = override
			c.FixtureHTTP = strings.HasPrefix(override, "http://127.0.0.1:")
			issuer := c.Issuer
			if override != "" {
				issuer = override
			}
			var requested []string
			tr := chatIssuerTransport(func(r *http.Request) (*http.Response, error) {
				requested = append(requested, r.URL.String())
				body := jwks
				switch r.URL.String() {
				case issuer + "/.well-known/openid-configuration":
					body = fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/protocol/openid-connect/certs")
				case issuer + "/protocol/openid-connect/certs":
				default:
					t.Fatalf("provider contacted another issuer: %s", r.URL.String())
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			provider, e := c.ChatProvider(context.Background(), tr)
			if e != nil || provider == nil {
				t.Fatal("pinned provider", e)
			}
			thumb := identity.Hash([]byte("synthetic public thumbprint"))
			sign := func(iss, audience, client string, signer *rsa.PrivateKey) string {
				claims, e := json.Marshal(map[string]any{"iss": iss, "sub": "synthetic-admin", "aud": audience, "azp": client, "iat": now.Unix(), "exp": now.Unix() + 300, "cnf": map[string]string{"jkt": thumb}})
				if e != nil {
					t.Fatal(e)
				}
				input := encode([]byte(`{"alg":"RS256","typ":"JWT","kid":"fixture"}`)) + "." + encode(claims)
				sum := sha256.Sum256([]byte(input))
				sig, e := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, sum[:])
				if e != nil {
					t.Fatal(e)
				}
				return input + "." + encode(sig)
			}
			valid := sign(issuer, c.ChatWebAudience, c.ChatWebClientID, k)
			p, e := provider.Verify(context.Background(), valid, now)
			if e != nil || p.Issuer != issuer || p.Subject != "synthetic-admin" || p.Thumbprint != thumb {
				t.Fatal("valid web identity", e)
			}
			foreign := "https://foreign.example.invalid/realms/operators"
			if override != "" {
				foreign = c.Issuer
			}
			other, e := rsa.GenerateKey(rand.Reader, 2048)
			if e != nil {
				t.Fatal(e)
			}
			for _, token := range []string{sign(foreign, c.ChatWebAudience, c.ChatWebClientID, k), sign(issuer, c.Audience, c.ClientID, k), sign(issuer, "wrong-audience", c.ChatWebClientID, k), sign(issuer, c.ChatWebAudience, "wrong-client", k), sign(issuer, c.ChatWebAudience, c.ChatWebClientID, other)} {
				if _, e := provider.Verify(context.Background(), token, now); e == nil {
					t.Fatal("foreign token accepted")
				}
			}
			if !reflect.DeepEqual(requested, []string{issuer + "/.well-known/openid-configuration", issuer + "/protocol/openid-connect/certs"}) {
				t.Fatal("invalid tokens triggered issuer fallback or repeated discovery")
			}
		})
	}
}

func TestChatProviderDisabledPartialAndUnsafeConfigurationCannotContactAnIssuer(t *testing.T) {
	tr := chatIssuerTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid or disabled configuration made a request")
		return nil, identity.ErrInvalid
	})
	for _, c := range []Config{{}, {Issuer: "https://id.example.invalid/realms/devices", ChatEnabled: true}} {
		v, e := c.ChatProvider(context.Background(), tr)
		if e != nil || v != nil {
			t.Fatal("disabled web provider must be a nil interface", e)
		}
	}
	good := chatIssuerConfig()
	bad := []Config{{ChatWebIssuer: "https://id.example.invalid/realms/operators"}}
	for i := 0; i < 4; i++ {
		c := good
		switch i {
		case 0:
			c.ChatEnabled = false
		case 1:
			c.ChatWebOrigin = ""
		case 2:
			c.ChatWebClientID = ""
		case 3:
			c.ChatWebAudience = ""
		}
		bad = append(bad, c)
	}
	for _, issuer := range []string{"http://id.example.invalid/realms/operators", "https://user@id.example.invalid/realms/operators", "https://id.example.invalid/realms/operators?x=1", "https://id.example.invalid/realms/operators#x", "https://id.example.invalid/realms/operators/", "http://127.0.0.1:1234/realms/operators"} {
		c := good
		c.ChatWebIssuer = issuer
		bad = append(bad, c)
	}
	for _, c := range bad {
		if v, e := c.ChatProvider(context.Background(), tr); e == nil || v != nil {
			t.Fatal("unsafe web configuration accepted")
		}
	}
}

func TestChatWebIssuerUsesTheClosedOwnerOnlyConfigDecoder(t *testing.T) {
	path := t.TempDir() + "/config.json"
	c := chatIssuerConfig()
	c.ChatWebIssuer = "https://id.example.invalid/realms/operators"
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	got, e := ReadConfig(path)
	if e != nil || got.ChatWebIssuer != c.ChatWebIssuer || got.Issuer != c.Issuer {
		t.Fatal("explicit issuer config did not round trip", e)
	}
	for _, raw := range []string{`{"chatWebISSUER":"https://id.example.invalid/realms/operators"}`, `{"chatWebIssuer":"https://id.example.invalid/realms/operators","chatWebIssuer":"https://other.example.invalid"}`} {
		if e = os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = ReadConfig(path); e == nil {
			t.Fatal("unknown or duplicate issuer field accepted")
		}
	}
}
