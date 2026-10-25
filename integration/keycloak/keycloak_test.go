//go:build keycloak

// This harness only accepts a temporary loopback IdP. It never contacts an operator's IdP.
package keycloak_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	t                                                 *testing.T
	issuer, origin, admin, username, password, userID string
}
type reply struct {
	status  int
	headers http.Header
	body    []byte
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("entropy unavailable")
	}
	return hex.EncodeToString(b)
}
func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Timeout: 10 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (f *fixture) request(c *http.Client, method, endpoint, contentType string, body io.Reader, admin bool) reply {
	f.t.Helper()
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		f.t.Fatal("request construction")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if admin {
		req.Header.Set("Authorization", "Bearer "+f.admin)
	}
	r, err := c.Do(req)
	if err != nil {
		f.t.Fatal("HTTP transport failed (details suppressed)")
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 524289))
	if err != nil || len(data) > 524288 {
		f.t.Fatal("response read limit")
	}
	return reply{r.StatusCode, r.Header, data}
}
func (f *fixture) form(c *http.Client, endpoint string, fields url.Values) reply {
	return f.request(c, "POST", endpoint, "application/x-www-form-urlencoded", strings.NewReader(fields.Encode()), false)
}
func (f *fixture) api(method, path string, data any) reply {
	var body io.Reader
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			f.t.Fatal("JSON encoding")
		}
		body = strings.NewReader(string(raw))
	}
	return f.request(browser(), method, f.origin+"/admin/realms/syn443-test"+path, "application/json", body, true)
}
func requireStatus(t *testing.T, r reply, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("HTTP status %d, expected %d (body suppressed)", r.status, status)
	}
}
func object(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("invalid JSON object")
	}
	return v
}
func (f *fixture) token(fields url.Values) reply {
	return f.form(browser(), f.issuer+"/protocol/openid-connect/token", fields)
}
func (f *fixture) authorize(client, redirect string, extra url.Values) (reply, string, string) {
	state, nonce := random(), random()
	fields := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}, "state": {state}, "nonce": {nonce}}
	for k, v := range extra {
		fields[k] = v
	}
	return f.request(browser(), "GET", f.issuer+"/protocol/openid-connect/auth?"+fields.Encode(), "", nil, false), state, nonce
}
func (f *fixture) login(client, redirect string) (code, verifier, nonce string) {
	f.t.Helper()
	verifier = random()
	sum := sha256.Sum256([]byte(verifier))
	state := random()
	nonce = random()
	fields := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}, "state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	c := browser()
	r := f.request(c, "GET", f.issuer+"/protocol/openid-connect/auth?"+fields.Encode(), "", nil, false)
	requireStatus(f.t, r, 200)
	form := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(r.body)
	if len(form) != 2 {
		f.t.Fatal("login form missing")
	}
	action := html.UnescapeString(string(form[1]))
	u, err := url.Parse(action)
	if err != nil || u.Scheme+"://"+u.Host != f.origin || !strings.HasPrefix(u.Path, "/realms/syn443-test/login-actions/") {
		f.t.Fatal("login form origin")
	}
	r = f.form(c, action, url.Values{"username": {f.username}, "password": {f.password}, "credentialId": {""}})
	if r.status != 302 && r.status != 303 {
		f.t.Fatal("login did not redirect")
	}
	u, err = url.Parse(r.headers.Get("Location"))
	expected, _ := url.Parse(redirect)
	if err != nil || u.Scheme != expected.Scheme || u.Host != expected.Host || u.Path != expected.Path || u.Query().Get("state") != state || u.Query().Get("code") == "" {
		f.t.Fatal("callback/state/code invalid")
	}
	return u.Query().Get("code"), verifier, nonce
}
func (f *fixture) redeem(client, redirect, code, verifier string) reply {
	return f.token(url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {redirect}, "code": {code}, "code_verifier": {verifier}})
}
func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		t.Fatal("base64url decode")
	}
	return b
}
func (f *fixture) verified(raw string) map[string]any {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		f.t.Fatal("JWT format")
	}
	header := object(f.t, decode(f.t, parts[0]))
	if header["alg"] != "RS256" {
		f.t.Fatal("JWT algorithm")
	}
	r := f.request(browser(), "GET", f.issuer+"/protocol/openid-connect/certs", "", nil, false)
	requireStatus(f.t, r, 200)
	var keys struct {
		Keys []struct{ Kid, Kty, N, E string }
	}
	if json.Unmarshal(r.body, &keys) != nil {
		f.t.Fatal("JWKS format")
	}
	found := false
	for _, k := range keys.Keys {
		if k.Kid != header["kid"] {
			continue
		}
		if k.Kty != "RSA" {
			f.t.Fatal("JWKS type")
		}
		n := new(big.Int).SetBytes(decode(f.t, k.N))
		e := new(big.Int).SetBytes(decode(f.t, k.E))
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&rsa.PublicKey{N: n, E: int(e.Int64())}, crypto.SHA256, sum[:], decode(f.t, parts[2])) != nil {
			f.t.Fatal("JWT signature")
		}
		found = true
	}
	if !found {
		f.t.Fatal("JWKS signing key missing")
	}
	claims := object(f.t, decode(f.t, parts[1]))
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= float64(time.Now().Unix()) || claims["iss"] != f.issuer || claims["sub"] != f.userID {
		f.t.Fatal("JWT issuer/subject/expiry")
	}
	return claims
}
func fixtureIssuer(issuer string) (*url.URL, bool) {
	u, e := url.Parse(issuer)
	if e != nil {
		return nil, false
	}
	port, e := strconv.Atoi(u.Port())
	return u, e == nil && port >= 1024 && port <= 65535 && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Path == "/realms/syn443-test" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.User == nil
}
func TestFixtureRefusesExternalOrAmbiguousIssuer(t *testing.T) {
	for _, raw := range []string{"https://id.example.org/realms/syn443-test", "http://localhost:17845/realms/syn443-test", "http://127.0.0.1:0/realms/syn443-test", "http://127.0.0.1:65536/realms/syn443-test", "http://127.0.0.1:17845/realms/master", "http://127.0.0.1:17845/realms/syn443-test?", "http://127.0.0.1:17845/realms/syn443-test?x=1", "http://127.0.0.1:17845/realms/syn443-test#x", "http://fixture@127.0.0.1:17845/realms/syn443-test"} {
		if _, ok := fixtureIssuer(raw); ok {
			t.Fatal("unsafe fixture issuer accepted")
		}
	}
	for _, raw := range []string{"http://127.0.0.1:1024/realms/syn443-test", "http://127.0.0.1:65535/realms/syn443-test"} {
		if _, ok := fixtureIssuer(raw); !ok {
			t.Fatal("valid fixture boundary rejected")
		}
	}
}
func setup(t *testing.T) *fixture {
	issuer := os.Getenv("SYN443_TEST_ISSUER")
	u, ok := fixtureIssuer(issuer)
	if !ok {
		t.Fatal("explicit temporary loopback issuer required")
	}
	password := os.Getenv("SYN443_TEST_ADMIN_PASSWORD")
	if len(password) < 24 {
		t.Fatal("ephemeral admin password required")
	}
	f := &fixture{t: t, issuer: issuer, origin: u.Scheme + "://" + u.Host, username: "fixture-" + random()[:12], password: random()}
	r := f.form(browser(), f.origin+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"fixture-admin"}, "password": {password}})
	requireStatus(t, r, 200)
	f.admin = object(t, r.body)["access_token"].(string)
	r = f.api("GET", "", nil)
	requireStatus(t, r, 200)
	realm := object(t, r.body)
	if realm["registrationAllowed"] != false || realm["revokeRefreshToken"] != true || realm["refreshTokenMaxReuse"] != float64(0) {
		t.Fatal("realm safety flags")
	}
	r = f.api("POST", "/users", map[string]any{"username": f.username, "enabled": true, "firstName": "Integration", "lastName": "Test", "email": f.username + "@example.org", "emailVerified": true, "requiredActions": []string{}, "credentials": []map[string]any{{"type": "password", "value": f.password, "temporary": false}}})
	requireStatus(t, r, 201)
	r = f.api("GET", "/users?username="+f.username+"&exact=true", nil)
	requireStatus(t, r, 200)
	var users []map[string]any
	if json.Unmarshal(r.body, &users) != nil || len(users) != 1 {
		t.Fatal("created user missing")
	}
	f.userID = users[0]["id"].(string)
	t.Cleanup(func() { requireStatus(t, f.api("DELETE", "/users/"+f.userID, nil), 204) })
	r = f.api("GET", "/roles/syn443-user", nil)
	requireStatus(t, r, 200)
	role := object(t, r.body)
	requireStatus(t, f.api("POST", "/users/"+f.userID+"/role-mappings/realm", []any{role}), 204)
	return f
}
func TestIsolatedRealm(t *testing.T) {
	f := setup(t)
	client := "syn443-test-web"
	redirect := "http://127.0.0.1:17843/callback"
	for _, v := range []struct{ client, redirect string }{{client, redirect}, {"syn443-android", "syn443://oauth/callback"}} {
		t.Run(v.client, func(t *testing.T) {
			f.t = t
			code, verifier, nonce := f.login(v.client, v.redirect)
			r := f.redeem(v.client, v.redirect, code, verifier)
			requireStatus(t, r, 200)
			tokens := object(t, r.body)
			id := f.verified(tokens["id_token"].(string))
			if id["aud"] != v.client || id["nonce"] != nonce {
				t.Fatal("ID audience/nonce")
			}
			access := f.verified(tokens["access_token"].(string))
			roles := access["realm_access"].(map[string]any)["roles"].([]any)
			found := false
			for _, role := range roles {
				if role == "syn443-user" {
					found = true
				}
			}
			if !found {
				t.Fatal("realm role missing")
			}
			r = f.redeem(v.client, v.redirect, code, verifier)
			requireStatus(t, r, 400)
			if object(t, r.body)["error"] != "invalid_grant" {
				t.Fatal("code replay accepted")
			}
		})
	}
	t.Run("wrong-verifier", func(t *testing.T) {
		f.t = t
		code, _, _ := f.login(client, redirect)
		r := f.redeem(client, redirect, code, random())
		requireStatus(t, r, 400)
		if object(t, r.body)["error"] != "invalid_grant" {
			t.Fatal("wrong verifier accepted")
		}
	})
	for _, v := range []struct {
		name   string
		fields url.Values
	}{{"missing-pkce", nil}, {"plain-pkce", url.Values{"code_challenge": {random()}, "code_challenge_method": {"plain"}}}, {"foreign-redirect", url.Values{"redirect_uri": {"https://example.org/callback"}}}, {"implicit", url.Values{"response_type": {"token"}}}} {
		t.Run(v.name, func(t *testing.T) {
			f.t = t
			r, _, _ := f.authorize(client, redirect, v.fields)
			if r.status == 400 {
				return
			}
			if v.name == "foreign-redirect" || (r.status != 302 && r.status != 303) {
				t.Fatal("unsafe authorization accepted")
			}
			u, e := url.Parse(r.headers.Get("Location"))
			if e != nil || u.Scheme != "http" || u.Host != "127.0.0.1:17843" || u.Path != "/callback" {
				t.Fatal("error callback origin")
			}
			q := u.Query()
			if u.Fragment != "" {
				q, _ = url.ParseQuery(u.Fragment)
			}
			if q.Get("error") == "" || q.Get("code") != "" || q.Get("access_token") != "" || q.Get("id_token") != "" {
				t.Fatal("authorization not rejected")
			}
		})
	}
	t.Run("password-grant-disabled", func(t *testing.T) {
		f.t = t
		r := f.token(url.Values{"grant_type": {"password"}, "client_id": {client}, "username": {f.username}, "password": {f.password}})
		requireStatus(t, r, 400)
		if object(t, r.body)["error"] != "unauthorized_client" {
			t.Fatal("password grant accepted")
		}
	})
	t.Run("refresh-rotation-and-reuse", func(t *testing.T) {
		f.t = t
		code, verifier, _ := f.login(client, redirect)
		r := f.redeem(client, redirect, code, verifier)
		requireStatus(t, r, 200)
		old := object(t, r.body)["refresh_token"].(string)
		fields := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {old}}
		r = f.token(fields)
		requireStatus(t, r, 200)
		if object(t, r.body)["refresh_token"] == old {
			t.Fatal("refresh not rotated")
		}
		r = f.token(fields)
		requireStatus(t, r, 400)
		if object(t, r.body)["error"] != "invalid_grant" {
			t.Fatal("refresh replay accepted")
		}
	})
	f.t = t
}
