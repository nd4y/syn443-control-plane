//go:build keycloak

package keycloak_test

import (
	"context"
	"encoding/json"
	"github.com/nd4y/syn443-control-plane/internal/chatweb"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestSupportWebBFFWithActualKeycloakPKCEAndDPoP(t *testing.T) {
	f := setup(t)
	ui := httptest.NewUnstartedServer(nil)
	origin := "http://" + ui.Listener.Addr().String()
	clientID := "support-" + random()[:12]
	audience := "syn443-support-api"
	created := f.api("POST", "/clients", map[string]any{"clientId": clientID, "enabled": true, "protocol": "openid-connect", "publicClient": true, "standardFlowEnabled": true, "implicitFlowEnabled": false, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false, "redirectUris": []string{origin + "/callback"}, "webOrigins": []string{}, "attributes": map[string]string{"pkce.code.challenge.method": "S256", "dpop.bound.access.tokens": "true"}, "protocolMappers": []any{map[string]any{"name": "support-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": map[string]string{"included.custom.audience": audience, "access.token.claim": "true", "id.token.claim": "false"}}}})
	requireStatus(t, created, 201)
	found := f.api("GET", "/clients?clientId="+clientID, nil)
	requireStatus(t, found, 200)
	var clients []map[string]any
	json.Unmarshal(found.body, &clients)
	if len(clients) != 1 {
		t.Fatal("fixture client")
	}
	t.Cleanup(func() { requireStatus(t, f.api("DELETE", "/clients/"+clients[0]["id"].(string), nil), 204) })
	verifier, e := identity.NewProvider(context.Background(), f.issuer, audience, clientID, nil, true)
	if e != nil {
		t.Fatal("verifier initialization")
	}
	var api *httptest.Server
	api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP ")
		p, e := verifier.Verify(r.Context(), token, time.Now())
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 32769))
		proof, err := identity.RequestProof(r.Header.Get("DPoP"), identity.ProofContext{Method: "POST", URI: api.URL + r.URL.Path, Token: token, BodyHash: identity.Hash(raw), Now: time.Now()})
		if e != nil || err != nil || p.Subject != f.userID || p.Thumbprint != proof.Thumbprint {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"admin":true}`)
	}))
	t.Cleanup(api.Close)
	handler, e := chatweb.New(context.Background(), chatweb.Config{Origin: origin, APIOrigin: api.URL, Issuer: f.issuer, ClientID: clientID, Audience: audience, FixtureHTTP: true}, nil)
	if e != nil {
		t.Fatal("web initialization")
	}
	t.Cleanup(handler.Close)
	ui.Config.Handler = handler
	ui.Start()
	t.Cleanup(ui.Close)
	browser := browser()
	post := func(path string) *http.Response {
		req, _ := http.NewRequest("POST", origin+path, strings.NewReader(`{}`))
		req.Header.Set("Origin", origin)
		req.Header.Set("X-Syn443-CSRF", "1")
		req.Header.Set("Content-Type", "application/json")
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal("browser transport")
		}
		return res
	}
	res := post("/login")
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("login start")
	}
	link := object(t, raw)["url"].(string)
	page := f.request(browser, "GET", link, "", nil, false)
	requireStatus(t, page, 200)
	form := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page.body)
	if len(form) != 2 {
		t.Fatal("login form")
	}
	action := html.UnescapeString(string(form[1]))
	parsed, _ := url.Parse(action)
	if parsed.Scheme+"://"+parsed.Host != f.origin {
		t.Fatal("form origin")
	}
	redirect := f.form(browser, action, url.Values{"username": {f.username}, "password": {f.password}, "credentialId": {""}})
	if redirect.status != 302 && redirect.status != 303 {
		t.Fatal("credential redirect")
	}
	callback := redirect.headers.Get("Location")
	parsed, _ = url.Parse(callback)
	if parsed.Scheme+"://"+parsed.Host != origin || parsed.Path != "/callback" {
		t.Fatal("callback origin")
	}
	done := f.request(browser, "GET", callback, "", nil, false)
	requireStatus(t, done, 303)
	res = post("/chat/self")
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || object(t, raw)["admin"] != true {
		t.Fatal("actual bound API request")
	}
	res = post("/logout")
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("logout")
	}
	res = post("/chat/self")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("session remained active")
	}
}
