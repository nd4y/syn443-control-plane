//go:build keycloak

package keycloak_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/chatweb"
)

// This creates a client-specific flow in the disposable loopback realm only.
// The AMR mapper reads completed authenticators; no hard-coded OTP claim exists.
func (f *fixture) assuranceFlow() string {
	alias := "assurance-" + random()[:12]
	r := f.api("POST", "/authentication/flows", map[string]any{"alias": alias, "providerId": "basic-flow", "topLevel": true, "builtIn": false})
	requireStatus(f.t, r, 201)
	flowID := r.headers.Get("Location")
	flowID = flowID[strings.LastIndex(flowID, "/")+1:]
	f.t.Cleanup(func() { requireStatus(f.t, f.api("DELETE", "/authentication/flows/"+flowID, nil), 204) })
	update := func(parent, selector, requirement string) string {
		r := f.api("GET", "/authentication/flows/"+parent+"/executions", nil)
		requireStatus(f.t, r, 200)
		var executions []map[string]any
		if json.Unmarshal(r.body, &executions) != nil {
			f.t.Fatal("execution inventory")
		}
		for _, execution := range executions {
			if execution["providerId"] == selector || execution["displayName"] == selector {
				execution["requirement"] = requirement
				requireStatus(f.t, f.api("PUT", "/authentication/flows/"+parent+"/executions", execution), 204)
				return execution["id"].(string)
			}
		}
		f.t.Fatal("expected execution missing")
		return ""
	}
	configure := func(id string, config map[string]string) {
		requireStatus(f.t, f.api("POST", "/authentication/executions/"+id+"/config", map[string]any{"alias": "configuration-" + random()[:12], "config": config}), 201)
	}
	for index, provider := range []string{"auth-username-password-form", "auth-otp-form"} {
		branch := alias + "-level-" + strconv.Itoa(index+1)
		requireStatus(f.t, f.api("POST", "/authentication/flows/"+alias+"/executions/flow", map[string]any{"alias": branch, "type": "basic-flow", "priority": (index + 1) * 10}), 201)
		update(alias, branch, "CONDITIONAL")
		requireStatus(f.t, f.api("POST", "/authentication/flows/"+branch+"/executions/execution", map[string]any{"provider": "conditional-level-of-authentication", "priority": 10}), 201)
		condition := update(branch, "conditional-level-of-authentication", "REQUIRED")
		configure(condition, map[string]string{"loa-condition-level": strconv.Itoa(index + 1), "loa-max-age": "0"})
		requireStatus(f.t, f.api("POST", "/authentication/flows/"+branch+"/executions/execution", map[string]any{"provider": provider, "priority": 20}), 201)
		execution := update(branch, provider, "REQUIRED")
		method := "pwd"
		if index == 1 {
			method = "otp"
		}
		configure(execution, map[string]string{"default.reference.value": method, "default.reference.maxAge": "600"})
	}
	return flowID
}

func fixtureOTP(secret string) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	h := hmac.New(sha1.New, []byte(secret))
	h.Write(counter[:])
	value := h.Sum(nil)
	offset := int(value[len(value)-1] & 15)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(value[offset:offset+4])&0x7fffffff)%1000000)
}

func TestControlWebReauthenticationWithActualKeycloakOTPAndAssuranceClaims(t *testing.T) {
	f := setup(t)
	flowID := f.assuranceFlow()
	secret := random()[:32]
	secretData, _ := json.Marshal(map[string]string{"value": secret})
	requireStatus(t, f.api("PUT", "/users/"+f.userID, map[string]any{"credentials": []any{map[string]any{"type": "otp", "userLabel": "Synthetic fixture only", "secretData": string(secretData), "credentialData": `{"subType":"totp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1"}`}}}), 204)
	ui := httptest.NewUnstartedServer(nil)
	origin := "http://" + ui.Listener.Addr().String()
	clientID, audience := "control-"+random()[:12], "syn443-control-api"
	mapper := func(name, provider string, config map[string]string) any {
		return map[string]any{"name": name, "protocol": "openid-connect", "protocolMapper": provider, "config": config}
	}
	r := f.api("POST", "/clients", map[string]any{"clientId": clientID, "enabled": true, "protocol": "openid-connect", "publicClient": true, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "redirectUris": []string{origin + "/callback"}, "webOrigins": []string{}, "attributes": map[string]string{"pkce.code.challenge.method": "S256", "dpop.bound.access.tokens": "true", "acr.loa.map": `{"1":1,"2":2}`}, "authenticationFlowBindingOverrides": map[string]string{"browser": flowID}, "protocolMappers": []any{
		mapper("control-audience", "oidc-audience-mapper", map[string]string{"included.custom.audience": audience, "access.token.claim": "true"}),
		mapper("actual-amr", "oidc-amr-mapper", map[string]string{"access.token.claim": "true", "id.token.claim": "true"}),
	}})
	requireStatus(t, r, 201)
	client := object(t, f.api("GET", "/clients/"+r.headers.Get("Location")[strings.LastIndex(r.headers.Get("Location"), "/")+1:], nil).body)
	clientInternalID := client["id"].(string)
	t.Cleanup(func() { requireStatus(t, f.api("DELETE", "/clients/"+clientInternalID, nil), 204) })
	// An actual optional scope, rather than a token injected by the test verifier.
	scopeName := "syn443.control"
	r = f.api("POST", "/client-scopes", map[string]any{"name": scopeName, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": "true"}})
	requireStatus(t, r, 201)
	scopeID := r.headers.Get("Location")
	scopeID = scopeID[strings.LastIndex(scopeID, "/")+1:]
	t.Cleanup(func() { requireStatus(t, f.api("DELETE", "/client-scopes/"+scopeID, nil), 204) })
	requireStatus(t, f.api("PUT", "/clients/"+clientInternalID+"/optional-client-scopes/"+scopeID, nil), 204)
	api := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(api.Close)
	startWebFrontend(t, ui, chatweb.Config{Origin: origin, APIOrigin: api.URL, Issuer: f.issuer, ClientID: clientID, Audience: audience, FixtureHTTP: true, ControlConsole: true, ReauthenticationACR: "2"})
	b := browser()
	post := func(path string) reply {
		req, _ := http.NewRequest("POST", origin+path, strings.NewReader(`{}`))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Syn443-CSRF", "1")
		res, e := b.Do(req)
		if e != nil {
			t.Fatal("BFF request")
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 65537))
		return reply{res.StatusCode, res.Header, raw}
	}
	formAction := func(page reply, id string) string {
		requireStatus(t, page, 200)
		match := regexp.MustCompile(`<form[^>]*id="` + id + `"[^>]*action="([^"]+)"`).FindSubmatch(page.body)
		if len(match) != 2 {
			t.Fatal("expected identity form missing", id)
		}
		action := html.UnescapeString(string(match[1]))
		u, _ := url.Parse(action)
		if u.Scheme+"://"+u.Host != f.origin || !strings.HasPrefix(u.Path, "/realms/syn443-test/login-actions/") {
			t.Fatal("identity form origin")
		}
		return action
	}
	login := func(path string, otp bool) {
		start := post(path)
		requireStatus(t, start, 200)
		link := object(t, start.body)["url"].(string)
		if otp {
			u, _ := url.Parse(link)
			if u.Query().Get("acr_values") != "2" || u.Query().Get("prompt") != "login" || u.Query().Get("max_age") != "0" {
				t.Fatal("fresh assurance was not requested")
			}
		}
		page := f.request(b, "GET", link, "", nil, false)
		action := formAction(page, "kc-form-login")
		page = f.form(b, action, url.Values{"username": {f.username}, "password": {f.password}, "credentialId": {""}})
		if otp {
			action = formAction(page, "kc-otp-login-form")
			page = f.form(b, action, url.Values{"otp": {""}})
			action = formAction(page, "kc-otp-login-form")
			page = f.form(b, action, url.Values{"otp": {fixtureOTP(secret)}})
		}
		if page.status != 302 && page.status != 303 {
			t.Fatal("identity flow did not finish", page.status)
		}
		callback := page.headers.Get("Location")
		u, _ := url.Parse(callback)
		if u.Scheme+"://"+u.Host != origin || u.Path != "/callback" || u.Query().Get("code") == "" {
			t.Fatal("control callback origin")
		}
		requireStatus(t, f.request(b, "GET", callback, "", nil, false), 303)
	}
	login("/login", false)
	initial := post("/session")
	requireStatus(t, initial, 200)
	if object(t, initial.body)["reauthenticationFresh"] != false {
		t.Fatal("password-only sign-in was accepted as fresh MFA")
	}
	login("/reauth", true)
	fresh := post("/session")
	requireStatus(t, fresh, 200)
	if object(t, fresh.body)["reauthenticationFresh"] != true {
		t.Fatal("actual signed ACR/AMR/auth_time not accepted")
	}
	requireStatus(t, post("/logout"), 200)
	requireStatus(t, post("/session"), 401)
}
