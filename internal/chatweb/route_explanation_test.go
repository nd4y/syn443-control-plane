package chatweb

import (
	"net/http"
	"strings"
	"testing"
)

func TestManualRouteExplanationDoesNotForwardOrRetainTheDestination(t *testing.T) {
	s, _, p := webFixture(t)
	const path = "/control/route-explanation"
	const raw = `{"rules":[{"id":"deny","match":{"domains":["manual.example.invalid"]},"action":"reject","matchAll":false}],"dnsRules":[],"dnsFinal":"system","routeFinal":"direct","query":{"domain":"manual.example.invalid","dnsType":"A"}}`
	chat := loginWeb(t, s)
	if w := webCall(s, path, raw, chat); w.Code != 404 {
		t.Fatal("standalone chat exposed the preview", w.Code)
	}
	s.config.ControlConsole = true
	p.Scope = "syn443.control"
	cookie := loginWeb(t, s)
	s.client.Transport = consoleTransportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("manual preview forwarded the destination")
		return nil, nil
	})
	response := webCall(s, path, raw, cookie)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"rule":"deny"`) || strings.Contains(response.Body.String(), "manual.example.invalid") || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("expected a noncacheable, destination-free result")
	}
	for _, bad := range []string{strings.Replace(raw, "manual.example.invalid", "bad/host", 1), strings.Replace(raw, `"query":`, `"providerToken":"unused","query":`, 1)} {
		if w := webCall(s, path, bad, cookie); w.Code != 400 {
			t.Fatal("invalid shape accepted")
		}
	}
	if w := webCall(s, path, strings.Repeat("x", routeExplanationLimit+1), cookie); w.Code != 413 {
		t.Fatal("request limit missing")
	}
	if w := webCall(s, path, raw, nil); w.Code != 401 {
		t.Fatal("session missing")
	}
	s.sessions[cookie.Value].principal.Scope = "openid"
	if w := webCall(s, path, raw, cookie); w.Code != 403 {
		t.Fatal("scope missing")
	}
}
