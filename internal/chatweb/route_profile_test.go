package chatweb

import (
	"net/http"
	"strings"
	"testing"
)

const profileFixture = `{"schemaVersion":2,"id":"home","revision":1,"deadlineMs":4000,"leaves":[{"id":"secure","check":{"method":"tls","target":"https://secure.example.invalid/"}},{"id":"a","check":{"method":"tcp","target":"a.example.invalid:443"}},{"id":"b","check":{"method":"tcp","target":"b.example.invalid:443"}}],"gates":["secure"],"stages":[{"any":[{"leaf":"a"},{"leaf":"b"}]}]}`

func TestConsoleProfileValidationUsesCanonicalGatesWithoutProbing(t *testing.T) {
	s, _, principal := webFixture(t)
	s.config.ControlConsole = true
	principal.Scope = "syn443.control"
	cookie := loginWeb(t, s)
	s.client.Transport = consoleTransportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("validating check definitions called an upstream service")
		return nil, nil
	})
	const path = "/control/route-check-profile"
	w := webCall(s, path, profileFixture, cookie)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"valid":true}` {
		t.Fatal("valid definition failed or preview disclosed its contents")
	}
	for _, bad := range []string{
		strings.Replace(profileFixture, `"gates":["secure"]`, `"gates":[]`, 1),
		strings.Replace(profileFixture, `"gates":["secure"],"stages":[`, `"gates":[],"stages":[{"leaf":"secure"},`, 1),
		strings.Replace(profileFixture, `"revision":1`, `"revision":1,"revision":1`, 1),
		strings.Replace(profileFixture, `"deadlineMs":4000`, `"deadlineMs":12001`, 1),
	} {
		if webCall(s, path, bad, cookie).Code != http.StatusBadRequest {
			t.Fatal("invalid profile passed")
		}
	}
	if webCall(s, path, strings.Repeat(" ", routeProfileLimit+1), cookie).Code != http.StatusRequestEntityTooLarge {
		t.Fatal("oversized request passed")
	}
	if webCall(s, path, profileFixture, nil).Code != http.StatusUnauthorized {
		t.Fatal("anonymous request passed")
	}
	s.sessions[cookie.Value].principal.Scope = "openid"
	if webCall(s, path, profileFixture, cookie).Code != http.StatusForbidden {
		t.Fatal("non-control account passed")
	}
	s.config.ControlConsole = false
	if webCall(s, path, profileFixture, cookie).Code != http.StatusNotFound {
		t.Fatal("standalone chat exposed profile validation")
	}
}
