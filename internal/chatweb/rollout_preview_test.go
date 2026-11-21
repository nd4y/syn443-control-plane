package chatweb

import (
	"net/http"
	"strings"
	"testing"
)

func TestDraftRolloutPreviewRequiresControlScopeAndNeverReadsADevice(t *testing.T) {
	s, _, p := webFixture(t)
	const path = "/control/rollout-preview"
	const request = `{"device":"synthetic-a","decision":{"id":"fixture-canary","basisPoints":10000}}`
	chat := loginWeb(t, s)
	if got := webCall(s, path, request, chat); got.Code != 404 {
		t.Fatal("preview available in user chat")
	}
	s.config.ControlConsole = true
	p.Scope = "syn443.control"
	console := loginWeb(t, s)
	s.client.Transport = consoleTransportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected upstream request"); return nil, nil })
	got := webCall(s, path, request, console)
	if got.Code != 200 || strings.TrimSpace(got.Body.String()) != `{"decision":"treatment"}` {
		t.Fatalf("unexpected preview: %d %s", got.Code, got.Body.String())
	}
	for _, invalid := range []string{
		`{"device":"synthetic-a"}`,
		`{"device":"synthetic-a","decision":{"id":"a","basisPoints":null}}`,
		`{"device":"synthetic-a","decision":{"id":"a","basisPoints":1},"decision":{"id":"b","basisPoints":0}}`,
		`{"device":"synthetic-a","decision":{"id":"a","basisPoints":1,"script":"abc"}}`,
		`{"device":"bad/id","probeCooldown":{"id":"a","basisPoints":0}}`,
	} {
		if response := webCall(s, path, invalid, console); response.Code != 400 {
			t.Fatalf("unexpected invalid response: %d", response.Code)
		}
	}
	if got := webCall(s, path, strings.Repeat("a", 1025), console); got.Code != 413 {
		t.Fatal("unbounded request")
	}
	if got := webCall(s, path, request, nil); got.Code != 401 {
		t.Fatal("missing session accepted")
	}
	s.sessions[console.Value].principal.Scope = "openid"
	if got := webCall(s, path, request, console); got.Code != 403 {
		t.Fatal("missing scope accepted")
	}
}
