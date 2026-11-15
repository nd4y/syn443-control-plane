package chatweb

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestConsoleChatAndControlUseTheirPinnedOriginsAndIndependentNonces(t *testing.T) {
	s, _, principal := webFixture(t)
	s.config.ControlConsole = true
	principal.Scope = "syn443.control"
	cookie := loginWeb(t, s)
	s.config.APIOrigin = "https://control.example.invalid"
	s.config.ChatAPIOrigin = "https://chat.example.invalid"
	challenges := map[string]int{}
	calls := map[string]int{}
	s.client.Transport = consoleTransportFunc(func(r *http.Request) (*http.Response, error) {
		origin := r.URL.Scheme + "://" + r.URL.Host
		expected := "control-nonce"
		if origin == s.config.ChatAPIOrigin {
			expected = "chat-nonce"
			if r.URL.Path != "/v1/admin/chat/inbox" {
				t.Fatal("chat path escaped its allowlist")
			}
		} else if origin != s.config.APIOrigin || r.URL.Path != "/v1/control/action" {
			t.Fatal("request escaped pinned origins")
		}
		body, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		proof, e := identity.RequestProof(r.Header.Get("DPoP"), identity.ProofContext{Method: "POST", URI: r.URL.String(), Token: "synthetic-access", BodyHash: identity.Hash(body), Now: s.clock()})
		if e != nil || proof.Thumbprint != principal.Thumbprint {
			t.Fatal("wrong target, access token or key proof", e)
		}
		calls[origin]++
		status := 200
		headers := http.Header{"Content-Type": []string{"application/json"}}
		if proof.Claims.Nonce != expected {
			if proof.Claims.Nonce != "" {
				t.Fatal("nonce borrowed from the other API")
			}
			challenges[origin]++
			status = 401
			headers.Set("DPoP-Nonce", expected)
		}
		return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	for i := 0; i < 3; i++ {
		for _, request := range []struct{ path, body string }{{"/chat/inbox", `{}`}, {"/control/action", `{"version":1,"action":"source.list","requestId":"synthetic-request-123","payload":{}}`}} {
			w := webCall(s, request.path, request.body, cookie)
			if w.Code != 200 {
				t.Fatalf("routed request rejected: %s status%d", request.path, w.Code)
			}
		}
	}
	for _, origin := range []string{s.config.APIOrigin, s.config.ChatAPIOrigin} {
		if challenges[origin] != 1 || calls[origin] != 4 {
			t.Fatal("repeated challenge or missing actual request")
		}
	}
}

func TestConsoleRejectsUnsafeChatOriginsBeforeIssuerDiscovery(t *testing.T) {
	s, _, _ := webFixture(t)
	for _, origin := range []string{"http://chat.example.invalid", "https://user@chat.example.invalid", "https://chat.example.invalid/v1", "https://chat.example.invalid?x=1", "https://chat.example.invalid#x", "https://chat.example.invalid/", "http://127.0.0.1:17845"} {
		c := s.config
		c.FixtureHTTP = false
		c.ChatAPIOrigin = origin
		// Keep every other field valid so this specifically checks the override.
		c.APIOrigin = "https://control.example.invalid"
		c.Issuer = "https://id.example.invalid/realms/test"
		tr := consoleTransportFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe origin reached discovery")
			return nil, invalid
		})
		if got, e := New(context.Background(), c, tr); e == nil || got != nil {
			t.Fatal("unsafe chat origin accepted")
		}
	}
}
