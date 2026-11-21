package chatweb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func fixtureBoundsPlan(t *testing.T, count int) string {
	t.Helper()
	ids := make([]string, count)
	hops := make([]map[string]any, count)
	bindings := make(map[string]map[string]string)
	for i := range ids {
		id := fmt.Sprintf("node-%02d", i)
		ids[i] = id
		hops[i] = map[string]any{"id": id, "entryModes": []string{"WIFI"}, "exitClass": "NON_RU", "features": []string{"TCP"}}
		bindings[id] = map[string]string{"sourceId": "source-a", "profileId": "source-a_" + id}
	}
	groups := make([]map[string]any, 0, 2)
	for _, id := range []string{"video", "work"} {
		groups = append(groups, map[string]any{"id": id, "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"multi"}})
	}
	encode := func(value any) string {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	metadata := encode(map[string]any{"schemaVersion": 1, "hops": hops, "edges": []any{}, "templates": []any{
		map[string]any{"id": "multi", "slots": [][]string{ids, ids, ids}},
	}, "groups": groups})
	return encode(map[string]any{"metadataB64": base64.RawURLEncoding.EncodeToString([]byte(metadata)),
		"bindingsB64": base64.RawURLEncoding.EncodeToString([]byte(encode(bindings))),
		"groups":      map[string]string{"video": "adaptive-video", "work": "adaptive-work"}})
}

func TestRouteBoundsPreviewUsesTheExactPerIntentLimitWithoutAuthorizingOrForwarding(t *testing.T) {
	s, _, p := webFixture(t)
	s.config.ControlConsole = true
	p.Scope = "syn443.control"
	cookie := loginWeb(t, s)
	s.client.Transport = consoleTransportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("preview performed an upstream request")
		return nil, nil
	})
	const path = "/control/route-bounds"
	exact := fixtureBoundsPlan(t, 16)
	response := webCall(s, path, exact, cookie)
	var result struct {
		Status  string
		Limit   int
		Intents map[string]int
		Groups  []groupBound
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Status != "ready" || result.Limit != 4096 || len(result.Intents) != 1 || result.Intents["NON_RU"] != 4096 ||
		len(result.Groups) != 2 || result.Groups[0] != (groupBound{"video", "NON_RU", 4096, 3}) || result.Groups[1] != (groupBound{"work", "NON_RU", 4096, 3}) {
		t.Fatal("incorrect deduplicated route bounds")
	}
	for _, forbidden := range []string{"source-a", "node-00", "bindingsB64", "metadataB64", "ticket"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatal("preview exposed a profile or authority")
		}
	}
	over := webCall(s, path, fixtureBoundsPlan(t, 17), cookie)
	var limited map[string]any
	if over.Code != 200 || json.Unmarshal(over.Body.Bytes(), &limited) != nil || len(limited) != 2 || limited["status"] != "over_limit" || limited["limit"] != float64(4096) {
		t.Fatal("oversize draft returned an incomplete count")
	}
	if w := webCall(s, path, `{"groups":{}}`, cookie); w.Code != 400 {
		t.Fatal("malformed draft accepted")
	}
	if w := webCall(s, path, strings.Repeat("x", routeBoundsLimit+1), cookie); w.Code != 413 {
		t.Fatal("oversize input accepted")
	}
	if w := webCall(s, path, exact, nil); w.Code != 401 {
		t.Fatal("missing session accepted")
	}
}

func TestRouteBoundsPreviewRequiresTheControlConsoleAndScope(t *testing.T) {
	s, _, p := webFixture(t)
	chat := loginWeb(t, s)
	const path = "/control/route-bounds"
	if w := webCall(s, path, fixtureBoundsPlan(t, 1), chat); w.Code != 404 {
		t.Fatal("standalone chat exposed the route preview")
	}
	s.config.ControlConsole = true
	// The console login itself validates its scope, so start with a valid session
	// and exercise a subsequently restricted principal.
	p.Scope = "syn443.control"
	console := loginWeb(t, s)
	s.sessions[console.Value].principal.Scope = "openid"
	if w := webCall(s, path, fixtureBoundsPlan(t, 1), console); w.Code != 403 {
		t.Fatal("incorrect audience/scope gate")
	}
}
