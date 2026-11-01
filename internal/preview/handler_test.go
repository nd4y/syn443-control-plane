package preview

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/decision"
)

func TestHTTPConformance(t *testing.T) {
	raw, _ := contracts.Files.ReadFile("v1/decision-vectors.json")
	var fixtures struct {
		Cases []struct {
			Name     string          `json:"name"`
			Input    json.RawMessage `json:"input"`
			Expected decision.Result `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler()
	for _, c := range fixtures.Cases {
		t.Run(c.Name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/v1/decision-preview", bytes.NewReader(c.Input))
			r.Header.Set("Content-Type", "application/json; charset=utf-8")
			handler.ServeHTTP(w, r)
			expected, _ := json.Marshal(c.Expected)
			if w.Code != 200 || strings.TrimSpace(w.Body.String()) != string(expected) {
				t.Fatalf("status %d %s, wanted %s", w.Code, w.Body.String(), expected)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}
func TestHTTPBoundaries(t *testing.T) {
	h := NewHandler()
	cases := []struct {
		method, path, body, content string
		status                      int
	}{
		{"GET", "/healthz", "", "", 200},
		{"POST", "/healthz", "", "", 405},
		{"GET", "/v1/decision-preview", "", "", 405},
		{"POST", "/v1/decision-preview", "{}", "text/plain", 415},
		{"POST", "/v1/decision-preview", "{", "application/json", 400},
		{"POST", "/v1/decision-preview", strings.Repeat("x", decision.MaxWireBytes+1), "application/json", 413},
		{"POST", "/v1/decision-preview", `{"secret":"must-not-echo"}`, "application/json", 400},
		{"GET", "/v1/devices", "", "", 404},
	}
	for i, c := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		if c.content != "" {
			r.Header.Set("Content-Type", c.content)
		}
		h.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Fatalf("case%d status%d body%s", i, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "must-not-echo") {
			t.Fatal("request echoed")
		}
	}
}
