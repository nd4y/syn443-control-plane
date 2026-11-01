// Package preview exposes only a bounded, side-effect-free development evaluator.
package preview

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/nd4y/syn443-control-plane/internal/decision"
)

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"status": "ok", "productionReady": false, "contractVersion": "0.1.0"})
	})
	mux.HandleFunc("POST /v1/decision-preview", func(w http.ResponseWriter, r *http.Request) {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			write(w, 415, map[string]string{"code": "unsupported_media_type"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, decision.MaxWireBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				write(w, 413, map[string]string{"code": "request_too_large"})
			} else {
				write(w, 400, map[string]string{"code": "invalid_request"})
			}
			return
		}
		input, err := decision.DecodeRequest(body)
		if err != nil {
			write(w, 400, map[string]string{"code": "invalid_request"})
			return
		}
		result, err := decision.Select(input)
		if err != nil {
			write(w, 400, map[string]string{"code": "invalid_request"})
			return
		}
		write(w, 200, result)
	})
	return mux
}
func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
