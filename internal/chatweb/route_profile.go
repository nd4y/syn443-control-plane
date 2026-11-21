package chatweb

import (
	"encoding/json"
	"net/http"

	"github.com/nd4y/syn443-control-plane/internal/routecheck"
)

const routeProfileLimit = routecheck.MaxBytes

// The profile decoder checks closed fields, references, budgets and mandatory
// gates. Compatibility with the device and selected path is checked at issuance.
func validateRouteProfile(w http.ResponseWriter, raw []byte) {
	var profile routecheck.Profile
	if json.Unmarshal(raw, &profile) != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	reply(w, map[string]bool{"valid": true})
}
