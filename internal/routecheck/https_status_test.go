package routecheck

import (
	"encoding/json"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
)

func TestHTTPSStatusContractRequiresExactVerbAndStatus(t *testing.T) {
	raw, err := contracts.Files.ReadFile("v1/https-status-check-vectors.json")
	var vectors struct{ Valid, Invalid []json.RawMessage }
	if err != nil || json.Unmarshal(raw, &vectors) != nil || len(vectors.Valid) != 3 || len(vectors.Invalid) != 12 {
		t.Fatal("missing HTTPS predicate vectors")
	}
	for _, example := range vectors.Valid {
		var check Check
		if json.Unmarshal(example, &check) != nil || !ValidTarget(check) {
			t.Fatal("valid predicate rejected")
		}
		p := sampleProfile()
		p.Leaves[0].Check = check
		if p.Validate() != nil {
			t.Fatal("HTTPS status cannot participate in an alternative")
		}
		wire, err := json.Marshal(check)
		var again Check
		if err != nil || json.Unmarshal(wire, &again) != nil || check != again {
			t.Fatal("status predicate did not round trip")
		}
	}
	for _, example := range vectors.Invalid {
		var check Check
		if json.Unmarshal(example, &check) == nil {
			t.Fatal("invalid predicate admitted")
		}
	}
}
