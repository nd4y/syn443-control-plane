package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeviceDiscoveryContractHasOnlyAnOptionalBoundedCursor(t *testing.T) {
	schema, e := loadControlSchema()
	if e != nil {
		t.Fatal(e)
	}
	for _, body := range []struct {
		payload string
		valid   bool
	}{
		{`{}`, true}, {`{"after":""}`, true}, {`{"after":"device-a"}`, true},
		{`{"after":null}`, false}, {`{"after":42}`, false}, {`{"after":"../device"}`, false},
		{`{"owner":"synthetic-user"}`, false}, {`{"limit":1000}`, false},
		{`{"after":"` + strings.Repeat("a", 65) + `"}`, false},
	} {
		var v any
		raw := `{"version":1,"action":"configuration.devices.list","requestId":"synthetic-request-identifier","payload":` + body.payload + `}`
		if e = json.Unmarshal([]byte(raw), &v); e != nil {
			if body.valid {
				t.Fatal(e)
			}
			continue
		}
		if (schema.Validate(v) == nil) != body.valid {
			t.Fatal("device discovery schema boundary", body.valid)
		}
	}
}
