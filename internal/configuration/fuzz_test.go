package configuration

import (
	"context"
	"encoding/json"
	"testing"
)

func FuzzConfigurationLayers(f *testing.F) {
	encoded, _ := json.Marshal([]Layer{layer("base", "template", setting("/mode", `"direct"`))})
	f.Add(encoded)
	f.Add([]byte(`[{"id":"base","kind":"template","revision":1,"changes":[],"permissions":[]}]`))
	f.Add([]byte(`[{"id":"a","id":"b"}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 50000 {
			return
		}
		layers, e := DecodeLayers(raw)
		if e != nil {
			return
		}
		result, e := Merge(context.Background(), layers, supported)
		if e == nil {
			if !json.Valid(result.Document) || len(result.Document) > 262144 {
				t.Fatal("invalid effective output")
			}
		}
	})
}
