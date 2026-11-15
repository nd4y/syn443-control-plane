package enrollment

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRuntimeObservationClosedShapeAndTruthfulEngineBounds(t *testing.T) {
	base := RuntimeObservation{Version: 1, Sequence: 1, Build: 74, Phase: "online", PolicyRevision: 1, EngineKnown: true, EngineActive: true, Network: "wifi", SampledAtMs: 1800000000000}
	encode := func(r RuntimeObservation) []byte { raw, _ := json.Marshal(r); return raw }
	if got, e := DecodeRuntimeObservation(encode(base)); e != nil || got != base {
		t.Fatal("valid observation", e)
	}
	for _, phase := range []string{"starting", "recovering", "no_network", "blocked", "unknown", "off"} {
		r := base
		r.Phase, r.EngineActive = phase, false
		if _, e := DecodeRuntimeObservation(encode(r)); e != nil {
			t.Fatal("valid phase", phase)
		}
	}
	for _, network := range []string{"none", "wifi", "cellular", "unknown"} {
		r := base
		r.Network, r.Sequence, r.PolicyRevision, r.SampledAtMs, r.Build = network, 9007199254740991, 9007199254740991, 9007199254740991, 2100000000
		if _, e := DecodeRuntimeObservation(encode(r)); e != nil {
			t.Fatal("exact integer upper boundaries", e)
		}
	}
	for _, edit := range []func(*RuntimeObservation){
		func(r *RuntimeObservation) { r.Version = 2 },
		func(r *RuntimeObservation) { r.Sequence = 0 },
		func(r *RuntimeObservation) { r.Sequence = 9007199254740992 },
		func(r *RuntimeObservation) { r.Build = 0 },
		func(r *RuntimeObservation) { r.Build = 2100000001 },
		func(r *RuntimeObservation) { r.PolicyRevision = -1 },
		func(r *RuntimeObservation) { r.PolicyRevision = 9007199254740992 },
		func(r *RuntimeObservation) { r.SampledAtMs = 0 },
		func(r *RuntimeObservation) { r.SampledAtMs = 9007199254740992 },
		func(r *RuntimeObservation) { r.EngineKnown = false },
		func(r *RuntimeObservation) { r.EngineActive = false },
		func(r *RuntimeObservation) { r.PolicyRevision = 0 },
		func(r *RuntimeObservation) { r.Phase = "off" },
		func(r *RuntimeObservation) { r.Phase = "Online" },
		func(r *RuntimeObservation) { r.Network = "synthetic-private-ssid" },
	} {
		r := base
		edit(&r)
		if _, e := DecodeRuntimeObservation(encode(r)); e == nil {
			t.Fatal("invalid observation accepted")
		}
	}
	raw := string(encode(base))
	for _, bad := range []string{
		"", "null", "[]", raw + "{}", strings.Repeat(" ", 1025),
		strings.Replace(raw, `"engineActive":true`, `"engineActive":null`, 1),
		strings.Replace(raw, `"engineKnown":true,`, "", 1),
		strings.Replace(raw, `"sequence":1`, `"sequence":1,"sequence":1`, 1),
		strings.Replace(raw, `"sequence":1`, `"sequence":1.0`, 1),
		strings.Replace(raw, `"sequence":1`, `"sequence":"1"`, 1),
		strings.Replace(raw, `"phase":"online"`, `"phase":"online","device":"foreign-device"`, 1),
		strings.Replace(raw, `"network":"wifi"`, `"network":"wifi","url":"https://private.example.invalid"`, 1),
	} {
		if _, e := DecodeRuntimeObservation([]byte(bad)); e == nil {
			t.Fatal("untrusted wire shape accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", base, base), "1800000000000") {
		t.Fatal("runtime payload was formatted")
	}
}

func FuzzRuntimeObservation(f *testing.F) {
	f.Add([]byte(`{"version":1,"sequence":1,"build":74,"phase":"off","policyRevision":0,"engineKnown":true,"engineActive":false,"network":"none","sampledAtMs":1800000000000}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, e := DecodeRuntimeObservation(raw)
		if e == nil {
			canonical, err := json.Marshal(value)
			if err != nil {
				t.Fatal("canonical encoding")
			}
			if again, err := DecodeRuntimeObservation(canonical); err != nil || again != value {
				t.Fatal("accepted observation did not round trip")
			}
		}
	})
}
