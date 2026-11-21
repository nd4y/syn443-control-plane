package policy

import "testing"

func TestNetworkModePolicyKeepsExplicitBoundedPermissionAndPhysicalHomeRequirement(t *testing.T) {
	for _, tc := range []struct {
		name, raw  string
		home, want bool
	}{
		{"disabled", `{"preferredMode":"AUTO","userModes":[],"maxOverrideMinutes":0}`, false, true},
		{"assigned only", `{"preferredMode":"WIFI","userModes":[],"maxOverrideMinutes":0}`, false, true},
		{"single minute", `{"preferredMode":"AUTO","userModes":["WIFI"],"maxOverrideMinutes":1}`, false, true},
		{"all modes", `{"preferredMode":"HOME_WIFI","userModes":["HOME_WIFI","WIFI","CELLULAR","CELLULAR_RESTRICTED"],"maxOverrideMinutes":1440}`, true, true},
		{"no home marker", `{"preferredMode":"HOME_WIFI","userModes":[],"maxOverrideMinutes":0}`, false, false},
		{"home override without marker", `{"preferredMode":"WIFI","userModes":["HOME_WIFI"],"maxOverrideMinutes":1}`, false, false},
		{"missing duration", `{"preferredMode":"AUTO","userModes":[]}`, false, false},
		{"null duration", `{"preferredMode":"AUTO","userModes":[],"maxOverrideMinutes":null}`, false, false},
		{"null list", `{"preferredMode":"AUTO","userModes":null,"maxOverrideMinutes":0}`, false, false},
		{"duplicate mode", `{"preferredMode":"AUTO","userModes":["WIFI","WIFI"],"maxOverrideMinutes":15}`, false, false},
		{"local unknown", `{"preferredMode":"UNKNOWN","userModes":[],"maxOverrideMinutes":0}`, false, false},
		{"unknown member", `{"preferredMode":"AUTO","userModes":[],"maxOverrideMinutes":0,"force":true}`, false, false},
		{"too long", `{"preferredMode":"WIFI","userModes":["WIFI"],"maxOverrideMinutes":1441}`, false, false},
		{"duplicate member", `{"preferredMode":"AUTO","preferredMode":"WIFI","userModes":[],"maxOverrideMinutes":0}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ValidNetworkModeJSON([]byte(tc.raw), tc.home) != tc.want {
				t.Fatal("unexpected validation result")
			}
		})
	}
}
