package enrollment

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestExitCountryCannotBypassAddressedDeviceApprovalOrNegotiation(t *testing.T) {
	prepared, payload, now := configuredPreparation(t)
	prepared.EngineConfig = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"},"route_checks":[{"outbound":"direct","checks":[{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU"}]}]}`)
	prepared.RequiredCapabilities = []string{"route.health.v1", policy.RouteExitCountry}
	available := append(append([]string(nil), payload.RequiredCapabilities...), prepared.RequiredCapabilities...)
	old := payload
	if err := applyPreparedConfiguration(&old, prepared, available[:len(available)-1], now); !errors.Is(err, ErrDenied) {
		t.Fatal("country check offered without advertised primitive capability", err)
	}
	if err := applyPreparedConfiguration(&payload, prepared, available, now); err != nil {
		t.Fatal("approved addressed configuration could not add country check", err)
	}
	payload.KeyThumbprint = ""
	grant := Grant{Issuer: "https://identity.example.invalid/realms/test", Subject: "synthetic-user", DeviceLimit: 2, Until: now.Add(time.Hour).Unix(), Template: payload}
	if err := grant.Validate(now); !errors.Is(err, identity.ErrInvalid) {
		t.Fatal("shared template bypassed addressed country-check approval", err)
	}
}
