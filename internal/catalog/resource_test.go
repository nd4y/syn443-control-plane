package catalog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/resources"
)

func TestResourceModelAndClosedCredentials(t *testing.T) {
	base := Resource{ID: "panel-a", Name: "Synthetic", ProviderType: resources.Remnawave, APIVersion: "3.4", Enabled: true}
	if base.Validate() != nil {
		t.Fatal("valid resource")
	}
	for _, change := range []func(*Resource){func(r *Resource) { r.ID = "../bad" }, func(r *Resource) { r.Name = "" }, func(r *Resource) { r.APIVersion = "latest" }, func(r *Resource) { r.Revision = -1 }, func(r *Resource) { r.ProviderType = "unknown" }, func(r *Resource) { r.ProviderType = "panel.x-ui" }} {
		r := base
		change(&r)
		if r.Validate() == nil {
			t.Fatal("invalid resource accepted")
		}
	}
	for _, kind := range []string{"panel.x-ui", "panel.3x-ui", "overlay.tailscale", "overlay.zerotier"} {
		r := base
		r.ProviderType = kind
		r.Enabled = false
		if r.Validate() != nil {
			t.Fatal("planned metadata denied")
		}
	}
	c := ResourceCredential{Endpoint: "https://panel.example.invalid", Token: "synthetic-token-not-a-real-secret"}
	raw, _ := json.Marshal(c)
	if _, e := readResourceCredential(raw); e != nil {
		t.Fatal(e)
	}
	client, e := c.Client(base, false)
	if e != nil {
		t.Fatal(e)
	}
	client.Close()
	for _, raw := range []string{`{}`, `{"endpoint":"http://panel.example.invalid","token":"synthetic"}`, `{"endpoint":"https://user@panel.example.invalid","token":"synthetic"}`, `{"endpoint":"https://panel.example.invalid?x=y","token":"synthetic"}`, `{"endpoint":"https://panel.example.invalid/path","token":"synthetic"}`, `{"endpoint":"https://panel.example.invalid","endpoint":"https://other.example.invalid"}`, `{"endpoint":"https://panel.example.invalid","fixtureLoopback":true}`, strings.Repeat(" ", 65537)} {
		if _, e := readResourceCredential([]byte(raw)); e == nil {
			t.Fatal("untrusted credential shape accepted")
		}
	}
	bad := c
	bad.Token = "short"
	if _, e = bad.Client(base, false); e == nil {
		t.Fatal("short credential accepted")
	}
	bad = c
	bad.RootCA = "not a CA"
	if _, e = bad.Client(base, false); e == nil {
		t.Fatal("invalid TLS roots accepted")
	}
	for _, value := range []any{base, c} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, "example.invalid") || strings.Contains(text, "synthetic-token") {
				t.Fatal("sensitive formatter")
			}
		}
	}
}

func TestWorkerFailureClassification(t *testing.T) {
	for _, test := range []struct {
		code, want string
		permanent  bool
	}{{"assignment_revoked", "resource_denied", true}, {"assignment_expired", "subscription_expired", true}, {"access_denied", "subscription_access_denied", true}, {"tls_validation_failed", "subscription_tls_failed", true}, {"empty_snapshot", "subscription_empty_response", true}, {"identity_mismatch", "subscription_invalid", true}, {"address_not_allowed", "subscription_access_denied", true}, {"rate_limited", "resource_unavailable", false}, {"provider_unavailable", "resource_unavailable", false}} {
		reason, permanent := sourceFailure(resources.Failure(test.code, !test.permanent))
		if reason != test.want || permanent != test.permanent {
			t.Fatal(test.code, reason, permanent)
		}
	}
}
