package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

const publicationIssuer = "https://identity.example.invalid/realms/fixture"

func publicationGrant(subject string, until time.Time) enrollment.Grant {
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	sum := sha256.Sum256(engine)
	return enrollment.Grant{
		Issuer: publicationIssuer, Subject: subject, DeviceLimit: 2, Until: until.Unix(),
		Template: policy.Payload{
			SchemaVersion: 1, Operation: "configure", Audience: "syn443-device",
			RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1"},
			AlgorithmRevision:    policy.BaselineAlgorithm,
			EngineConfigB64:      base64.RawURLEncoding.EncodeToString(engine),
			ContentHash:          hex.EncodeToString(sum[:]),
			Activation: policy.Gate{TimeoutSeconds: 30, Checks: []policy.Check{
				{ID: "internet", Type: "https_204", Target: "https://health.example.org/generate_204", Required: true},
			}},
		},
	}
}

func TestPublisherGrantsSkipExpiredWithoutChangingActiveAuthority(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	expired := publicationGrant("expired", now.Add(-time.Hour))
	boundary := publicationGrant("boundary", now)
	current := publicationGrant("current", now.Add(time.Hour))
	active, err := activePublicationGrants([]enrollment.Grant{expired, boundary, current}, publicationIssuer, now)
	if err != nil || len(active) != 1 {
		t.Fatalf("expected only the active entry: count=%d, error=%v", len(active), err)
	}
	if got := active[enrollment.Owner(current.Issuer, current.Subject)]; got.Hash() != current.Hash() {
		t.Fatal("active owner or grant fingerprint changed")
	}
	for _, grant := range []enrollment.Grant{expired, boundary} {
		if _, exists := active[enrollment.Owner(grant.Issuer, grant.Subject)]; exists || grant.Validate(now) == nil {
			t.Fatal("expired grant retained publication authority")
		}
	}
	active, err = activePublicationGrants([]enrollment.Grant{expired, boundary}, publicationIssuer, now)
	if err != nil || len(active) != 0 {
		t.Fatalf("the worker must accept an empty active grant set: count=%d, error=%v", len(active), err)
	}
}

func TestPublisherGrantsKeepIdentityAndActiveGrantValidation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	current := publicationGrant("current", now.Add(time.Hour))
	expired := publicationGrant("current", now)
	wrongIssuer := expired
	wrongIssuer.Issuer = "https://other.example.invalid/realms/fixture"
	emptySubject := expired
	emptySubject.Subject = ""
	invalidExpiry := expired
	invalidExpiry.Until = 0
	invalidTemplate := current
	invalidTemplate.Template.Operation = "release"
	tooLong := publicationGrant("future", now.Add(8*24*time.Hour))
	for name, grants := range map[string][]enrollment.Grant{
		"duplicate with expired entry":   {expired, current},
		"wrong issuer on expired entry":  {wrongIssuer},
		"missing owner on expired entry": {emptySubject},
		"invalid deadline":               {invalidExpiry},
		"invalid active template":        {invalidTemplate},
		"active deadline beyond limit":   {tooLong},
	} {
		t.Run(name, func(t *testing.T) {
			active, err := activePublicationGrants(grants, publicationIssuer, now)
			if active != nil || !errors.Is(err, identity.ErrInvalid) {
				t.Fatal("an invalid grant set acquired publication authority")
			}
		})
	}
}
