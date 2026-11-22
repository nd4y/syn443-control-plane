package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestFailoverProgramHasIndependentSignatureExactScopeAndConservativeBounds(t *testing.T) {
	_, p, now := sample(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]*ecdsa.PublicKey{"root": &key.PublicKey}
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"},"route_failover":{}}`)
	sum := sha256.Sum256(engine)
	p.EngineConfigB64 = base64.RawURLEncoding.EncodeToString(engine)
	p.ContentHash = hex.EncodeToString(sum[:])
	p.SchemaVersion = 2
	p.KeyThumbprint = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	p.AlgorithmRevision = ConfirmedFailoverAlgorithm
	p.RequiredCapabilities = append(p.RequiredCapabilities, "policy.keybound.v2", "route.health.v1", "route.failover.v1", RouteDecision, DecisionBundleCapability)
	program := FailoverProgram{Revision: 7, Confirmations: 4, MinSwitchIntervalMs: 120000}
	signOuter := func(candidate Payload) (string, error) {
		raw, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		return Sign(raw, "root", key, candidate.TargetDevice, candidate.Revision, now)
	}
	issued, err := IssueFailoverProgram(p, program, "root", key)
	if err != nil {
		t.Fatal(err)
	}
	p.DecisionBundle = issued
	outer, err := signOuter(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBound(outer, roots, p.TargetDevice, p.KeyThumbprint, now); err != nil {
		t.Fatal(err)
	}
	docRaw, err := verifiedDocument(issued, roots, decisionDocumentType, maxDecisionBundle)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*decisionDocument){
		"device":          func(d *decisionDocument) { d.TargetDevice = "another-device" },
		"key":             func(d *decisionDocument) { d.KeyThumbprint = strings.Repeat("a", 43) },
		"config":          func(d *decisionDocument) { d.ConfigHash = strings.Repeat("b", 64) },
		"lease":           func(d *decisionDocument) { d.ExpiresMs++ },
		"evaluator":       func(d *decisionDocument) { d.EvaluatorMax++ },
		"digest":          func(d *decisionDocument) { d.PolicyHash = strings.Repeat("0", 64) },
		"caps":            func(d *decisionDocument) { d.RequiredCapabilities = d.RequiredCapabilities[:1] },
		"unsigned_limits": func(d *decisionDocument) { d.Program.Confirmations++ },
	} {
		t.Run(name, func(t *testing.T) {
			var d decisionDocument
			if err := json.Unmarshal(docRaw, &d); err != nil {
				t.Fatal(err)
			}
			mutate(&d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := Canonical(raw)
			if err != nil {
				t.Fatal(err)
			}
			altered, err := signDocument(wire, "root", decisionDocumentType, key)
			if err != nil {
				t.Fatal(err)
			}
			candidate := p
			candidate.DecisionBundle = altered
			if _, err := signOuter(candidate); err == nil {
				t.Fatal("publisher endorsed mismatched program")
			}
			raw, err = json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			wire, err = Canonical(raw)
			if err != nil {
				t.Fatal(err)
			}
			bypass, err := signDocument(wire, "root", "syn443-policy+jws", key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyBound(bypass, roots, p.TargetDevice, p.KeyThumbprint, now); err == nil {
				t.Fatal("reader accepted mismatched program")
			}
		})
	}
	for _, bad := range []FailoverProgram{{Revision: 0, Confirmations: 4, MinSwitchIntervalMs: 120000}, {Revision: 7, Confirmations: 2, MinSwitchIntervalMs: 120000}, {Revision: 7, Confirmations: 4, MinSwitchIntervalMs: 59999}, {Revision: 7, Confirmations: 4, MinSwitchIntervalMs: 300001}} {
		if _, err := IssueFailoverProgram(p, bad, "root", key); err == nil {
			t.Fatal("invalid thresholds issued")
		}
	}
	foreign, err := IssueFailoverProgram(p, program, "root", other)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []string{"", outer, foreign} {
		invalid := p
		invalid.DecisionBundle = document
		if _, err := signOuter(invalid); err == nil {
			t.Fatal("invalid signature domain")
		}
	}
}
