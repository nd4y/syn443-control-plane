package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const DecisionBundleCapability = "decision.bundle.v1"
const decisionDocumentType = "syn443-decision+jws"
const maxDecisionBundle = 8192

// The first supported program adjusts only the existing confirmed failover primitive.
// It cannot authorize a path, start a probe, or relax the evaluator's local limits.
type FailoverProgram struct {
	Revision            int64 `json:"revision"`
	Confirmations       int   `json:"confirmations"`
	MinSwitchIntervalMs int   `json:"minSwitchIntervalMs"`
}

func (p FailoverProgram) Valid() bool {
	return p.Revision >= 1 && p.Revision <= 9007199254740991 &&
		p.Confirmations >= 3 && p.Confirmations <= 6 &&
		p.MinSwitchIntervalMs >= 60000 && p.MinSwitchIntervalMs <= 300000
}

type decisionDocument struct {
	SchemaVersion        int             `json:"schemaVersion"`
	AlgorithmID          string          `json:"algorithmId"`
	EvaluatorMin         int             `json:"evaluatorMin"`
	EvaluatorMax         int             `json:"evaluatorMax"`
	RequiredCapabilities []string        `json:"requiredCapabilities"`
	TargetDevice         string          `json:"targetDevice"`
	KeyThumbprint        string          `json:"keyThumbprint"`
	ConfigHash           string          `json:"configHash"`
	NotBeforeMs          int64           `json:"notBeforeMs"`
	ExpiresMs            int64           `json:"expiresMs"`
	PolicyHash           string          `json:"policyHash"`
	Program              FailoverProgram `json:"program"`
}

func canonicalProgramHash(p FailoverProgram) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	canonical, err := Canonical(raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// IssueFailoverProgram is called by the same approved publisher that owns the device policy.
func IssueFailoverProgram(p Payload, program FailoverProgram, kid string, key *ecdsa.PrivateKey) (string, error) {
	if !program.Valid() || p.SchemaVersion != 2 || p.Operation != "configure" || p.AlgorithmRevision != ConfirmedFailoverAlgorithm ||
		!identifier.MatchString(kid) || key == nil || key.Curve != elliptic.P256() {
		return "", errors.New("invalid decision program")
	}
	digest, err := canonicalProgramHash(program)
	if err != nil {
		return "", err
	}
	doc := decisionDocument{SchemaVersion: 1, AlgorithmID: ConfirmedFailoverAlgorithm, EvaluatorMin: 1, EvaluatorMax: 1,
		RequiredCapabilities: []string{DecisionBundleCapability, RouteDecision}, TargetDevice: p.TargetDevice, KeyThumbprint: p.KeyThumbprint,
		ConfigHash: p.ContentHash, NotBeforeMs: p.NotBeforeMs, ExpiresMs: p.OfflineUntilMs, PolicyHash: digest, Program: program}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	canonical, err := Canonical(encoded)
	if err != nil {
		return "", err
	}
	return signDocument(canonical, kid, decisionDocumentType, key)
}

func verifyDecisionBundle(p Payload, keys map[string]*ecdsa.PublicKey, now time.Time) error {
	if p.DecisionBundle == "" {
		return nil
	}
	raw, err := verifiedDocument(p.DecisionBundle, keys, decisionDocumentType, maxDecisionBundle)
	if err != nil {
		return err
	}
	var doc decisionDocument
	if identity.DecodeConfiguration(raw, &doc) != nil || doc.SchemaVersion != 1 || doc.AlgorithmID != ConfirmedFailoverAlgorithm ||
		doc.AlgorithmID != p.AlgorithmRevision || doc.EvaluatorMin != 1 || doc.EvaluatorMax != 1 ||
		!slices.Equal(doc.RequiredCapabilities, []string{DecisionBundleCapability, RouteDecision}) ||
		doc.TargetDevice != p.TargetDevice || doc.KeyThumbprint != p.KeyThumbprint || doc.ConfigHash != p.ContentHash ||
		doc.NotBeforeMs != p.NotBeforeMs || doc.ExpiresMs != p.OfflineUntilMs || now.UnixMilli() < doc.NotBeforeMs ||
		now.UnixMilli() >= doc.ExpiresMs || !doc.Program.Valid() {
		return errors.New("decision program outside policy scope")
	}
	normalized, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	exact, err := Canonical(normalized)
	if err != nil || !bytes.Equal(exact, raw) {
		return errors.New("invalid decision document fields")
	}
	digest, err := canonicalProgramHash(doc.Program)
	if err != nil || doc.PolicyHash != digest {
		return errors.New("decision program digest mismatch")
	}
	return nil
}
