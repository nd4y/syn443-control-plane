package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/deviceprovisioning"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

const operationsLimit = 65536
const operationsNowMS int64 = 1800000000000
const operationsOrigin = "https://control.example.invalid"
const operationsKeyID = "synthetic-operation-root"

// These wrappers reproduce unexported HTTP input wrappers, not their authority.
// Tests bind their fields/tags to actual server source and validate every body
// using the unchanged public OpenAPI. Nested values are actual server DTOs.
type operationSavePayload struct {
	Draft deviceprovisioning.ConfigurationDraft `json:"draft"`
}
type operationPreviewPayload struct {
	Proposal deviceprovisioning.LayerProposal `json:"proposal"`
}
type operationPublishPayload struct {
	PreviewID string `json:"previewId"`
	Ticket    string `json:"ticket"`
}
type operationReconcileWire struct {
	Version        int    `json:"version"`
	RequestID      string `json:"requestId"`
	Intent         string `json:"intent"`
	OriginalBody64 string `json:"originalBody64"`
}

type operationOutcomeVector struct {
	Name string `json:"name"`
	Wire string `json:"wire"`
}
type operationOriginalVector struct {
	Name           string                   `json:"name"`
	OriginalBody64 string                   `json:"originalBody64"`
	BodyHash       string                   `json:"bodyHash"`
	JobID          string                   `json:"jobId"`
	LookupWire     string                   `json:"lookupWire"`
	SealWire       string                   `json:"sealWire"`
	Outcomes       []operationOutcomeVector `json:"outcomes"`
}
type operationsDocument struct {
	SchemaVersion      int                       `json:"schemaVersion"`
	SyntheticOnly      bool                      `json:"syntheticOnly"`
	NowMS              int64                     `json:"nowMs"`
	Actor              string                    `json:"actor"`
	APIOrigin          string                    `json:"apiOrigin"`
	ProposalWire       string                    `json:"proposalWire"`
	PreviewKeyID       string                    `json:"previewKeyId"`
	PreviewRootSPKIB64 string                    `json:"previewRootSpkiB64"`
	Originals          []operationOriginalVector `json:"originals"`
}

func operationRequest(version int, name string) string {
	return identity.Hash([]byte("synthetic-operation/v" + strconv.Itoa(version) + "/" + name))
}
func operationJob(actor, request string) string {
	return identity.Hash([]byte(actor + "\x00" + request))
}

func operationProposal() deviceprovisioning.LayerProposal {
	parent := configuration.Layer{ID: "synthetic-template", Kind: "template", Revision: 1, Changes: []configuration.Change{
		setting("/schemaVersion", `1`),
		setting("/graph", `{"profiles":{},"chains":{},"balancers":{},"final":"direct"}`),
		setting("/network", `{"schemaVersion":1,"requiredNetworks":["tcp"],"dnsFinal":"system","dnsStrategy":"\u0069pv4_only"}`),
		setting("/activation", `{"checks":[{"id":"fixture","type":"https_204","target":"https://health.example.invalid/generate_204","required":true}],"timeoutSeconds":30}`),
	}, Permissions: []configuration.Permission{}}
	return deviceprovisioning.LayerProposal{DraftID: "synthetic-operation-draft", DraftRevision: 1, TargetKind: "device", TargetID: "synthetic-device", Mode: "wifi", ApprovalUntilMs: operationsNowMS + 86400000,
		Bundles: []deviceprovisioning.LayerBundle{{Device: "synthetic-device", BaseRevision: 7, BaseHash: globalLayerHash([]byte("synthetic-base-head")), Layers: []configuration.Layer{parent, {ID: "synthetic-device", Kind: "device", Revision: 1, Changes: []configuration.Change{}, Permissions: []configuration.Permission{}}}}}}
}

func operationPreview(actor string, version int, proposal deviceprovisioning.LayerProposal, proposalRaw []byte) (configuration.Preview, error) {
	capabilities, e := configuration.PreviewCapabilitiesHash([]string{"fixture.synthetic"})
	if e != nil {
		return configuration.Preview{}, errFixture
	}
	return configuration.Preview{SchemaVersion: 1, Origin: operationsOrigin, Actor: actor, RequestID: operationRequest(version, "preview"), DraftID: proposal.DraftID, DraftRevision: proposal.DraftRevision, DraftHash: globalLayerHash(proposalRaw), TargetKind: proposal.TargetKind, TargetID: proposal.TargetID, Mode: proposal.Mode,
		DependencyHash: globalLayerHash([]byte("synthetic-dependency")), EffectiveHash: globalLayerHash([]byte("synthetic-effective")), IssuedAtMs: operationsNowMS, ExpiresAtMs: operationsNowMS + 120000,
		Recipients: []configuration.PreviewRecipient{{Owner: identity.Hash([]byte("synthetic-owner")), Device: proposal.TargetID, Thumbprint: identity.Hash([]byte("synthetic-device-key")), GrantHash: identity.Hash([]byte("synthetic-grant")), BaseRevision: 7, BaseHash: proposal.Bundles[0].BaseHash, CapabilitiesHash: capabilities}}}, nil
}

func makeOperations() (operationsDocument, error) {
	doc := operationsDocument{SchemaVersion: 1, SyntheticOnly: true, NowMS: operationsNowMS, Actor: identity.Hash([]byte("https://identity.example.invalid/realms/fixture\x00synthetic-admin")), APIOrigin: operationsOrigin, PreviewKeyID: operationsKeyID, Originals: []operationOriginalVector{}}
	proposal := operationProposal()
	proposalRaw, e := json.Marshal(proposal)
	if e != nil {
		return operationsDocument{}, errFixture
	}
	doc.ProposalWire = string(proposalRaw)
	if _, e = configuration.Merge(context.Background(), proposal.Bundles[0].Layers, func(raw json.RawMessage) error { _, e := configuration.DecodeNetworkPlan(raw); return e }); e != nil {
		return operationsDocument{}, errFixture
	}
	// The private scalar remains local to this generation. Only SPKI and
	// signatures for a reserved synthetic origin are exported. No client/server
	// runtime roots are read or changed and no database/network constructor runs.
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return operationsDocument{}, errFixture
	}
	spki, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		return operationsDocument{}, errFixture
	}
	doc.PreviewRootSPKIB64 = base64.StdEncoding.EncodeToString(spki)
	roots := map[string]*ecdsa.PublicKey{operationsKeyID: &key.PublicKey}
	for _, version := range []int{1, 2} {
		preview, e := operationPreview(doc.Actor, version, proposal, proposalRaw)
		if e != nil {
			return operationsDocument{}, errFixture
		}
		ticket, e := configuration.SignPreview(context.Background(), preview, operationsKeyID, key, time.UnixMilli(operationsNowMS))
		if e != nil {
			return operationsDocument{}, errFixture
		}
		if _, e = configuration.VerifyPreview(context.Background(), ticket, roots, operationsOrigin, doc.Actor, time.UnixMilli(operationsNowMS)); e != nil {
			return operationsDocument{}, errFixture
		}
		previewID := operationJob(doc.Actor, operationRequest(version, "preview"))
		specs := []struct {
			name, action string
			payload      any
		}{
			{"draft-put", "configuration.layers.draft.put", operationSavePayload{deviceprovisioning.ConfigurationDraft{ID: proposal.DraftID, Revision: 0, Proposal: proposal, SavedAtMs: 0}}},
			{"draft-discard", "configuration.layers.draft.discard", deviceprovisioning.ConfigurationDraftDiscard{ID: proposal.DraftID, Revision: 1, TargetKind: proposal.TargetKind, TargetID: proposal.TargetID}},
			{"preview", "configuration.preview.request", operationPreviewPayload{proposal}},
			{"publish", "configuration.publish", operationPublishPayload{previewID, ticket}},
		}
		for _, spec := range specs {
			payload, e := json.Marshal(spec.payload)
			if e != nil {
				return operationsDocument{}, errFixture
			}
			original := invitation.Envelope{Version: version, Action: spec.action, RequestID: operationRequest(version, spec.name), Payload: payload}
			raw, e := json.Marshal(original)
			if e != nil || len(raw) > 262144 {
				return operationsDocument{}, errFixture
			}
			vector := operationOriginalVector{Name: spec.name + "-v" + strconv.Itoa(version), OriginalBody64: base64.RawURLEncoding.EncodeToString(raw), BodyHash: globalLayerHash(raw), Outcomes: []operationOutcomeVector{}}
			for _, intent := range []string{"lookup", "seal_if_absent"} {
				wire, e := json.Marshal(operationReconcileWire{1, identity.Hash([]byte("synthetic-reconcile/" + vector.Name + "/" + intent)), intent, vector.OriginalBody64})
				if e != nil || len(wire) > 524288 {
					return operationsDocument{}, errFixture
				}
				if intent == "lookup" {
					vector.LookupWire = string(wire)
				} else {
					vector.SealWire = string(wire)
				}
			}
			isJob := spec.name == "preview" || spec.name == "publish"
			if isJob {
				vector.JobID = operationJob(doc.Actor, original.RequestID)
			}
			base := deviceprovisioning.ConfigurationOperationOutcome{Version: 1, Actor: doc.Actor, Action: original.Action, RequestID: original.RequestID, BodyHash: vector.BodyHash, TargetKind: proposal.TargetKind, TargetID: proposal.TargetID}
			appendOutcome := func(name string, value deviceprovisioning.ConfigurationOperationOutcome) error {
				wire, e := json.Marshal(value)
				if e != nil || len(wire) > 100000 {
					return errFixture
				}
				vector.Outcomes = append(vector.Outcomes, operationOutcomeVector{name, string(wire)})
				return nil
			}
			unknown := base
			unknown.Outcome = "UNKNOWN"
			if appendOutcome("UNKNOWN", unknown) != nil {
				return operationsDocument{}, errFixture
			}
			recorded := base
			recorded.Outcome = "RECORDED"
			recorded.RecordedAtMS = operationsNowMS + 1
			if isJob {
				recorded.EffectKind = "job"
				recorded.EffectID = vector.JobID
				recorded.Job = &deviceprovisioning.ConfigurationRequestView{ID: vector.JobID, State: "queued"}
			} else {
				recorded.EffectKind = "draft"
				recorded.EffectID = proposal.DraftID
				recorded.EffectRevision = 1
			}
			if appendOutcome("RECORDED", recorded) != nil {
				return operationsDocument{}, errFixture
			}
			missing := recorded
			missing.Outcome = "RECORDED_RESULT_UNAVAILABLE"
			missing.Job = nil
			if appendOutcome("RECORDED_RESULT_UNAVAILABLE", missing) != nil {
				return operationsDocument{}, errFixture
			}
			if version == 2 {
				absent := base
				absent.Outcome = "NO_EFFECT"
				absent.RecordedAtMS = operationsNowMS + 1
				if appendOutcome("NO_EFFECT", absent) != nil {
					return operationsDocument{}, errFixture
				}
			}
			if isJob {
				running := recorded
				running.Job = &deviceprovisioning.ConfigurationRequestView{ID: vector.JobID, State: "running"}
				if appendOutcome("RECORDED_RUNNING", running) != nil {
					return operationsDocument{}, errFixture
				}
				terminal := recorded
				if spec.name == "preview" {
					result, e := json.Marshal(deviceprovisioning.ConfigurationPreviewResult{PreviewID: previewID, Ticket: ticket, Preview: preview})
					if e != nil {
						return operationsDocument{}, errFixture
					}
					terminal.Job = &deviceprovisioning.ConfigurationRequestView{ID: vector.JobID, State: "ready", Result: result}
					if appendOutcome("RECORDED_READY", terminal) != nil {
						return operationsDocument{}, errFixture
					}
				} else {
					result, e := json.Marshal(struct {
						Heads []deviceprovisioning.ConfigurationPublishedHead `json:"heads"`
					}{[]deviceprovisioning.ConfigurationPublishedHead{{Device: proposal.TargetID, Revision: 8, Hash: preview.DraftHash}}})
					if e != nil {
						return operationsDocument{}, errFixture
					}
					terminal.Job = &deviceprovisioning.ConfigurationRequestView{ID: vector.JobID, State: "published", Result: result}
					if appendOutcome("RECORDED_PUBLISHED", terminal) != nil {
						return operationsDocument{}, errFixture
					}
				}
			}
			doc.Originals = append(doc.Originals, vector)
		}
	}
	return doc, nil
}

func runOperations(getenv func(string) string, output io.Writer) error {
	if getenv == nil || output == nil || getenv("GITHUB_ACTIONS") != "true" {
		return errFixture
	}
	doc, e := makeOperations()
	if e != nil {
		return errFixture
	}
	raw, e := json.Marshal(doc)
	if e != nil || len(raw)+1 > operationsLimit {
		return errFixture
	}
	raw = append(raw, '\n')
	if n, e := output.Write(raw); e != nil || n != len(raw) {
		return errFixture
	}
	return nil
}
