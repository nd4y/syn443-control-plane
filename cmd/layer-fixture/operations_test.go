package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/deviceprovisioning"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func operationsFixture(t *testing.T) operationsDocument {
	t.Helper()
	doc, e := makeOperations()
	if e != nil {
		t.Fatal("synthetic actual-Go operation generation failed")
	}
	return doc
}
func operationsOriginal(t *testing.T, sample operationOriginalVector) (invitation.Envelope, []byte) {
	t.Helper()
	raw, e := base64.RawURLEncoding.DecodeString(sample.OriginalBody64)
	var value invitation.Envelope
	if e != nil || len(raw) == 0 || len(raw) > 262144 || base64.RawURLEncoding.EncodeToString(raw) != sample.OriginalBody64 || identity.DecodeConfiguration(raw, &value) != nil {
		t.Fatal("invalid original bytes")
	}
	return value, raw
}
func operationsRoot(t *testing.T, doc operationsDocument) map[string]*ecdsa.PublicKey {
	t.Helper()
	der, e := base64.StdEncoding.DecodeString(doc.PreviewRootSPKIB64)
	if e != nil || len(der) > 4096 {
		t.Fatal("invalid public SPKI")
	}
	key, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		t.Fatal("invalid public fixture root")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatal("fixture is not P256")
	}
	if _, e = x509.ParsePKCS8PrivateKey(der); e == nil {
		t.Fatal("private key bytes in public root")
	}
	return map[string]*ecdsa.PublicKey{doc.PreviewKeyID: pub}
}
func operationSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	raw, e := contracts.Files.ReadFile("v1/control-openapi.json")
	if e != nil {
		t.Fatal("actual server schema missing")
	}
	var source any
	if json.Unmarshal(raw, &source) != nil {
		t.Fatal("invalid server contract")
	}
	c := jsonschema.NewCompiler()
	const base = "https://contracts.example.invalid/control-openapi.json"
	if c.AddResource(base, source) != nil {
		t.Fatal("cannot load server contract")
	}
	schema, e := c.Compile(base + "#/components/schemas/" + name)
	if e != nil {
		t.Fatal("cannot compile actual server schema")
	}
	return schema
}
func operationSchemaValue(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()
	var value any
	if json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		t.Fatal("actual Go wire violates current server contract")
	}
}

func TestOperationFixtureActualEnvelopeBytesHashesAndDerivedJobIDsAreSourceBound(t *testing.T) {
	doc := operationsFixture(t)
	seen := map[string]bool{}
	if doc.Actor != identity.Hash([]byte("https://identity.example.invalid/realms/fixture\x00synthetic-admin")) {
		t.Fatal("actor hash algorithm changed")
	}
	for _, sample := range doc.Originals {
		original, raw := operationsOriginal(t, sample)
		again, e := json.Marshal(original)
		if e != nil || !bytes.Equal(again, raw) || globalLayerHash(raw) != sample.BodyHash || seen[sample.Name] {
			t.Fatal("original Marshal bytes/hash/name changed")
		}
		seen[sample.Name] = true
		var generic map[string]any
		if json.Unmarshal(raw, &generic) != nil {
			t.Fatal("invalid original")
		}
		reencoded, _ := json.Marshal(generic)
		if globalLayerHash(reencoded) == sample.BodyHash {
			t.Fatal("generic reencoding silently substituted original bytes")
		}
		job := original.Action == "configuration.preview.request" || original.Action == "configuration.publish"
		if job && sample.JobID != identity.Hash([]byte(doc.Actor+"\x00"+original.RequestID)) || !job && sample.JobID != "" {
			t.Fatal("job identity borrowed a body hash or wrong scope")
		}
	}
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path missing")
	}
	set := token.NewFileSet()
	source, e := parser.ParseFile(set, filepath.Join(filepath.Dir(here), "../../internal/deviceprovisioning/layer_requests.go"), nil, 0)
	if e != nil {
		t.Fatal("cannot inspect actual queue identity")
	}
	bound := 0
	for _, node := range source.Decls {
		f, ok := node.(*ast.FuncDecl)
		if !ok || f.Name.Name != "queue" {
			continue
		}
		ast.Inspect(f.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || render(t, set, lit.Type) != "ConfigurationRequestView" {
				return true
			}
			for _, entry := range lit.Elts {
				kv, ok := entry.(*ast.KeyValueExpr)
				if ok && render(t, set, kv.Key) == "ID" && render(t, set, kv.Value) == `identity.Hash([]byte(actor + "\x00" + envelope.RequestID))` {
					bound++
				}
			}
			return true
		})
	}
	if bound != 1 {
		t.Fatal("fixture detached from actual actor-NUL-request queue algorithm")
	}
}

func TestOperationFixtureEightMutationOriginalsUseActualClosedServerSchemas(t *testing.T) {
	doc := operationsFixture(t)
	action := operationSchema(t, "Action")
	reconcile := operationSchema(t, "ConfigurationOperationReconcile")
	seen := map[string]bool{}
	for _, sample := range doc.Originals {
		envelope, raw := operationsOriginal(t, sample)
		operationSchemaValue(t, action, raw)
		key := sample.Name
		if seen[key] {
			t.Fatal("duplicate original")
		}
		seen[key] = true
		for _, entry := range []struct{ wire, intent string }{{sample.LookupWire, "lookup"}, {sample.SealWire, "seal_if_absent"}} {
			operationSchemaValue(t, reconcile, []byte(entry.wire))
			var input operationReconcileWire
			if identity.DecodeConfiguration([]byte(entry.wire), &input) != nil || input.OriginalBody64 != sample.OriginalBody64 || input.Intent != entry.intent || input.RequestID == envelope.RequestID {
				t.Fatal("reconciliation replaced original identity")
			}
		}
	}
	expected := []string{"draft-put-v1", "draft-discard-v1", "preview-v1", "publish-v1", "draft-put-v2", "draft-discard-v2", "preview-v2", "publish-v2"}
	if len(seen) != 8 {
		t.Fatal("version/action matrix changed")
	}
	for _, name := range expected {
		if !seen[name] {
			t.Fatal("missing versioned mutation")
		}
	}
	// The wrappers with private server names stay byte-shape bound without
	// exporting production authority constructors or changing the server API.
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "../.."))
	set := token.NewFileSet()
	load := func(path string) *ast.File {
		f, e := parser.ParseFile(set, filepath.Join(root, path), nil, 0)
		if e != nil {
			t.Fatal("cannot inspect wrapper source")
		}
		return f
	}
	fields := func(s *ast.StructType) []string {
		out := []string{}
		for _, f := range s.Fields.List {
			if len(f.Names) != 1 || f.Tag == nil {
				t.Fatal("unexpected wire wrapper")
			}
			out = append(out, f.Names[0].Name+":"+strings.TrimPrefix(render(t, set, f.Type), "deviceprovisioning.")+":"+f.Tag.Value)
		}
		return out
	}
	find := func(source *ast.File, name string) *ast.StructType {
		for _, decl := range source.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range d.Specs {
				v, ok := spec.(*ast.TypeSpec)
				if ok && v.Name.Name == name {
					s, ok := v.Type.(*ast.StructType)
					if !ok {
						t.Fatal("wrapper ceased to be a struct")
					}
					return s
				}
			}
		}
		t.Fatal("missing actual wrapper")
		return nil
	}
	ours := load("cmd/layer-fixture/operations.go")
	server := load("internal/deviceprovisioning/layer_requests.go")
	for _, pair := range [][2]string{{"operationPreviewPayload", "configurationPreviewInput"}, {"operationPublishPayload", "configurationPublishInput"}} {
		if !reflect.DeepEqual(fields(find(ours, pair[0])), fields(find(server, pair[1]))) {
			t.Fatal("request wrapper differs from actual server")
		}
	}
	if !reflect.DeepEqual(fields(find(ours, "operationReconcileWire")), fields(find(load("internal/deviceprovisioning/operation_reconcile.go"), "configurationReconcileInput"))) {
		t.Fatal("reconcile wrapper differs from server")
	}
	matched := 0
	ast.Inspect(server, func(n ast.Node) bool {
		v, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		s, ok := v.Type.(*ast.StructType)
		if !ok || len(s.Fields.List) != 1 {
			return true
		}
		f := s.Fields.List[0]
		if len(f.Names) == 1 && f.Names[0].Name == "Draft" && render(t, set, f.Type) == "ConfigurationDraft" {
			if !reflect.DeepEqual(fields(s), fields(find(ours, "operationSavePayload"))) {
				t.Fatal("save wrapper differs from server")
			}
			matched++
		}
		return true
	})
	if matched != 1 {
		t.Fatal("actual save wrapper source missing or ambiguous")
	}
}

func TestOperationFixtureEveryOutcomeUsesActualDTOAndCorrectOptionalJobShape(t *testing.T) {
	doc := operationsFixture(t)
	schema := operationSchema(t, "ConfigurationOperationOutcome")
	total := 0
	states := map[string]int{}
	for _, sample := range doc.Originals {
		original, _ := operationsOriginal(t, sample)
		seen := map[string]bool{}
		for _, entry := range sample.Outcomes {
			total++
			if seen[entry.Name] {
				t.Fatal("duplicate outcome vector")
			}
			seen[entry.Name] = true
			operationSchemaValue(t, schema, []byte(entry.Wire))
			var value deviceprovisioning.ConfigurationOperationOutcome
			if identity.DecodeConfiguration([]byte(entry.Wire), &value) != nil {
				t.Fatal("not an actual outcome DTO")
			}
			again, e := json.Marshal(value)
			if e != nil || string(again) != entry.Wire {
				t.Fatal("outcome did not use server Marshal")
			}
			if value.Actor != doc.Actor || value.Action != original.Action || value.RequestID != original.RequestID || value.BodyHash != sample.BodyHash || value.TargetID != "synthetic-device" || value.TargetKind != "device" {
				t.Fatal("outcome borrowed another operation")
			}
			states[value.Outcome]++
			if value.Outcome == "UNKNOWN" || value.Outcome == "NO_EFFECT" {
				if value.Job != nil || value.EffectKind != "" || value.EffectID != "" || value.EffectRevision != 0 || value.Outcome == "NO_EFFECT" && original.Version != 2 {
					t.Fatal("unproved effect/legacy absence")
				}
			} else if sample.JobID != "" {
				if value.EffectKind != "job" || value.EffectID != sample.JobID || value.EffectRevision != 0 {
					t.Fatal("wrong job reference")
				}
			} else if value.EffectKind != "draft" || value.EffectID != "synthetic-operation-draft" || value.EffectRevision != 1 {
				t.Fatal("wrong draft reference")
			}
			var raw map[string]any
			json.Unmarshal([]byte(entry.Wire), &raw)
			if value.Job == nil {
				if _, ok := raw["job"]; ok {
					t.Fatal("nil job was serialized instead of omitted")
				}
			} else {
				if value.Outcome != "RECORDED" || value.Job.ID != sample.JobID {
					t.Fatal("unavailable/nonterminal job misclassified")
				}
				job := raw["job"].(map[string]any)
				if _, ok := job["error"]; ok {
					t.Fatal("empty error not omitted")
				}
				_, hasResult := job["result"]
				if hasResult != (len(value.Job.Result) > 0) {
					t.Fatal("nil result was not omitted")
				}
			}
		}
	}
	if total != 36 || states["UNKNOWN"] != 8 || states["NO_EFFECT"] != 4 || states["RECORDED_RESULT_UNAVAILABLE"] != 8 || states["RECORDED"] != 16 {
		t.Fatal("four-outcome/job-shape matrix changed")
	}
}

func TestOperationFixtureEphemeralPreviewTicketsVerifyOnlyWithPublicSyntheticRoot(t *testing.T) {
	doc := operationsFixture(t)
	roots := operationsRoot(t, doc)
	count := 0
	for _, sample := range doc.Originals {
		original, _ := operationsOriginal(t, sample)
		if original.Action != "configuration.publish" {
			continue
		}
		count++
		var input operationPublishPayload
		if identity.DecodeConfiguration(original.Payload, &input) != nil {
			t.Fatal("invalid publish payload")
		}
		p, e := configuration.VerifyPreview(context.Background(), input.Ticket, roots, doc.APIOrigin, doc.Actor, time.UnixMilli(doc.NowMS))
		if e != nil || p.DraftHash != globalLayerHash([]byte(doc.ProposalWire)) {
			t.Fatal("actual Go preview verification failed")
		}
		for _, bad := range []struct {
			roots                 map[string]*ecdsa.PublicKey
			origin, actor, ticket string
			at                    int64
		}{{nil, doc.APIOrigin, doc.Actor, input.Ticket, doc.NowMS}, {roots, "https://foreign.example.invalid", doc.Actor, input.Ticket, doc.NowMS}, {roots, doc.APIOrigin, identity.Hash([]byte("foreign")), input.Ticket, doc.NowMS}, {roots, doc.APIOrigin, doc.Actor, input.Ticket, doc.NowMS + 120001}} {
			if _, e := configuration.VerifyPreview(context.Background(), bad.ticket, bad.roots, bad.origin, bad.actor, time.UnixMilli(bad.at)); e == nil {
				t.Fatal("fixture ticket became unrelated/expired authority")
			}
		}
		parts := strings.Split(input.Ticket, ".")
		if len(parts) != 3 {
			t.Fatal("invalid actual compact ticket")
		}
		zero := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		if _, e := configuration.VerifyPreview(context.Background(), zero, roots, doc.APIOrigin, doc.Actor, time.UnixMilli(doc.NowMS)); e == nil {
			t.Fatal("zero signature accepted")
		}
	}
	other := operationsFixture(t)
	if count != 2 || other.PreviewRootSPKIB64 == doc.PreviewRootSPKIB64 {
		t.Fatal("fixture key was persisted or reused")
	}
}

func TestOperationFixturePublishBodiesRetainExactProposalAndPreviewContext(t *testing.T) {
	doc := operationsFixture(t)
	var p deviceprovisioning.LayerProposal
	if identity.DecodeConfiguration([]byte(doc.ProposalWire), &p) != nil {
		t.Fatal("invalid actual proposal")
	}
	raw, e := json.Marshal(p)
	if e != nil || string(raw) != doc.ProposalWire {
		t.Fatal("proposal changed actual server bytes")
	}
	if _, e := configuration.Merge(context.Background(), p.Bundles[0].Layers, func(raw json.RawMessage) error { _, e := configuration.DecodeNetworkPlan(raw); return e }); e != nil {
		t.Fatal("synthetic proposal is not a typed portable plan")
	}
	roots := operationsRoot(t, doc)
	for _, sample := range doc.Originals {
		original, _ := operationsOriginal(t, sample)
		switch original.Action {
		case "configuration.layers.draft.put":
			var in operationSavePayload
			if identity.DecodeConfiguration(original.Payload, &in) != nil || in.Draft.Revision != 0 || in.Draft.SavedAtMs != 0 {
				t.Fatal("invalid actual draft")
			}
			body, _ := json.Marshal(in.Draft.Proposal)
			if string(body) != doc.ProposalWire {
				t.Fatal("save replaced private proposal")
			}
		case "configuration.preview.request":
			var in operationPreviewPayload
			if identity.DecodeConfiguration(original.Payload, &in) != nil {
				t.Fatal("invalid preview")
			}
			body, _ := json.Marshal(in.Proposal)
			if string(body) != doc.ProposalWire {
				t.Fatal("preview changed proposal")
			}
		case "configuration.publish":
			var in operationPublishPayload
			if identity.DecodeConfiguration(original.Payload, &in) != nil {
				t.Fatal("invalid publish")
			}
			ticket, e := configuration.VerifyPreview(context.Background(), in.Ticket, roots, doc.APIOrigin, doc.Actor, time.UnixMilli(doc.NowMS))
			if e != nil || in.PreviewID != operationJob(doc.Actor, ticket.RequestID) || ticket.RequestID != operationRequest(original.Version, "preview") || ticket.DraftID != p.DraftID || ticket.DraftRevision != p.DraftRevision || ticket.DraftHash != globalLayerHash([]byte(doc.ProposalWire)) || ticket.TargetID != p.TargetID || ticket.Mode != p.Mode {
				t.Fatal("publish borrowed another preview/proposal")
			}
		}
	}
}

func TestOperationFixtureBoundedActionsOutputPreservesExistingModesAndRejectsFailedWrites(t *testing.T) {
	owned := func(name string) string {
		if name != "GITHUB_ACTIONS" {
			t.Fatal("producer consulted unrelated environment")
		}
		return "true"
	}
	var beforeWire, beforeProjection, operations, afterWire, afterProjection bytes.Buffer
	if run(owned, &beforeWire) != nil || runProjection(owned, &beforeProjection) != nil || runOperations(owned, &operations) != nil || run(owned, &afterWire) != nil || runProjection(owned, &afterProjection) != nil {
		t.Fatal("fixture mode failed")
	}
	if !bytes.Equal(beforeWire.Bytes(), afterWire.Bytes()) || !bytes.Equal(beforeProjection.Bytes(), afterProjection.Bytes()) {
		t.Fatal("new mode changed existing payload bytes")
	}
	if operations.Len() == 0 || operations.Len() > operationsLimit {
		t.Fatal("operation fixture exceeded bound")
	}
	var doc operationsDocument
	decoder := json.NewDecoder(bytes.NewReader(operations.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(new(any)) != io.EOF || doc.SchemaVersion != 1 || !doc.SyntheticOnly || doc.APIOrigin != operationsOrigin || doc.PreviewKeyID != operationsKeyID || len(doc.Originals) != 8 {
		t.Fatal("operation artifact ABI changed")
	}
	for _, forbidden := range []string{"PRIVATE KEY", `"setup_key":`, `"access_token":`, `"refresh_token":`, `"password":`, "192.168."} {
		if bytes.Contains(operations.Bytes(), []byte(forbidden)) {
			t.Fatal("non-public/credential-like fixture data")
		}
	}
	for _, env := range []string{"", "false", "TRUE", "1"} {
		var output bytes.Buffer
		if runOperations(func(string) string { return env }, &output) != errFixture || output.Len() != 0 {
			t.Fatal("unowned producer wrote output")
		}
	}
	for _, writer := range []io.Writer{nil, brokenOutput{}, brokenOutput{short: true}} {
		if runOperations(owned, writer) != errFixture {
			t.Fatal("missing/failed/short writer accepted")
		}
	}
	if runOperations(nil, io.Discard) != errFixture {
		t.Fatal("missing Actions guard")
	}
}
