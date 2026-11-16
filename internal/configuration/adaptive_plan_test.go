package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func canonicalAdaptivePlanBindings(t *testing.T, refs map[string]ProfileReference) string {
	t.Helper()
	document := make(map[string]map[string]string, len(refs))
	for hop, ref := range refs {
		document[hop] = map[string]string{"profileId": ref.ProfileID, "sourceId": ref.SourceID}
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func adaptivePlanFixture(t *testing.T, count int) AdaptivePlan {
	t.Helper()
	metadata, refs, _ := adaptiveSnapshotInput(t, count)
	return AdaptivePlan{MetadataB64: base64.RawURLEncoding.EncodeToString(metadata), BindingsB64: canonicalAdaptivePlanBindings(t, refs), Groups: map[string]string{"foreign": "adaptive-foreign"}}
}

func cloneAdaptivePlan(t *testing.T, plan AdaptivePlan) AdaptivePlan {
	t.Helper()
	raw, err := json.Marshal(plan)
	var result AdaptivePlan
	if err != nil || json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid fixture")
	}
	return result
}

func TestAdaptivePlanOwns500BindingsWithoutWideningOrdinaryJSONLimits(t *testing.T) {
	adaptive := adaptivePlanFixture(t, 500)
	metadata, err := base64.RawURLEncoding.DecodeString(adaptive.MetadataB64)
	if err != nil {
		t.Fatal(err)
	}
	rawBindings, err := base64.RawURLEncoding.DecodeString(adaptive.BindingsB64)
	if err != nil {
		t.Fatal(err)
	}
	var ordinary any
	if identity.DecodeConfiguration(metadata, &ordinary) == nil || identity.DecodeConfiguration(rawBindings, &ordinary) == nil {
		t.Fatal("large inner documents unexpectedly bypassed ordinary256/128 limits")
	}
	plan := planBase()
	plan.Adaptive = &adaptive
	raw, err := json.Marshal(plan)
	if err != nil || len(raw) > 262144 {
		t.Fatal("fixture exceeded full plan bound", err)
	}
	decoded, err := DecodeNetworkPlan(raw)
	if err != nil || decoded.Adaptive == nil {
		t.Fatal("bounded500-binding draft failed", err)
	}
	snapshot, err := DecodeAdaptivePlan(*decoded.Adaptive, decoded.Graph)
	if err != nil || len(snapshot.Bindings()) != 500 || len(snapshot.Graph().GroupIDs()) != 1 || snapshot.Groups()["foreign"] != "adaptive-foreign" {
		t.Fatal("owned handoff omitted declared bindings/groups", err)
	}
	if !bytes.Equal(snapshot.Metadata(), metadata) || !snapshot.Graph().Allows("foreign", "WIFI", []string{"hop-499"}) {
		t.Fatal("last candidate or original metadata was lost")
	}
	decoded.Adaptive.Groups["foreign"] = "changed-tag"
	copyMetadata := snapshot.Metadata()
	copyMetadata[0] = '!'
	copyRefs := snapshot.Bindings()
	copyRefs["hop-000"] = ProfileReference{SourceID: "changed-source", ProfileID: "changed-profile"}
	copyGroups := snapshot.Groups()
	copyGroups["foreign"] = "changed-again"
	if !bytes.Equal(snapshot.Metadata(), metadata) || snapshot.Bindings()["hop-000"].SourceID != "source-a" || snapshot.Groups()["foreign"] != "adaptive-foreign" {
		t.Fatal("draft or returned collection mutated the owned handoff")
	}
	if output, _ := json.Marshal(snapshot); string(output) != "{}" || strings.Contains(fmt.Sprintf("%v %#v %v %#v", adaptive, adaptive, snapshot, snapshot), "source-a") {
		t.Fatal("decoded references leaked through diagnostics")
	}
}

func TestAdaptivePlanRequiresCanonicalBase64AndExactBoundedBindingJSON(t *testing.T) {
	base := adaptivePlanFixture(t, 1)
	for _, field := range []string{"metadata", "bindings"} {
		for _, bad := range []string{"", "=", "e31", "e30=", "e30\n", "/w", strings.Repeat("A", MaxAdaptivePlanBytes+1)} {
			plan := cloneAdaptivePlan(t, base)
			if field == "metadata" {
				plan.MetadataB64 = bad
			} else {
				plan.BindingsB64 = bad
			}
			if _, err := DecodeAdaptivePlan(plan, planBase().Graph); err == nil {
				t.Fatal("noncanonical or oversized base64url accepted")
			}
		}
	}
	for _, raw := range [][]byte{
		[]byte(`null`), []byte(`[]`), []byte(`{}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":"source-a","extra":"x"}}`),
		[]byte(`{"hop-000":{"ProfileId":"p","sourceId":"source-a"}}`),
		[]byte(`{"hop-000":{"profileId":"p","SourceId":"source-a"}}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":null}}`),
		[]byte(`{"hop-000":{"profileId":null,"sourceId":"source-a"}}`),
		[]byte(`{"hop-000":{"profileId":"p"}}`),
		[]byte(`{"hop-000":null}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":{"url":"not-a-reference"}}}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":"https://source.example.invalid"}}`),
		[]byte(`{"hop-000":{"profileId":"профиль","sourceId":"source-a"}}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":"source-a","sourceId":"source-b"}}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":"source-a"},"hop-000":{"profileId":"q","sourceId":"source-a"}}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":"source-a"},"hop-001":{"profileId":"p","sourceId":"source-a"}}`),
		[]byte(`{"hop-000":{"sourceId":"source-a","profileId":"p"}}`),
		[]byte(` {"hop-000":{"profileId":"p","sourceId":"source-a"}}`),
		[]byte(`{"hop-000":{"profileId":"p","sourceId":"source-a"}}{}`),
		[]byte(`{"HOP-000":{"profileId":"p","sourceId":"source-a"}}`),
		bytes.ReplaceAll([]byte(`{"hop-000":{"profileId":"p","sourceId":"source-a"}}`), []byte("source-a"), []byte{0xff}),
	} {
		plan := cloneAdaptivePlan(t, base)
		plan.BindingsB64 = base64.RawURLEncoding.EncodeToString(raw)
		if _, err := DecodeAdaptivePlan(plan, planBase().Graph); err == nil {
			t.Fatal("ambiguous or noncanonical inner bindings accepted")
		}
	}
	_, refs, _ := adaptiveSnapshotInput(t, 501)
	base.BindingsB64 = canonicalAdaptivePlanBindings(t, refs)
	if _, err := DecodeAdaptivePlan(base, planBase().Graph); err == nil {
		t.Fatal("501 inner bindings accepted")
	}
}

func TestAdaptivePlanRequiresClosedMetadataExactGroupMappingAndStaticTagIsolation(t *testing.T) {
	base := adaptivePlanFixture(t, 1)
	for _, mutate := range []func(*AdaptivePlan){
		func(p *AdaptivePlan) { p.Groups = nil },
		func(p *AdaptivePlan) { p.Groups = map[string]string{} },
		func(p *AdaptivePlan) { p.Groups = map[string]string{"missing": "adaptive-foreign"} },
		func(p *AdaptivePlan) { p.Groups["extra"] = "adaptive-extra" },
		func(p *AdaptivePlan) { p.Groups["foreign"] = "" },
		func(p *AdaptivePlan) { p.Groups["foreign"] = "direct" },
		func(p *AdaptivePlan) { p.Groups["foreign"] = "syn443_reserved" },
		func(p *AdaptivePlan) { p.Groups["foreign"] = "bad/tag" },
		func(p *AdaptivePlan) { p.Groups["foreign"] = "UPPER" },
		func(p *AdaptivePlan) { p.Groups["foreign"] = "bad.dot" },
		func(p *AdaptivePlan) { p.Groups["foreign"] = "_leading" },
		func(p *AdaptivePlan) { p.MetadataB64 = base64.RawURLEncoding.EncodeToString([]byte(`{}`)) },
		func(p *AdaptivePlan) { p.MetadataB64 = base64.RawURLEncoding.EncodeToString([]byte(`null`)) },
		func(p *AdaptivePlan) {
			raw, _ := base64.RawURLEncoding.DecodeString(p.MetadataB64)
			raw = bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
			p.MetadataB64 = base64.RawURLEncoding.EncodeToString(raw)
		},
		func(p *AdaptivePlan) {
			raw, _ := base64.RawURLEncoding.DecodeString(p.MetadataB64)
			raw = bytes.Replace(raw, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"unknown":1`), 1)
			p.MetadataB64 = base64.RawURLEncoding.EncodeToString(raw)
		},
	} {
		plan := cloneAdaptivePlan(t, base)
		mutate(&plan)
		if _, err := DecodeAdaptivePlan(plan, planBase().Graph); err == nil {
			t.Fatal("unbound group, reserved tag or invalid graph accepted")
		}
	}
	for _, static := range []Graph{
		{Profiles: map[string]ProfileReference{"adaptive-foreign": {SourceID: "source-a", ProfileID: "p"}}},
		{Chains: map[string]Chain{"adaptive-foreign": {DialOrder: []string{"entry", "exit"}}}},
		{Balancers: map[string]Balancer{"adaptive-foreign": {Type: "selector", Members: []string{"entry", "exit"}}}},
		{NetBird: &NetBirdNode{Tag: "adaptive-foreign"}},
	} {
		if _, err := DecodeAdaptivePlan(base, static); err == nil {
			t.Fatal("managed tag collided with an existing outbound")
		}
	}
	metadata, _ := base64.RawURLEncoding.DecodeString(base.MetadataB64)
	var graph map[string]any
	if json.Unmarshal(metadata, &graph) != nil {
		t.Fatal("invalid fixture")
	}
	groups := make([]any, 16)
	base.Groups = map[string]string{}
	for i := range groups {
		group, tag := fmt.Sprintf("group-%02d", i), fmt.Sprintf("adaptive-%02d", i)
		groups[i] = map[string]any{"id": group, "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"simple"}}
		base.Groups[group] = tag
	}
	graph["groups"] = groups
	metadata, _ = json.Marshal(graph)
	base.MetadataB64 = base64.RawURLEncoding.EncodeToString(metadata)
	if _, err := DecodeAdaptivePlan(base, planBase().Graph); err != nil {
		t.Fatal("16 exact groups rejected", err)
	}
	base.Groups["group-01"] = base.Groups["group-00"]
	if _, err := DecodeAdaptivePlan(base, planBase().Graph); err == nil {
		t.Fatal("two groups share one managed outbound tag")
	}
	base.Groups["group-01"] = "adaptive-01"
	base.Groups["group-16"] = "adaptive-16"
	if _, err := DecodeAdaptivePlan(base, planBase().Graph); err == nil {
		t.Fatal("17 groups accepted")
	}
}

func TestAdaptiveDraftLayersRemainClosedAndRequireManagedCheckBindings(t *testing.T) {
	plan := planBase()
	adaptive := adaptivePlanFixture(t, 3)
	plan.Adaptive = &adaptive
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"metadataB64":`), []byte(`"MetadataB64":`), 1),
		bytes.Replace(raw, []byte(`"metadataB64":"`+adaptive.MetadataB64+`"`), []byte(`"metadataB64":null`), 1),
		bytes.Replace(raw, []byte(`"bindingsB64":"`+adaptive.BindingsB64+`"`), []byte(`"bindingsB64":null`), 1),
		bytes.Replace(raw, []byte(`"bindingsB64":`), []byte(`"bindingsB64":null,"unused":`), 1),
		bytes.Replace(raw, []byte(`"groups":`), []byte(`"groups":{},"groups":`), 1),
		bytes.Replace(raw, []byte(`"adaptive":{`), []byte(`"adaptive":{"unknown":0,`), 1),
		bytes.Replace(raw, []byte(`"adaptive":{`), []byte(`"adaptive":{"schemaVersion":1,`), 1),
		append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), 262145)...),
	} {
		if _, err := DecodeNetworkPlan(bad); err == nil {
			t.Fatal("outer closed plan accepted malformed adaptive shape")
		}
	}
	fields := map[string]json.RawMessage{}
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("invalid fixture")
	}
	layer := Layer{ID: "base", Kind: "template", Revision: 1}
	for _, name := range []string{"schemaVersion", "graph", "network", "activation", "adaptive"} {
		layer.Changes = append(layer.Changes, Change{Path: "/" + name, Operation: "set", Value: fields[name]})
	}
	effective, err := Merge(context.Background(), []Layer{layer}, func(raw json.RawMessage) error { _, err := DecodeNetworkPlan(raw); return err })
	if err != nil {
		t.Fatal("closed adaptive draft cannot pass normal layer handling", err)
	}
	decoded, err := DecodeNetworkPlan(effective.Document)
	if err != nil || !reflect.DeepEqual(decoded.Adaptive, plan.Adaptive) {
		t.Fatal("draft merge dropped or altered its adaptive field", err)
	}
	calls := 0
	compiled, err := CompileNetworkPlan(context.Background(), decoded, func(ProfileReference) (subscriptions.Profile, error) {
		calls++
		return subscriptions.Profile{}, nil
	})
	if !errors.Is(err, ErrInvalid) || calls != 0 || len(compiled.EngineConfig) != 0 {
		t.Fatal("adaptive plan bypassed required managed check bindings before source resolution", err)
	}
	decoded.Adaptive = nil
	if _, err := CompileNetworkPlan(context.Background(), decoded, defaultGraphResolver()); err != nil {
		t.Fatal("ordinary nil-adaptive compilation changed", err)
	}
	oversize := cloneAdaptivePlan(t, adaptive)
	oversize.MetadataB64 = strings.Repeat("A", MaxAdaptivePlanBytes)
	if _, err := DecodeAdaptivePlan(oversize, plan.Graph); err == nil {
		t.Fatal("adaptive serialized byte quota escaped")
	}
}
