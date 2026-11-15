package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func adaptiveSnapshotInput(t *testing.T, count int) ([]byte, map[string]ProfileReference, map[ProfileReference]subscriptions.Profile) {
	t.Helper()
	hops := []any{}
	ids := []string{}
	refs := map[string]ProfileReference{}
	profiles := map[ProfileReference]subscriptions.Profile{}
	for i := 0; i < count; i++ {
		hop := fmt.Sprintf("hop-%03d", i)
		ids = append(ids, hop)
		hops = append(hops, map[string]any{"id": hop, "entryModes": []string{"WIFI"}, "exitClass": "NON_RU", "features": []string{"TCP"}})
		ref := ProfileReference{"source-a", fmt.Sprintf("source-a_profile-%03d", i)}
		refs[hop] = ref
		raw, _ := json.Marshal(map[string]any{"type": "http", "tag": ref.ProfileID, "server": fmt.Sprintf("proxy-%03d.example.invalid", i), "server_port": 443})
		profiles[ref] = subscriptions.Profile{ID: ref.ProfileID, Name: "synthetic-provider-name", Kind: "http", Outbound: raw}
	}
	raw, e := json.Marshal(map[string]any{"schemaVersion": 1, "hops": hops, "edges": []any{}, "templates": []any{map[string]any{"id": "simple", "slots": [][]string{ids}}}, "groups": []any{map[string]any{"id": "foreign", "intent": "NON_RU", "features": []string{"TCP"}, "templates": []string{"simple"}}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw, refs, profiles
}

func TestAdaptiveSnapshotOwnsGraphCatalogueAndDeterministicSourceBinding(t *testing.T) {
	metadata, refs, profiles := adaptiveSnapshotInput(t, 3)
	beforeMetadata := append([]byte(nil), metadata...)
	var calls []ProfileReference
	s, e := CompileAdaptiveSnapshot(context.Background(), metadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) {
		calls = append(calls, ref)
		return profiles[ref], nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(calls) != 3 || calls[0].ProfileID >= calls[1].ProfileID || calls[1].ProfileID >= calls[2].ProfileID {
		t.Fatal("resolution is not finite deterministic order")
	}
	again, e := CompileAdaptiveSnapshot(context.Background(), beforeMetadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) { return profiles[ref], nil })
	if e != nil || again.ContentHash() != s.ContentHash() {
		t.Fatal("same authorized selection changed identity", e)
	}
	copy(metadata, bytes.Repeat([]byte("!"), len(metadata)))
	refs["hop-000"] = ProfileReference{"changed-source", "changed-profile"}
	for _, p := range profiles {
		copy(p.Outbound, bytes.Repeat([]byte("!"), len(p.Outbound)))
	}
	if !s.DeclaredPath("foreign", "WIFI", []string{"hop-000"}) || s.DeclaredPath("foreign", "CELLULAR", []string{"hop-000"}) || s.DeclaredPath("missing", "WIFI", []string{"hop-000"}) {
		t.Fatal("snapshot eligibility changed or expanded")
	}
	p, e := s.Profile("hop-000")
	if e != nil || p.ID != "hop-000" || p.Name != "" || !bytes.Contains(p.Outbound, []byte(`"tag":"hop-000"`)) {
		t.Fatal("local profile was not normalized", e)
	}
	if bytes.Contains(p.Outbound, []byte("source-a")) || bytes.Contains(p.Outbound, []byte("synthetic-provider-name")) {
		t.Fatal("provider identifiers leaked into device profile")
	}
	copy(p.Outbound, bytes.Repeat([]byte("!"), len(p.Outbound)))
	fresh, e := s.Profile("hop-000")
	if e != nil || fresh.Outbound[0] != '{' {
		t.Fatal("returned buffer mutated snapshot")
	}
	if _, e = s.Profile("unbound"); !errors.Is(e, ErrInvalid) {
		t.Fatal("unbound profile resolved")
	}
	if raw, _ := json.Marshal(s); string(raw) != "{}" || strings.Contains(fmt.Sprintf("%v %#v", s, s), "proxy-") {
		t.Fatal("ordinary diagnostics exposed snapshot")
	}
	var readers sync.WaitGroup
	for i := 0; i < 40; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for n := 0; n < 50; n++ {
				p, e := s.Profile("hop-001")
				if e != nil || p.ID != "hop-001" || s.ContentHash() != again.ContentHash() || !s.DeclaredPath("foreign", "WIFI", []string{"hop-001"}) {
					t.Error("concurrent immutable read changed")
				}
			}
		}()
	}
	readers.Wait()
}

func TestAdaptiveSnapshotRejectsUnboundAliasesInvalidProfilesAndClosedGraph(t *testing.T) {
	for _, kind := range []string{"nil-context", "nil-resolver", "empty-bindings", "too-many-bindings", "bad-hop", "bad-source", "bad-profile-id", "aliased-reference", "wrong-graph", "empty-metadata", "oversized-metadata"} {
		t.Run(kind, func(t *testing.T) {
			metadata, refs, profiles := adaptiveSnapshotInput(t, 2)
			ctx := context.Background()
			calls := 0
			resolve := func(ref ProfileReference) (subscriptions.Profile, error) { calls++; return profiles[ref], nil }
			switch kind {
			case "nil-context":
				ctx = nil
			case "nil-resolver":
				resolve = nil
			case "empty-bindings":
				refs = nil
			case "too-many-bindings":
				metadata, refs, profiles = adaptiveSnapshotInput(t, 501)
			case "bad-hop":
				refs["INVALID"] = refs["hop-000"]
				delete(refs, "hop-000")
			case "bad-source":
				refs["hop-000"] = ProfileReference{"https://source.example.invalid", "profile"}
			case "bad-profile-id":
				refs["hop-000"] = ProfileReference{"source-a", "../profile"}
			case "aliased-reference":
				refs["hop-001"] = refs["hop-000"]
			case "wrong-graph":
				delete(refs, "hop-000")
			case "empty-metadata":
				metadata = nil
			case "oversized-metadata":
				metadata = bytes.Repeat([]byte(" "), 262145)
			}
			if s, e := CompileAdaptiveSnapshot(ctx, metadata, refs, resolve); s != nil || !errors.Is(e, ErrInvalid) || calls != 0 {
				t.Fatal("invalid binding reached source or snapshot", e, calls)
			}
		})
	}
	for _, kind := range []string{"revoked", "wrong-id", "wrong-kind", "empty", "oversized", "not-object", "invalid-json", "insecure-tls", "foreign-detour", "duplicate-transport"} {
		t.Run(kind, func(t *testing.T) {
			metadata, refs, profiles := adaptiveSnapshotInput(t, 2)
			s, e := CompileAdaptiveSnapshot(context.Background(), metadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) {
				p := profiles[ref]
				switch kind {
				case "revoked":
					return p, fmt.Errorf("synthetic provider credential must not become an error")
				case "wrong-id":
					p.ID = "substituted"
				case "wrong-kind":
					p.Kind = "vless"
				case "empty":
					p.Outbound = nil
				case "oversized":
					p.Outbound = bytes.Repeat([]byte(" "), 65537)
				case "not-object":
					p.Outbound = json.RawMessage(`[]`)
				case "invalid-json":
					p.Outbound = json.RawMessage(`{"tag":`)
				default:
					var node map[string]any
					_ = json.Unmarshal(p.Outbound, &node)
					if kind == "insecure-tls" {
						node["tls"] = map[string]any{"enabled": true, "insecure": true}
					}
					if kind == "foreign-detour" {
						node["detour"] = "outside"
					}
					if kind == "duplicate-transport" {
						node["server"] = "same.example.invalid"
					}
					p.Outbound, _ = json.Marshal(node)
				}
				return p, nil
			})
			if s != nil || e != ErrInvalid {
				t.Fatal("invalid/revoked source yielded authority or raw source error", e)
			}
		})
	}
}

func TestAdaptiveSnapshotLimitsRevocationCancellationAndContentIdentity(t *testing.T) {
	metadata, refs, profiles := adaptiveSnapshotInput(t, 500)
	resolve := func(ref ProfileReference) (subscriptions.Profile, error) { return profiles[ref], nil }
	s, e := CompileAdaptiveSnapshot(context.Background(), metadata, refs, resolve)
	if e != nil || len(s.profiles) != 500 {
		t.Fatal("500-profile bounded catalogue failed", e)
	}
	for ref, p := range profiles {
		var node map[string]any
		_ = json.Unmarshal(p.Outbound, &node)
		node["password"] = strings.Repeat("x", 600)
		p.Outbound, _ = json.Marshal(node)
		profiles[ref] = p
	}
	if s, e = CompileAdaptiveSnapshot(context.Background(), metadata, refs, resolve); s != nil || e != ErrInvalid {
		t.Fatal("aggregate protected snapshot exceeded byte bound", e)
	}
	metadata, refs, profiles = adaptiveSnapshotInput(t, 2)
	first, e := CompileAdaptiveSnapshot(context.Background(), metadata, refs, resolve)
	if e != nil {
		t.Fatal(e)
	}
	ref := refs["hop-001"]
	p := profiles[ref]
	p.Outbound = bytes.ReplaceAll(p.Outbound, []byte("proxy-001"), []byte("changed-001"))
	profiles[ref] = p
	changed, e := CompileAdaptiveSnapshot(context.Background(), metadata, refs, resolve)
	if e != nil || first.ContentHash() == changed.ContentHash() {
		t.Fatal("changed source content kept prior binding", e)
	}
	refs["hop-001"] = ProfileReference{"source-b", ref.ProfileID}
	profiles[refs["hop-001"]] = p
	changedRef, e := CompileAdaptiveSnapshot(context.Background(), metadata, refs, resolve)
	if e != nil || changedRef.ContentHash() == changed.ContentHash() {
		t.Fatal("changed source authority kept prior binding", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if s, e = CompileAdaptiveSnapshot(ctx, metadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) { calls++; return profiles[ref], nil }); s != nil || e != context.Canceled || calls != 0 {
		t.Fatal("cancelled source work started", e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if s, e = CompileAdaptiveSnapshot(ctx, metadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) { cancel(); return profiles[ref], nil }); s != nil || e != context.Canceled {
		t.Fatal("late source result bypassed cancellation", e)
	}
	calls = 0
	if s, e = CompileAdaptiveSnapshot(context.Background(), metadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) {
		calls++
		if calls == 2 {
			return subscriptions.Profile{}, ErrLocked
		}
		return profiles[ref], nil
	}); s != nil || e != ErrInvalid || calls != 2 {
		t.Fatal("revocation left a partial usable catalogue", e)
	}
}

func TestAdaptiveSnapshotCopiesBeforeFurtherResolutionAndCannotPublishBlockedWork(t *testing.T) {
	metadata, refs, profiles := adaptiveSnapshotInput(t, 2)
	original := append([]byte(nil), metadata...)
	s, e := CompileAdaptiveSnapshot(context.Background(), metadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) {
		if ref == refs["hop-001"] {
			copy(metadata, bytes.Repeat([]byte("!"), len(metadata)))
			p := profiles[refs["hop-000"]]
			copy(p.Outbound, bytes.Repeat([]byte("!"), len(p.Outbound)))
		}
		return profiles[ref], nil
	})
	if e != nil || !s.DeclaredPath("foreign", "WIFI", []string{"hop-000"}) {
		t.Fatal("later resolution changed earlier owned input", e)
	}
	metadata, refs, profiles = adaptiveSnapshotInput(t, 2)
	if !bytes.Equal(metadata, original) {
		t.Fatal("fixture changed")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(done)
		s, e := CompileAdaptiveSnapshot(ctx, metadata, refs, func(ref ProfileReference) (subscriptions.Profile, error) {
			close(entered)
			<-release
			return profiles[ref], nil
		})
		if s != nil || e != context.Canceled {
			t.Error("blocked stale resolution published")
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("resolver did not enter")
	}
	cancel()
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("resolver did not finish")
	}
	if p, e := s.Profile("hop-000"); e != nil || !bytes.Contains(p.Outbound, []byte("proxy-000")) {
		t.Fatal("prior immutable snapshot was lost", e)
	}
}
