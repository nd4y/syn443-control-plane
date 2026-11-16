//go:build postgres

package catalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func adaptiveSQLSelectionFixture(t *testing.T) (*Store, *Store, Actor, Source, []ProfileReference, time.Time) {
	t.Helper()
	api, worker, actor, now := databaseFixture(t)
	source := mustSource(t, api, actor, sourceExample(now), "create-adaptive-selection-source", now)
	urls := make([]string, 532)
	for i := range urls {
		urls[i] = fmt.Sprintf("http://proxy-%03d.example.invalid:443", i)
	}
	job, profiles := manualWork(t, api, worker, actor, source, "import-adaptive-selection", strings.Join(urls, "\n"), now)
	snapshot, err := worker.Complete(context.Background(), job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
	if err != nil || snapshot.State != "active" || len(profiles) != 532 {
		t.Fatal("bounded adaptive source fixture", err)
	}
	reader := *api
	reader.DB = fixturePublisher
	refs := make([]ProfileReference, len(profiles))
	for i, profile := range profiles {
		refs[i] = ProfileReference{SourceID: source.ID, ProfileID: profile.ID}
	}
	return api, &reader, actor, source, refs, now
}

func TestSQLAdaptiveSelectionOwns500Plus32AndPreservesOrdinaryLimit(t *testing.T) {
	_, reader, _, source, refs, now := adaptiveSQLSelectionFixture(t)
	ctx := context.Background()
	target := SelectionTarget{Owner: source.Owner, Device: "device-a"}
	if _, err := reader.PrepareSelection(ctx, target, refs[:64], "wifi", now.Unix()+3600, now); err != nil {
		t.Fatal("ordinary64 rejected", err)
	}
	if _, err := reader.PrepareSelection(ctx, target, refs[:65], "wifi", now.Unix()+3600, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("ordinary65 used the adaptive quota", err)
	}
	owned := append([]ProfileReference(nil), refs...)
	prepared, err := reader.PrepareAdaptiveSelection(ctx, target, refs, "wifi", now.Unix()+3600, now)
	if err != nil || prepared.validationLimit != 532 || len(prepared.refs) != 532 || len(prepared.profiles) != 532 || len(prepared.Dependencies()) != 1 {
		t.Fatal("adaptive union was truncated or lost its private bound", err)
	}
	refs[0] = ProfileReference{SourceID: "other-source", ProfileID: "other-profile"}
	if prepared.refs[0] != owned[0] {
		t.Fatal("caller mutated prepared references")
	}
	for _, ref := range owned {
		profile, ok := prepared.Profile(ref)
		if !ok || len(profile.Outbound) == 0 {
			t.Fatal("requested adaptive profile omitted")
		}
		profile.Outbound[0] = '!'
		fresh, _ := prepared.Profile(ref)
		if fresh.Outbound[0] != '{' {
			t.Fatal("profile handoff shares mutable buffers")
		}
	}
	if err := lockSelection(t, prepared, now); err != nil {
		t.Fatal("adaptive final fence rejected532", err)
	}
	tooMany := append(append([]ProfileReference(nil), owned...), ProfileReference{SourceID: source.ID, ProfileID: "unassigned-profile"})
	if _, err := reader.PrepareAdaptiveSelection(ctx, target, tooMany, "wifi", now.Unix()+3600, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("533 references accepted", err)
	}
	if _, err := reader.PrepareAdaptiveSelection(ctx, target, append(append([]ProfileReference(nil), owned[:2]...), owned[0]), "wifi", now.Unix()+3600, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate reference accepted", err)
	}
	prepared.validationLimit = 64
	if err := lockSelection(t, prepared, now); !errors.Is(err, ErrDenied) {
		t.Fatal("final fence ignored original selection bound", err)
	}
	prepared.validationLimit = 532
	prepared.refs = tooMany
	if err := lockSelection(t, prepared, now); !errors.Is(err, ErrDenied) {
		t.Fatal("final fence accepted a widened adaptive union", err)
	}
}

func TestSQLAdaptiveSelectionRepeatsSharesModeExpiryAndRevocationAtFinalFence(t *testing.T) {
	api, _, reader, actor, source, _, ref, now := selectionFixture(t)
	ctx := context.Background()
	shares, err := api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Recipients: []Recipient{{Kind: "device", ID: "device-b"}}}, "share-adaptive-selection", now)
	if err != nil {
		t.Fatal(err)
	}
	target := SelectionTarget{Owner: "user-b", Device: "device-b"}
	prepared, err := reader.PrepareAdaptiveSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now)
	if err != nil || prepared.validationLimit != 532 {
		t.Fatal("independently granted adaptive reference denied", err)
	}
	if err := lockSelection(t, prepared, now); err != nil {
		t.Fatal("unchanged source rejected", err)
	}
	for _, other := range []SelectionTarget{{Owner: "user-b", Device: "other-device"}, {Owner: "other-user", Device: "other-device"}} {
		if _, err := reader.PrepareAdaptiveSelection(ctx, other, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); !errors.Is(err, ErrDenied) {
			t.Fatal("adaptive scope broadened a device grant", err)
		}
	}
	if _, err := reader.PrepareAdaptiveSelection(ctx, target, []ProfileReference{ref}, "cellular", now.Unix()+3600, now); !errors.Is(err, ErrDenied) {
		t.Fatal("source enabled only on Wi-Fi was selected on another mode", err)
	}
	if _, err := api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Revision: shares.Revision}, "revoke-adaptive-selection", now); err != nil {
		t.Fatal(err)
	}
	if err := lockSelection(t, prepared, now); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked adaptive share passed final fence", err)
	}
	if _, err := reader.PrepareAdaptiveSelection(ctx, target, []ProfileReference{ref}, "wifi", now.Unix()+3600, now); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked adaptive share produced a new selection", err)
	}
	prepared, err = reader.PrepareAdaptiveSelection(ctx, SelectionTarget{Owner: source.Owner, Device: "device-a"}, []ProfileReference{ref}, "wifi", now.Unix()+3600, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := lockSelection(t, prepared, time.Unix(prepared.ValidUntil(), 0)); !errors.Is(err, ErrDenied) {
		t.Fatal("expired adaptive selection passed final fence", err)
	}
	if _, err := fixtureOwner.Exec(`UPDATE catalog_sources SET state='pending',access_state='revoked' WHERE id=$1`, source.ID); err != nil {
		t.Fatal(err)
	}
	if err := lockSelection(t, prepared, now); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked source passed adaptive final fence", err)
	}
}
