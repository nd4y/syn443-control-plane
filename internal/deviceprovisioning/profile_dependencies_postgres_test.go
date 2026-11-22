//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
)

func TestSQLPublishedReferencesProtectSourceUntilRouteReplacement(t *testing.T) {
	ctx := context.Background()
	n, c, p, publisher := layerPublisherFixture(t)
	store, err := catalog.NewStore(fixtureSourceWorker, bytes.Repeat([]byte{81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker := catalog.Worker{Store: store, Clock: func() time.Time { return n.f.now }}
	refresh := func(operation string, lines []string) catalog.Source {
		t.Helper()
		job, err := n.api.Queue(ctx, n.actor, n.source.ID, n.source.Revision, operation, []byte(strings.Join(lines, "\n")), n.f.now)
		if err != nil {
			t.Fatal(err)
		}
		finished, err := worker.ProcessOne(ctx)
		if err != nil || finished.ID != job.ID || finished.Phase != "succeeded" {
			t.Fatal("source sync did not finish", finished.Phase, err)
		}
		source, err := n.api.GetSource(ctx, n.actor, n.source.ID, n.f.now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}

	lines := []string{
		"http://entry.example.invalid:443#entry", "http://proxy.example.invalid:443",
		"http://one.example.invalid:443", "http://two.example.invalid:443",
		"http://three.example.invalid:443", "http://four.example.invalid:443",
	}
	initial := refresh("chain-feed", lines)
	working, err := n.api.GetSnapshot(ctx, n.actor, n.source.ID, initial.ActiveSnapshot, n.f.now)
	if err != nil || len(working.Profiles) != len(lines) {
		t.Fatal("working feed", err)
	}
	var entry configuration.ProfileReference
	for _, profile := range working.Profiles {
		if profile.Name == "entry" {
			entry = configuration.ProfileReference{SourceID: n.source.ID, ProfileID: profile.ID}
		}
	}
	if entry.ProfileID == "" || entry == n.ref {
		t.Fatal("chain must use distinct entry and exit profiles")
	}
	graph := configuration.Graph{
		Profiles:  map[string]configuration.ProfileReference{"entry": entry, "exit": n.ref},
		Chains:    map[string]configuration.Chain{"tunnel": {DialOrder: []string{"entry", "exit"}}},
		Balancers: map[string]configuration.Balancer{}, Final: "tunnel",
	}
	setGraph := func() {
		t.Helper()
		raw, err := json.Marshal(graph)
		if err != nil {
			t.Fatal(err)
		}
		for i, change := range p.Bundles[0].Layers[0].Changes {
			if change.Path == "/graph" {
				p.Bundles[0].Layers[0].Changes[i].Value = raw
				return
			}
		}
		t.Fatal("missing graph layer")
	}
	setGraph()
	preview := prepareLayerPreview(t, n, c, p, publisher, "initial route preview")
	queueLayerPublish(t, n, c, preview, "initial route publish")
	if err := publisher.RunOnce(ctx, n.f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assertRefs := func(wantEntry, wantExit int) {
		t.Helper()
		var entries, exits int
		if err := fixtureSourceWorker.QueryRow(`SELECT count(*) FILTER(WHERE profile_id=$2), count(*) FILTER(WHERE profile_id=$3)
			FROM catalog_published_references WHERE source_id=$1`, n.source.ID, entry.ProfileID, n.ref.ProfileID).Scan(&entries, &exits); err != nil || entries != wantEntry || exits != wantExit {
			t.Fatal("unexpected published chain dependencies", entries, exits, err)
		}
	}
	assertRefs(1, 1)

	// One missing profile out of six is below the mass-removal threshold.
	n.f.now = n.f.now.Add(2 * time.Second)
	current := refresh("remove-only-entry", lines[1:])
	if current.ActiveSnapshot != initial.ActiveSnapshot || current.CandidateSnapshot == "" {
		t.Fatal("removing the published entry replaced the working feed")
	}
	candidate, err := n.api.GetSnapshot(ctx, n.actor, n.source.ID, current.CandidateSnapshot, n.f.now)
	if err != nil || len(candidate.Profiles) != len(lines)-1 || candidate.Snapshot.State != "quarantined" || candidate.Snapshot.Reason != "referenced_profile_removed" {
		t.Fatal("referenced entry removal escaped quarantine", err)
	}
	next := candidate.Snapshot
	review := catalog.Review{SourceID: current.ID, SourceRevision: current.Revision, Active: current.ActiveSnapshot, Candidate: next.ID, Hash: next.Hash, Approve: true}
	if _, err = n.api.ReviewSnapshot(ctx, n.actor, review, "premature-removal", n.f.now); !errors.Is(err, catalog.ErrConflict) {
		t.Fatal("manual approval removed a live dependency", err)
	}

	// Commit an ordinary replacement before the quarantined candidate can be promoted.
	p.Bundles[0].BaseRevision = 1
	p.Bundles[0].BaseHash = preview.Preview.DraftHash
	p.TargetKind = "template"
	p.TargetID = p.Bundles[0].Layers[0].ID
	p.Bundles[0].Layers[0].Revision = 2
	delete(graph.Profiles, "entry")
	delete(graph.Chains, "tunnel")
	graph.Final = "exit"
	setGraph()
	preview = prepareLayerPreview(t, n, c, p, publisher, "replacement route preview")
	queueLayerPublish(t, n, c, preview, "replacement route publish")
	if err = publisher.RunOnce(ctx, n.f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n.f.now = n.f.now.Add(2 * time.Second)
	assertRefs(0, 1)
	approved, err := n.api.ReviewSnapshot(ctx, n.actor, review, "approved-removal", n.f.now)
	if err != nil || approved.State != "active" {
		t.Fatal("old reference survived current route replacement", err)
	}
	active, err := n.api.GetSource(ctx, n.actor, n.source.ID, n.f.now)
	if err != nil || active.ActiveSnapshot != next.ID || active.CandidateSnapshot != "" {
		t.Fatal("review did not promote the exact candidate", err)
	}
	assertRefs(0, 1)
}

func TestSQLRecoversLegacyConfigurationReferencesWithoutRenewal(t *testing.T) {
	for _, mode := range []string{"static", "adaptive"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			n, c, p, publisher := layerPublisherFixture(t)
			if mode == "adaptive" {
				seedAdaptiveAvailability(t, &n)
				configureAdaptiveNetworkFixture(t, &n, adaptiveAuthorityPlan(t, []configuration.ProfileReference{n.ref}))
				p.Bundles[0].Layers = n.approved.Layers
			}
			preview := prepareLayerPreview(t, n, c, p, publisher, "historical preview")
			queueLayerPublish(t, n, c, preview, "historical publication")
			if err := publisher.RunOnce(ctx, n.f.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var before, after string
			readReceipt := func(dst *string) {
				t.Helper()
				if err := fixtureOwner.QueryRow(`SELECT concat_ws(':',v.revision,v.body_hash,v.approved_at_ms,p.expires_at_ms,d.refresh_after,d.jkt)
					FROM managed_configuration_versions v JOIN managed_configuration_previews p ON p.id=v.preview JOIN identity_devices d ON d.id=v.device WHERE v.device=$1`, n.target.Device).Scan(dst); err != nil {
					t.Fatal(err)
				}
			}
			readReceipt(&before)
			if _, err := fixtureOwner.Exec(`DELETE FROM managed_configuration_profile_refs; UPDATE managed_configuration_heads SET indexed_profile_revision=0`); err != nil {
				t.Fatal(err)
			}
			var unknown bool
			if err := fixtureSourceWorker.QueryRow(`SELECT EXISTS(SELECT FROM catalog_published_references WHERE source_id IS NULL)`).Scan(&unknown); err != nil || !unknown {
				t.Fatal("missing legacy fence", err)
			}
			// An idle normal worker can recover a head after the preview and plan expired.
			if err := publisher.RunOnce(ctx, n.f.now.Add(48*time.Hour)); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := fixtureSourceWorker.QueryRow(`SELECT count(*) FILTER(WHERE source_id=$1 AND profile_id=$2),bool_or(source_id IS NULL)
				FROM catalog_published_references`, n.ref.SourceID, n.ref.ProfileID).Scan(&count, &unknown); err != nil || count != 1 || unknown {
				t.Fatal("historical source scope", err, count, unknown)
			}
			readReceipt(&after)
			if before != after {
				t.Fatal("backfill changed an approval, device or clock")
			}
		})
	}
}
