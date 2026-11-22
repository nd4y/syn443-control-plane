//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func TestSQLPublishedReferencesProtectSourceUntilRouteReplacement(t *testing.T) {
	ctx := context.Background()
	n, c, p, publisher := layerPublisherFixture(t)
	preview := prepareLayerPreview(t, n, c, p, publisher, "initial route preview")
	queueLayerPublish(t, n, c, preview, "initial route publish")
	if err := publisher.RunOnce(ctx, n.f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var refs int
	if err := fixtureSourceWorker.QueryRow(`SELECT count(*) FROM catalog_published_references WHERE source_id=$1 AND profile_id=$2`, n.ref.SourceID, n.ref.ProfileID).Scan(&refs); err != nil || refs != 1 {
		t.Fatal("actual selected profile was not recorded exactly once", err, refs)
	}

	n.f.now = n.f.now.Add(2 * time.Second)
	worker, err := catalog.NewStore(fixtureSourceWorker, bytes.Repeat([]byte{81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	queued, err := n.api.Queue(ctx, n.actor, n.source.ID, n.source.Revision, "new-feed", []byte("http://replacement.example.invalid:443"), n.f.now)
	if err != nil {
		t.Fatal(err)
	}
	job, err := worker.Claim(ctx, n.f.now)
	if err != nil || job.ID != queued.ID {
		t.Fatal("new feed job", err)
	}
	input, salt, _, raw, err := worker.JobInput(ctx, job, n.f.now)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := subscriptions.Import(input.ID, salt, input.Format, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, err := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, n.f.now)
	if err != nil || next.State != "quarantined" || next.Reason != "referenced_profile_removed" {
		t.Fatal("selected profile removal escaped quarantine", err, next.State, next.Reason)
	}
	current, err := n.api.GetSource(ctx, n.actor, n.source.ID, n.f.now)
	if err != nil {
		t.Fatal(err)
	}
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
	for i, change := range p.Bundles[0].Layers[0].Changes {
		if change.Path == "/graph" {
			p.Bundles[0].Layers[0].Changes[i].Value = json.RawMessage(`{"profiles":{},"chains":{},"balancers":{},"final":"direct"}`)
		}
	}
	preview = prepareLayerPreview(t, n, c, p, publisher, "replacement route preview")
	queueLayerPublish(t, n, c, preview, "replacement route publish")
	if err = publisher.RunOnce(ctx, n.f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n.f.now = n.f.now.Add(2 * time.Second)
	approved, err := n.api.ReviewSnapshot(ctx, n.actor, review, "approved-removal", n.f.now)
	if err != nil || approved.State != "active" {
		t.Fatal("old reference survived current route replacement", err)
	}
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
