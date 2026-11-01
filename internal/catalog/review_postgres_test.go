//go:build postgres

package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func TestSQLScopedSharesCASAndDeviceSourceIsolation(t *testing.T) {
	api, _, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	shares, e := api.GetShares(ctx, actor, source.ID, now)
	if e != nil || shares.Revision != 0 || len(shares.Recipients) != 0 {
		t.Fatal("default sharing", e)
	}
	draft := Shares{Recipients: []Recipient{{Kind: "user", ID: "user-b"}, {Kind: "group", ID: "group-a"}}}
	noMFA := actor
	noMFA.MFAUntil = now.Unix()
	if _, e = api.SetShares(ctx, noMFA, source.ID, source.Revision, draft, "no-assurance", now); !errors.Is(e, ErrDenied) {
		t.Fatal("sharing without fresh assurance")
	}
	created, e := api.SetShares(ctx, actor, source.ID, source.Revision, draft, "share", now)
	if e != nil || created.Revision != 1 {
		t.Fatal(e)
	}
	retry, e := api.SetShares(ctx, actor, source.ID, source.Revision, draft, "share", now)
	if e != nil || retry.Revision != 1 {
		t.Fatal("sharing lost reply", e)
	}
	if _, e = api.SetShares(ctx, actor, source.ID, source.Revision, draft, "stale", now); !errors.Is(e, ErrConflict) {
		t.Fatal("sharing stale revision")
	}
	if _, e = api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Revision: 1, Recipients: []Recipient{{Kind: "user", ID: "user-b"}, {Kind: "user", ID: "user-b"}}}, "duplicates", now); !errors.Is(e, ErrInvalid) {
		t.Fatal("duplicate recipients")
	}
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'sources.share','user',$2,$3)`, actor.ID, source.Owner, now.Add(time.Hour).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = api.SetShares(ctx, actor, source.ID, source.Revision, Shares{Revision: 1, Recipients: []Recipient{{Kind: "device", ID: "unowned-device"}}}, "no-recipient-right", now); !errors.Is(e, ErrDenied) {
		t.Fatal("source-write authority became recipient authority")
	}
	read, e := api.GetShares(ctx, actor, source.ID, now)
	if e != nil || read.Revision != 1 || len(read.Recipients) != 2 {
		t.Fatal("denied share partially committed", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE catalog_acl SET action='*',target_kind='*',target_id='*' WHERE actor=$1`, actor.ID); e != nil {
		t.Fatal(e)
	}
	device := sourceExample(now)
	device.ID = "personal-device-source"
	device.Mode = "device"
	device, e = api.PutSource(ctx, actor, device, SecretPatch{Operation: "replace", Value: []byte(`{"url":"https://subscription.example.invalid"}`)}, "create-device-source", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = api.SetShares(ctx, actor, device.ID, device.Revision, Shares{Recipients: []Recipient{{Kind: "user", ID: "other-user"}}}, "share-untrusted-device-data", now); !errors.Is(e, ErrDenied) {
		t.Fatal("device-fetched source escaped personal scope")
	}
	if _, e = api.SetShares(ctx, actor, device.ID, device.Revision, Shares{Recipients: []Recipient{{Kind: "user", ID: device.Owner}}}, "keep-personal", now); e != nil {
		t.Fatal(e)
	}
}

func TestSQLCandidateReviewIsExplicitAndCannotBreakReferences(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	lines := []string{"http://one.example.invalid:443", "http://two.example.invalid:443", "http://three.example.invalid:443"}
	job, profiles := manualWork(t, api, worker, actor, source, "first", strings.Join(lines, "\n"), now)
	first, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
	if e != nil {
		t.Fatal(e)
	}
	job, profiles = manualWork(t, api, worker, actor, source, "candidate", lines[0], now)
	candidate, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
	if e != nil || candidate.State != "quarantined" {
		t.Fatal(e)
	}
	review := Review{SourceID: source.ID, SourceRevision: source.Revision, Candidate: candidate.ID, Hash: candidate.Hash, Active: first.ID, Approve: true}
	noMFA := actor
	noMFA.MFAUntil = now.Unix()
	if _, e = api.ReviewSnapshot(ctx, noMFA, review, "no-mfa", now); !errors.Is(e, ErrDenied) {
		t.Fatal("unconfirmed mass removal")
	}
	wrong := review
	wrong.Active = "stale-head"
	if _, e = api.ReviewSnapshot(ctx, actor, wrong, "wrong-head", now); !errors.Is(e, ErrConflict) {
		t.Fatal("review ignored head CAS")
	}
	oldProfiles, e := subscriptions.Import(source.ID, func() []byte {
		var salt []byte
		if e := fixtureOwner.QueryRow(`SELECT salt FROM catalog_sources WHERE id=$1`, source.ID).Scan(&salt); e != nil {
			t.Fatal(e)
		}
		return salt
	}(), "uri", []byte(strings.Join(lines, "\n")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO catalog_dependencies(owner,layer_id,layer_revision,source_id,profile_id) VALUES($1,'layer-a',1,$2,$3)`, source.Owner, source.ID, oldProfiles[1].ID); e != nil {
		t.Fatal(e)
	}
	if _, e = api.ReviewSnapshot(ctx, actor, review, "broken-reference", now); !errors.Is(e, ErrConflict) {
		t.Fatal("review allowed dangling profile reference", e)
	}
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_dependencies`); e != nil {
		t.Fatal(e)
	}
	approved, e := api.ReviewSnapshot(ctx, actor, review, "approve", now)
	if e != nil || approved.State != "active" {
		t.Fatal(e)
	}
	if retry, e := api.ReviewSnapshot(ctx, actor, review, "approve", now); e != nil || retry.ID != candidate.ID {
		t.Fatal("review lost reply", e)
	}
	read, e := api.GetSource(ctx, actor, source.ID, now)
	if e != nil || read.ActiveSnapshot != candidate.ID || read.CandidateSnapshot != "" {
		t.Fatal("review head not committed", e)
	}
	job, profiles = manualWork(t, api, worker, actor, source, "new-large", strings.Join(lines, "\n"), now)
	large, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
	if e != nil {
		t.Fatal(e)
	}
	job, profiles = manualWork(t, api, worker, actor, source, "new-candidate", lines[0], now)
	candidate, e = worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
	if e != nil {
		t.Fatal(e)
	}
	review = Review{SourceID: source.ID, SourceRevision: source.Revision, Candidate: candidate.ID, Hash: candidate.Hash, Active: large.ID, Approve: false}
	if rejected, e := api.ReviewSnapshot(ctx, actor, review, "reject", now); e != nil || rejected.State != "rejected" {
		t.Fatal(e)
	}
	read, e = api.GetSource(ctx, actor, source.ID, now)
	if e != nil || read.ActiveSnapshot != large.ID || read.State != "review_rejected" {
		t.Fatal("rejection replaced working head", e)
	}
}
