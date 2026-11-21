package catalog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func TestSQLSnapshotViewPreservesProviderCounterPrecisionAndObservation(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	const profile = "http://one.example.invalid:443"
	job, profiles := manualWork(t, api, worker, actor, source, "first", profile, now)
	first, err := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := api.GetSnapshot(ctx, actor, source.ID, first.ID, now)
	if err != nil || unknown.TrafficBytes != nil {
		t.Fatal("unknown counters acquired a value", err)
	}
	quota := subscriptions.Quota{Known: true, Used: 18446744073709551614, Limit: 18446744073709551615, ObservedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	after := now.Add(time.Minute)
	job, profiles = manualWork(t, api, worker, actor, source, "next", profile, after)
	if _, err = worker.Complete(ctx, job, profiles, quota, subscriptions.Cache{}, after); err != nil {
		t.Fatal(err)
	}
	later := after.Add(time.Minute)
	job, profiles = manualWork(t, api, worker, actor, source, "refresh", profile, later)
	if _, err = worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, later); err != nil {
		t.Fatal(err)
	}
	view, err := api.GetSnapshot(ctx, actor, source.ID, "", later)
	if err != nil || view.TrafficBytes == nil {
		t.Fatal("missing authoritative counters", err)
	}
	if *view.TrafficBytes != (SnapshotTrafficBytes{"18446744073709551614", "18446744073709551615"}) ||
		view.Snapshot.Quota != quota || view.Snapshot.ObservedAt != later.Unix() {
		t.Fatal("lost provider precision or observation time")
	}
	other := actor
	other.ID = "unassigned-reader"
	if _, err = api.GetSnapshot(ctx, other, source.ID, "", later); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign reader observed provider counters", err)
	}
}
