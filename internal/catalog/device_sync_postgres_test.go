//go:build postgres

package catalog

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestSQLDeviceFetchLeaseUploadAndSelectionStayBoundToOneDevice(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := sourceExample(now)
	source.Mode = "device"
	source.FetchDeviceID = "bound-device"
	credential := SecretPatch{Operation: "replace", Value: []byte(`{"url":"https://subscription.example.invalid"}`)}
	var err error
	source, err = api.PutSource(ctx, actor, source, credential, "bound-source", now)
	if err != nil {
		t.Fatal(err)
	}
	withTx := func(action func(*sql.Tx) error) error {
		t.Helper()
		tx, e := fixtureWorker.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if e = action(tx); e != nil {
			return e
		}
		return tx.Commit()
	}
	var queued Job
	if err = withTx(func(tx *sql.Tx) error {
		var e error
		queued, e = worker.enqueue(ctx, tx, source, "source-scheduler", "device-fetch", "scheduled", nil, now.Unix())
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if job, e := worker.Claim(ctx, now); e != nil || job.ID != "" {
		t.Fatal("server parser claimed a device fetch before upload", e)
	}
	claim := func(scope DeviceFetchScope, at time.Time) DeviceFetchLease {
		t.Helper()
		var result DeviceFetchLease
		if e := withTx(func(tx *sql.Tx) error {
			var e error
			result, e = worker.ClaimDeviceFetch(ctx, tx, scope, at)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		return result
	}
	owner := DeviceFetchScope{source.Owner, source.FetchDeviceID}
	otherDevice := DeviceFetchScope{source.Owner, "other-device"}
	if claim(otherDevice, now).JobID != "" || claim(DeviceFetchScope{"another-owner", source.FetchDeviceID}, now).JobID != "" {
		t.Fatal("device fetch credential escaped its owner/device")
	}
	first := claim(owner, now)
	if first.JobID != queued.ID || first.Lease == "" || first.Credential.URL != "https://subscription.example.invalid" ||
		claim(owner, now.Add(time.Second)).Lease != first.Lease {
		t.Fatal("lost claim reply created another lease or wrong source")
	}
	late := now.Add(time.Minute)
	second := claim(owner, late)
	if second.JobID != queued.ID || second.Lease == "" || second.Lease == first.Lease {
		t.Fatal("expired lease not renewed independently")
	}
	raw := []byte("http://node.example.invalid:443")
	accept := func(scope DeviceFetchScope, lease string, body []byte) error {
		return withTx(func(tx *sql.Tx) error { return worker.AcceptDeviceFetch(ctx, tx, scope, queued.ID, lease, body, late) })
	}
	if !errors.Is(accept(otherDevice, second.Lease, raw), ErrDenied) || !errors.Is(accept(owner, first.Lease, raw), ErrStale) {
		t.Fatal("old lease or foreign device accepted")
	}
	if e := accept(owner, second.Lease, raw); e != nil {
		t.Fatal(e)
	}
	if e := accept(owner, second.Lease, raw); e != nil || !errors.Is(accept(owner, second.Lease, []byte("changed")), ErrConflict) {
		t.Fatal("upload receipt did not fence retries", e)
	}
	var protected []byte
	if e := fixtureOwner.QueryRow(`SELECT payload FROM catalog_jobs WHERE id=$1`, queued.ID).Scan(&protected); e != nil ||
		len(protected) <= len(raw) || bytes.Contains(protected, raw) {
		t.Fatal("uploaded data not protected", e)
	}
	processed, e := (&Worker{Store: worker, Clock: func() time.Time { return late }}).ProcessOne(ctx)
	if e != nil || processed.ID != queued.ID || processed.Phase != "succeeded" {
		t.Fatal("existing worker did not normalize device upload", e)
	}
	if e = accept(owner, second.Lease, raw); e != nil {
		t.Fatal("normalized job lost its idempotent receipt", e)
	}
	var erased bool
	if e = fixtureOwner.QueryRow(`SELECT payload IS NULL FROM catalog_jobs WHERE id=$1`, queued.ID).Scan(&erased); e != nil || !erased {
		t.Fatal("terminal raw input not erased", e)
	}
	snapshot, e := api.GetSnapshot(ctx, actor, source.ID, "", late)
	if e != nil || snapshot.Snapshot.ID == "" || len(snapshot.Profiles) != 1 {
		t.Fatal("no normalized snapshot", e)
	}
	if _, e = fixtureAPI.Exec(`UPDATE catalog_sources SET fetch_device_id='replacement-device' WHERE id=$1`, source.ID); e == nil {
		t.Fatal("direct update rebound the source")
	}
	reader := *worker
	reader.DB = fixturePublisher
	ref := ProfileReference{source.ID, snapshot.Profiles[0].ID}
	if _, e = reader.PrepareSelection(ctx, SelectionTarget{source.Owner, owner.Device}, []ProfileReference{ref},
		"wifi", late.Add(time.Minute).Unix(), late); e != nil {
		t.Fatal("bound device could not use the normalized source", e)
	}
	if _, e = reader.PrepareSelection(ctx, SelectionTarget{source.Owner, otherDevice.Device}, []ProfileReference{ref},
		"wifi", late.Add(time.Minute).Unix(), late); !errors.Is(e, ErrDenied) {
		t.Fatal("other device of the same owner consumed a personal source", e)
	}
}
