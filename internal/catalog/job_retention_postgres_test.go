//go:build postgres

package catalog

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

func assertRetiredInput(t *testing.T, id, phase string) {
	t.Helper()
	var actual, lease string
	var empty bool
	var until int64
	if e := fixtureOwner.QueryRow(`SELECT phase,payload IS NULL,lease,lease_until FROM catalog_jobs WHERE id=$1`, id).Scan(&actual, &empty, &lease, &until); e != nil || actual != phase || !empty || lease != "" || until != 0 {
		t.Fatal("terminal input or lease retained", actual, empty, until, e)
	}
}

func TestSQLTerminalJobsEraseRawInputButKeepIdempotentReceipts(t *testing.T) {
	for _, mode := range []string{"success", "permanent", "cancel", "abandon", "source-change", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			api, worker, actor, now := databaseFixture(t)
			ctx := context.Background()
			source := mustSource(t, api, actor, sourceExample(now), "create", now)
			raw := []byte("http://proxy.example.invalid:443")
			queued, e := api.Queue(ctx, actor, source.ID, source.Revision, "original-input", raw, now)
			if e != nil {
				t.Fatal(e)
			}
			job, e := worker.Claim(ctx, now)
			if e != nil || job.ID != queued.ID {
				t.Fatal("claim", e)
			}
			var phase string
			switch mode {
			case "success":
				_, salt, _, input, err := worker.JobInput(ctx, job, now)
				if err != nil {
					t.Fatal(err)
				}
				profiles, err := subscriptions.Import(source.ID, salt, source.Format, input)
				if err != nil {
					t.Fatal(err)
				}
				_, e = worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
				phase = "succeeded"
			case "permanent":
				e = worker.Fail(ctx, job, "subscription_invalid", true, now)
				phase = "failed"
			case "cancel":
				e = api.Cancel(ctx, actor, job.ID, "cancel", now)
				phase = "cancelled"
			case "abandon":
				e = worker.Abandon(ctx, job, now)
				phase = "cancelled"
			case "source-change":
				source.Name = "changed"
				_, e = api.PutSource(ctx, actor, source, SecretPatch{Operation: "keep"}, "edit-source", now)
				phase = "cancelled"
			case "deadline":
				_, e = worker.Claim(ctx, now.Add(901*time.Second))
				phase = "dead_letter"
			}
			if e != nil {
				t.Fatal(e)
			}
			assertRetiredInput(t, job.ID, phase)
			replay, e := api.Queue(ctx, actor, source.ID, 1, "original-input", raw, now.Add(time.Second))
			if e != nil || replay.ID != job.ID || replay.Phase != phase {
				t.Fatal("terminal replay changed identity", e)
			}
			if _, _, _, _, e = worker.JobInput(ctx, job, now); !errors.Is(e, ErrStale) {
				t.Fatal("terminal lease still readable", e)
			}
			if _, e = fixtureWorker.Exec(`UPDATE catalog_jobs SET phase='queued',payload='reintroduced' WHERE id=$1`, job.ID); e == nil {
				t.Fatal("terminal input resurrected")
			}
			if _, e = fixtureAPI.Exec(`UPDATE catalog_jobs SET payload='reintroduced',lease='old',lease_until=99 WHERE id=$1`, job.ID); e != nil {
				t.Fatal(e)
			}
			assertRetiredInput(t, job.ID, phase)
		})
	}
}

func TestSQLRetryKeepsEncryptedInputAndOldLeaseCannotEraseNewWork(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	raw := []byte("http://proxy.example.invalid:443")
	job, e := api.Queue(ctx, actor, source.ID, source.Revision, "input", raw, now)
	if e != nil {
		t.Fatal(e)
	}
	job, e = worker.Claim(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = worker.Fail(ctx, job, "subscription_fetch_unavailable", false, now); e != nil {
		t.Fatal(e)
	}
	next, e := worker.Claim(ctx, now.Add(6*time.Second))
	if e != nil || next.ID != job.ID || next.Lease == job.Lease {
		t.Fatal("retry lease", e)
	}
	if e = worker.Abandon(ctx, job, now.Add(6*time.Second)); e != nil {
		t.Fatal(e)
	}
	_, _, _, input, e := worker.JobInput(ctx, next, now.Add(6*time.Second))
	if e != nil || string(input) != string(raw) {
		t.Fatal("retry input erased", e)
	}
	var cipher []byte
	if e = fixtureOwner.QueryRow(`SELECT payload FROM catalog_jobs WHERE id=$1`, job.ID).Scan(&cipher); e != nil || string(cipher) == string(raw) {
		t.Fatal("retry input was not protected", e)
	}
}

func TestSQLLegacyTerminalInputCleanupIsBoundedAndDoesNotTouchQueuedInput(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	job, e := api.Queue(ctx, actor, source.ID, source.Revision, "live", []byte("http://proxy.example.invalid:443"), now)
	if e != nil {
		t.Fatal(e)
	}
	// Model rows created before this owner migration, only inside the isolated SQL fixture.
	if _, e = fixtureOwner.Exec(`ALTER TABLE catalog_jobs DISABLE TRIGGER catalog_terminal_input_guard`); e != nil {
		t.Fatal(e)
	}
	func() {
		defer func() {
			if _, err := fixtureOwner.Exec(`ALTER TABLE catalog_jobs ENABLE TRIGGER catalog_terminal_input_guard`); err != nil {
				t.Fatal(err)
			}
		}()
		for i := 0; i < 33; i++ {
			_, e = fixtureOwner.Exec(`INSERT INTO catalog_jobs(id,source_id,source_revision,kind,request_id,actor,body_hash,phase,not_before,deadline,payload,created_at,updated_at,lease,lease_until) SELECT $1,source_id,source_revision,kind,$1,actor,body_hash,'failed',not_before,deadline,payload,created_at,updated_at,'old',99 FROM catalog_jobs WHERE id=$2`, fmt.Sprintf("legacy-%02d", i), job.ID)
			if e != nil {
				t.Fatal(e)
			}
		}
	}()
	claimed, e := worker.Claim(ctx, now)
	if e != nil || claimed.ID != job.ID {
		t.Fatal("live work starved", e)
	}
	var remaining int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_jobs WHERE phase='failed' AND payload IS NOT NULL`).Scan(&remaining); e != nil || remaining != 1 {
		t.Fatal("cleanup was not bounded to32", remaining, e)
	}
	if _, _, _, _, e = worker.JobInput(ctx, claimed, now); e != nil {
		t.Fatal("live input erased", e)
	}
	if _, e = worker.Claim(ctx, now); e != nil {
		t.Fatal(e)
	}
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_jobs WHERE phase='failed' AND (payload IS NOT NULL OR lease<>'' OR lease_until<>0)`).Scan(&remaining); e != nil || remaining != 0 {
		t.Fatal("legacy cleanup incomplete", remaining, e)
	}
}
