//go:build postgres

package catalog

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

var fixtureOwner, fixtureAPI, fixtureWorker *sql.DB

func TestMain(m *testing.M) {
	dsn := os.Getenv("SYN443_TEST_DATABASE")
	u, e := url.Parse(dsn)
	if e != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" {
		panic("owned loopback SQL fixture required")
	}
	fixtureOwner, e = sql.Open("pgx", dsn)
	if e != nil {
		panic("catalog fixture connection")
	}
	if _, e = fixtureOwner.Exec(Schema); e != nil {
		panic(e)
	}
	for _, role := range []struct {
		name   string
		target **sql.DB
	}{{"syn443_control_api", &fixtureAPI}, {"syn443_source_worker", &fixtureWorker}} {
		password, e := random()
		if e != nil {
			panic("fixture entropy")
		}
		var statement string
		if e = fixtureOwner.QueryRow(`SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOBYPASSRLS PASSWORD %L',$1::text,$2::text)`, role.name, password).Scan(&statement); e != nil {
			panic("fixture role declaration")
		}
		if _, e = fixtureOwner.Exec(statement); e != nil {
			panic("fixture role creation")
		}
		copy := *u
		copy.User = url.UserPassword(role.name, password)
		*role.target, e = sql.Open("pgx", copy.String())
		if e != nil {
			panic("fixture restricted connection")
		}
		(*role.target).SetMaxOpenConns(4)
	}
	if _, e = fixtureOwner.Exec(Roles); e != nil {
		panic(e)
	}
	code := m.Run()
	fixtureWorker.Close()
	fixtureAPI.Close()
	fixtureOwner.Close()
	os.Exit(code)
}
func databaseFixture(t *testing.T) (*Store, *Store, Actor, time.Time) {
	t.Helper()
	if _, e := fixtureOwner.Exec(`TRUNCATE catalog_proofs,catalog_outbox,catalog_audit,catalog_operations,catalog_jobs,catalog_dependencies,catalog_snapshots,catalog_share_heads,catalog_source_grants,catalog_sources,catalog_resources,catalog_acl RESTART IDENTITY CASCADE`); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE catalog_clock SET second=0 WHERE id=true`); e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal("fixture entropy")
	}
	api, e := NewStore(fixtureAPI, key)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := NewStore(fixtureWorker, key)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	actor := Actor{ID: "synthetic-admin", SessionUntil: now.Add(3 * time.Hour).Unix(), MFAUntil: now.Add(10 * time.Minute).Unix()}
	if _, e = fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'*','*','*',$2)`, actor.ID, now.Add(24*time.Hour).Unix()); e != nil {
		t.Fatal(e)
	}
	return api, worker, actor, now
}
func mustSource(t *testing.T, s *Store, a Actor, source Source, request string, now time.Time) Source {
	t.Helper()
	source.State = ""
	source.ActiveSnapshot = ""
	source.CandidateSnapshot = ""
	source.LastSync = 0
	source.NextSync = 0
	source.LastResourceRevision = 0
	source.AccessState = ""
	v, e := s.PutSource(context.Background(), a, source, SecretPatch{Operation: "keep"}, request, now)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func manualWork(t *testing.T, api, worker *Store, actor Actor, source Source, request, raw string, now time.Time) (Job, []subscriptions.Profile) {
	t.Helper()
	ctx := context.Background()
	queued, e := api.Queue(ctx, actor, source.ID, source.Revision, request, []byte(raw), now)
	if e != nil {
		t.Fatal(e)
	}
	job, e := worker.Claim(ctx, now)
	if e != nil || job.ID != queued.ID {
		t.Fatal("job not claimed")
	}
	input, salt, _, payload, e := worker.JobInput(ctx, job, now)
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := subscriptions.Import(input.ID, salt, input.Format, payload)
	if e != nil {
		t.Fatal(e)
	}
	return job, profiles
}
func TestSQLSourcePersistenceRoleSeparationAndIdempotency(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	if api.RuntimeRole(ctx, false) != nil || worker.RuntimeRole(ctx, true) != nil || api.RuntimeRole(ctx, true) == nil {
		t.Fatal("runtime role guard")
	}
	source := sourceExample(now)
	created := mustSource(t, api, actor, source, "create-1", now)
	again, e := api.PutSource(ctx, actor, source, SecretPatch{Operation: "keep"}, "create-1", now)
	if e != nil || again.Revision != 1 || again.ID != created.ID {
		t.Fatal("lost response created another revision")
	}
	read, e := api.GetSource(ctx, actor, source.ID, now)
	if e != nil || read.Name != source.Name || read.Revision != 1 || read.State != "pending" {
		t.Fatal("source readback")
	}
	ordinary := Actor{ID: "synthetic-user", SessionUntil: actor.SessionUntil, MFAUntil: actor.MFAUntil}
	if _, e = api.GetSource(ctx, ordinary, source.ID, now); !errors.Is(e, ErrDenied) {
		t.Fatal("ordinary token became administrator")
	}
	if _, e = fixtureWorker.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES('forged','*','*','*',1)`); e == nil {
		t.Fatal("worker granted authority")
	}
	if _, e = fixtureAPI.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES('forged','*','*','*',1)`); e == nil {
		t.Fatal("API self-granted authority")
	}
	if _, e = fixtureWorker.Exec(`INSERT INTO catalog_audit(actor,action,target,request_id,observed_at,before_hash,after_hash,outcome) VALUES('forged','forged','','',1,'','','')`); e == nil {
		t.Fatal("worker impersonated administrator")
	}
	if _, e = fixtureAPI.Exec(`UPDATE catalog_sources SET owner='forged' WHERE id=$1`, source.ID); e == nil {
		t.Fatal("immutable source owner")
	}
	source.Name = "Changed"
	if _, e = api.PutSource(ctx, actor, source, SecretPatch{Operation: "keep"}, "create-1", now); !errors.Is(e, ErrConflict) {
		t.Fatal("operation request reused for another body")
	}
}
func TestSQLWorkingSnapshotAndQuarantinePreserveLastGood(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	base := sourceExample(now)
	base.ValidUntil = now.Add(72 * time.Hour).Unix()
	base.MaxStaleSeconds = 3600
	source := mustSource(t, api, actor, base, "create-1", now)
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, fmt.Sprintf("http://node%d.example.invalid:443", i))
	}
	job, profiles := manualWork(t, api, worker, actor, source, "import-1", strings.Join(lines, "\n"), now)
	first, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{ETag: `"working"`}, now)
	if e != nil || first.State != "active" {
		t.Fatal("first promotion")
	}
	read, e := api.GetSource(ctx, actor, source.ID, now)
	if e != nil || read.ActiveSnapshot != first.ID || read.State != "active" {
		t.Fatal("active snapshot readback")
	}
	job, profiles = manualWork(t, api, worker, actor, source, "import-2", strings.Join(lines[:3], "\n"), now.Add(time.Second))
	second, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now.Add(time.Second))
	if e != nil || second.State != "quarantined" || second.Reason != "excessive_removal" {
		t.Fatal("candidate not quarantined")
	}
	read, e = api.GetSource(ctx, actor, source.ID, now.Add(time.Second))
	if e != nil || read.ActiveSnapshot != first.ID || read.CandidateSnapshot != second.ID {
		t.Fatal("last good replaced by quarantine")
	}
	if _, e = fixtureWorker.Exec(`UPDATE catalog_snapshots SET content_hash='forged' WHERE id=$1`, first.ID); e == nil {
		t.Fatal("snapshot mutated")
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_outbox`).Scan(&count); e != nil || count != 2 {
		t.Fatal("transactional outbox")
	}
	// Stale data is never presented as fresh solely because its row exists.
	if _, e = fixtureOwner.Exec(`UPDATE catalog_sources SET state='active' WHERE id=$1`, source.ID); e != nil {
		t.Fatal(e)
	}
	read, e = api.GetSource(ctx, actor, source.ID, now.Add(3601*time.Second))
	if e != nil || read.State != "stale" {
		t.Fatalf("expired snapshot state=%q error=%v", read.State, e)
	}
}
func TestSQLReferenceRemovalAndConfirmedExpiry(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	raw := "http://one.example.invalid:443\nhttp://two.example.invalid:443"
	job, profiles := manualWork(t, api, worker, actor, source, "import", raw, now)
	first, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{Known: true, Limit: 100, Used: 1, ExpiresAt: now.Add(time.Hour).Unix()}, subscriptions.Cache{}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`INSERT INTO catalog_dependencies(owner,layer_id,layer_revision,source_id,profile_id) VALUES($1,'layer-a',1,$2,$3)`, source.Owner, source.ID, profiles[1].ID); e != nil {
		t.Fatal(e)
	}
	job, profiles = manualWork(t, api, worker, actor, source, "remove", strings.Split(raw, "\n")[0], now.Add(time.Second))
	candidate, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now.Add(time.Second))
	if e != nil || candidate.Reason != "referenced_profile_removed" {
		t.Fatal("referenced dependency not fenced")
	}
	if candidate.ValidUntil != first.ValidUntil {
		t.Fatal("missing quota header extended provider expiry")
	}
	job, _ = manualWork(t, api, worker, actor, source, "expired", raw, now.Add(2*time.Second))
	if e = worker.Fail(ctx, job, "subscription_expired", true, now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	read, e := api.GetSource(ctx, actor, source.ID, now.Add(2*time.Second))
	if e != nil || read.State != "expired" || read.ActiveSnapshot != first.ID {
		t.Fatal("confirmed expiry is not ordinary cached success")
	}
}
func TestSQLLateWorkersCancelAndSourceChangesCannotCommit(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	other := sourceExample(now)
	other.ID = "source-b"
	other = mustSource(t, api, actor, other, "create-b", now)
	job, profiles := manualWork(t, api, worker, actor, source, "import", "http://proxy.example.invalid:443", now)
	forged := job
	forged.SourceID = other.ID
	if _, _, _, _, e := worker.JobInput(ctx, forged, now); !errors.Is(e, ErrStale) {
		t.Fatal("lease crossed sources")
	}
	if e := api.Cancel(ctx, actor, job.ID, "cancel", now); e != nil {
		t.Fatal(e)
	}
	if _, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now); !errors.Is(e, ErrStale) {
		t.Fatal("cancelled late success committed")
	}
	job, profiles = manualWork(t, api, worker, actor, source, "import-2", "http://proxy.example.invalid:443", now)
	draft := source
	draft.Name = "New metadata"
	draft = mustSource(t, api, actor, draft, "edit", now)
	if _, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now); !errors.Is(e, ErrStale) {
		t.Fatal("old source revision committed")
	}
	read, e := api.GetSource(ctx, actor, source.ID, now)
	if e != nil || read.Revision != draft.Revision || read.ActiveSnapshot != "" {
		t.Fatal("source edit overwritten")
	}
}
func TestSQLLeaseReclaimAndLostQueueResponse(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	raw := []byte("http://proxy.example.invalid:443")
	first, e := api.Queue(ctx, actor, source.ID, source.Revision, "queue", raw, now)
	if e != nil {
		t.Fatal(e)
	}
	repeat, e := api.Queue(ctx, actor, source.ID, source.Revision, "queue", raw, now)
	if e != nil || repeat.ID != first.ID {
		t.Fatal("duplicate queued work")
	}
	old, e := worker.Claim(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	next, e := worker.Claim(ctx, now.Add(61*time.Second))
	if e != nil || next.ID != old.ID || next.Lease == old.Lease || next.Attempts != 2 {
		t.Fatal("crash lease not reclaimed")
	}
	if _, _, _, _, e = worker.JobInput(ctx, old, now.Add(62*time.Second)); !errors.Is(e, ErrStale) {
		t.Fatal("retired lease resurrected")
	}
	if e = worker.Abandon(ctx, old, now.Add(62*time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, _, _, _, e = worker.JobInput(ctx, next, now.Add(62*time.Second)); e != nil {
		t.Fatal("old worker cancelled new lease")
	}
	_, salt, _, payload, e := worker.JobInput(ctx, next, now.Add(62*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := subscriptions.Import(source.ID, salt, source.Format, payload)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Complete(ctx, next, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now.Add(62*time.Second)); e != nil {
		t.Fatal(e)
	}
}
func TestSQLConcurrentScheduleAndClaimsDoNotDuplicate(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := sourceExample(now)
	source.Mode = "server"
	secret, _ := json.Marshal(FetchCredential{URL: "https://proxy.example.invalid/subscription"})
	source, e := api.PutSource(ctx, actor, source, SecretPatch{Operation: "replace", Value: secret}, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := worker.Schedule(ctx, now); errs <- e }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_jobs WHERE source_id=$1`, source.ID).Scan(&count); e != nil || count != 1 {
		t.Fatal("scheduler created duplicate jobs")
	}
	claims := make(chan Job, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, e := worker.Claim(ctx, now)
			if e != nil {
				t.Error(e)
			}
			claims <- j
		}()
	}
	wg.Wait()
	close(claims)
	claimed := 0
	for j := range claims {
		if j.ID != "" {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatal("job had multiple concurrent owners")
	}
	// Plain source/credential values cannot be recovered from the stored records.
	var spec, stored []byte
	if e = fixtureOwner.QueryRow(`SELECT spec,secrets FROM catalog_sources WHERE id=$1`, source.ID).Scan(&spec, &stored); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(stored, []byte("proxy.example.invalid")) || bytes.Contains(spec, []byte("Synthetic source")) {
		t.Fatal("unencrypted source state")
	}
}

func TestSQLProtectedCacheAndSourceCredentialsRemainScoped(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	job, profiles := manualWork(t, api, worker, actor, source, "first", "http://proxy.example.invalid:443", now)
	cache, meta, old, e := worker.SyncCache(ctx, job, now)
	if e != nil || cache.ETag != "" || meta.ID != "" || len(old) != 0 {
		t.Fatal("empty cache became known")
	}
	first, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{ETag: `"cached-version"`}, now)
	if e != nil {
		t.Fatal(e)
	}
	job, _ = manualWork(t, api, worker, actor, source, "next", "http://proxy.example.invalid:443", now.Add(time.Second))
	cache, meta, old, e = worker.SyncCache(ctx, job, now.Add(time.Second))
	if e != nil || cache.ETag != `"cached-version"` || meta.ID != first.ID || len(old) != 1 {
		t.Fatal("working cache lost its source snapshot")
	}
	if e = api.Cancel(ctx, actor, job.ID, "cancel", now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = worker.SyncCache(ctx, job, now.Add(time.Second)); !errors.Is(e, ErrStale) {
		t.Fatal("cancelled cache reader")
	}
	server := sourceExample(now)
	server.ID = "server-source"
	server.Mode = "server"
	credential, _ := json.Marshal(FetchCredential{URL: "https://proxy.example.invalid/subscription", Headers: map[string]string{"Authorization": "Bearer synthetic-only"}})
	server, e = api.PutSource(ctx, actor, server, SecretPatch{Operation: "replace", Value: credential}, "server", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Schedule(ctx, now); e != nil {
		t.Fatal(e)
	}
	job, e = worker.Claim(ctx, now)
	if e != nil || job.SourceID != server.ID {
		t.Fatal("server source claim")
	}
	_, _, secret, _, e := worker.JobInput(ctx, job, now)
	if e != nil || !bytes.Contains(secret, []byte("synthetic-only")) {
		t.Fatal("worker lost addressed credential")
	}
	if e = worker.Fail(ctx, job, "subscription_fetch_unavailable", false, now); e != nil {
		t.Fatal(e)
	}
	if j, e := worker.Claim(ctx, now); e != nil || j.ID != "" {
		t.Fatal("retry ignored backoff")
	}
	job, e = worker.Claim(ctx, now.Add(6*time.Second))
	if e != nil || job.Attempts != 2 {
		t.Fatal("bounded retry not admitted")
	}
	if e = worker.Fail(ctx, job, "untrusted raw error body", true, now.Add(6*time.Second)); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = fixtureOwner.QueryRow(`SELECT reason FROM catalog_jobs WHERE id=$1`, job.ID).Scan(&reason); e != nil || reason != "subscription_fetch_unavailable" {
		t.Fatal("untrusted reason persisted")
	}
}

func TestSQLLiveAuthorityMFARevisionAndCiphertextFailures(t *testing.T) {
	api, _, actor, now := databaseFixture(t)
	ctx := context.Background()
	source := sourceExample(now)
	source.Mode = "server"
	secret, _ := json.Marshal(FetchCredential{URL: "https://proxy.example.invalid/subscription"})
	staleMFA := actor
	staleMFA.MFAUntil = now.Unix()
	if _, e := api.PutSource(ctx, staleMFA, source, SecretPatch{Operation: "replace", Value: secret}, "no-mfa", now); !errors.Is(e, ErrDenied) {
		t.Fatal("secret mutation without fresh MFA")
	}
	created, e := api.PutSource(ctx, actor, source, SecretPatch{Operation: "replace", Value: secret}, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	draft := source
	draft.Revision = created.Revision
	draft.Name = "Rename without reauth"
	updated, e := api.PutSource(ctx, staleMFA, draft, SecretPatch{Operation: "keep"}, "rename", now)
	if e != nil || updated.Revision != 2 {
		t.Fatal("scoped metadata edit unnecessarily required reauth")
	}
	if _, e = api.PutSource(ctx, actor, draft, SecretPatch{Operation: "keep"}, "stale-revision", now); !errors.Is(e, ErrConflict) {
		t.Fatal("stale editor overwrote revision")
	}
	draft.Revision = 2
	draft.ValidUntil += 60
	if _, e = api.PutSource(ctx, staleMFA, draft, SecretPatch{Operation: "keep"}, "weaken-expiry", now); !errors.Is(e, ErrDenied) {
		t.Fatal("expiry extended without fresh assurance")
	}
	expired := actor
	expired.SessionUntil = now.Unix()
	if _, e = api.GetSource(ctx, expired, source.ID, now); !errors.Is(e, ErrDenied) {
		t.Fatal("expired session read source")
	}
	var protected []byte
	if e = fixtureOwner.QueryRow(`SELECT spec FROM catalog_sources WHERE id=$1`, source.ID).Scan(&protected); e != nil {
		t.Fatal(e)
	}
	damaged := append([]byte(nil), protected...)
	damaged[len(damaged)-1] ^= 1
	if _, e = fixtureAPI.Exec(`UPDATE catalog_sources SET spec=$2 WHERE id=$1`, source.ID, damaged); e != nil {
		t.Fatal(e)
	}
	if _, e = api.GetSource(ctx, actor, source.ID, now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("corrupt protected state was accepted")
	}
	if _, e = fixtureAPI.Exec(`UPDATE catalog_sources SET spec=$2 WHERE id=$1`, source.ID, protected); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE catalog_acl SET expires=$2 WHERE actor=$1`, actor.ID, now.Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = api.GetSource(ctx, actor, source.ID, now); !errors.Is(e, ErrDenied) {
		t.Fatal("withdrawn role remained effective")
	}
}

func TestSQLJobQuotasDeadlineAndCancelledTransaction(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	ctx := context.Background()
	for i := 0; i < 9; i++ {
		source := sourceExample(now)
		source.ID = fmt.Sprintf("source-%d", i)
		source = mustSource(t, api, actor, source, fmt.Sprintf("create-%d", i), now)
		if _, e := api.Queue(ctx, actor, source.ID, source.Revision, fmt.Sprintf("import-%d", i), []byte("http://proxy.example.invalid:443"), now); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 8; i++ {
		j, e := worker.Claim(ctx, now)
		if e != nil || j.ID == "" {
			t.Fatal("bounded admitted work")
		}
	}
	if j, e := worker.Claim(ctx, now); e != nil || j.ID != "" {
		t.Fatal("global active-work limit exceeded")
	}
	if _, e := worker.Claim(ctx, now.Add(901*time.Second)); e != nil {
		t.Fatal(e)
	}
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_jobs WHERE phase='dead_letter'`).Scan(&count); e != nil || count != 9 {
		t.Fatal("job deadlines silently disappeared")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	source := sourceExample(now)
	source.ID = "cancelled-source"
	if _, e := api.PutSource(cancelled, actor, source, SecretPatch{Operation: "keep"}, "cancelled-write", now); e == nil {
		t.Fatal("cancelled SQL operation acknowledged")
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_sources WHERE id='cancelled-source'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("cancelled write partially committed")
	}
}

func TestSQLMonotonicClockAndUnavailableDatabaseNeverAcknowledge(t *testing.T) {
	api, _, actor, now := databaseFixture(t)
	ctx := context.Background()
	first, e := api.Now(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	back, e := api.Now(ctx, now.Add(-24*time.Hour))
	if e != nil || !back.Equal(first) {
		t.Fatal("wall clock rollback extended authority")
	}
	closed, e := sql.Open("pgx", os.Getenv("SYN443_TEST_DATABASE"))
	if e != nil {
		t.Fatal("fixture setup")
	}
	closed.Close()
	dead, e := NewStore(closed, bytes.Repeat([]byte{3}, 32))
	if e != nil {
		t.Fatal(e)
	}
	source := sourceExample(now)
	job := Job{ID: "job-a", SourceID: source.ID, SourceRevision: 1, Attempts: 1}
	for _, call := range []func() error{
		func() error {
			_, e := dead.PutSource(ctx, actor, source, SecretPatch{Operation: "keep"}, "write", now)
			return e
		},
		func() error { _, e := dead.GetSource(ctx, actor, source.ID, now); return e },
		func() error {
			_, e := dead.Queue(ctx, actor, source.ID, 1, "queue", []byte("synthetic"), now)
			return e
		},
		func() error { _, e := dead.Claim(ctx, now); return e }, func() error { _, e := dead.Schedule(ctx, now); return e },
		func() error { return dead.Fail(ctx, job, "subscription_fetch_unavailable", false, now) },
		func() error { return dead.Cancel(ctx, actor, job.ID, "cancel", now) },
		func() error { return dead.Abandon(ctx, job, now) },
		func() error { _, _, _, e := dead.SyncCache(ctx, job, now); return e },
		func() error {
			_, e := dead.Complete(ctx, job, nil, subscriptions.Quota{}, subscriptions.Cache{}, now)
			return e
		},
		func() error { _, e := dead.Now(ctx, now); return e },
		func() error { _, _, e := dead.GetResource(ctx, actor, "panel-a", now); return e },
		func() error {
			_, e := dead.PutResource(ctx, actor, resourceExample(), resourceSecret("https://panel.example.invalid"), "", "create-resource", now)
			return e
		},
		func() error { _, _, e := dead.ResourceClient(ctx, job, false, now); return e },
		func() error { _, e := dead.GetShares(ctx, actor, source.ID, now); return e },
		func() error { _, e := dead.SetShares(ctx, actor, source.ID, 1, Shares{}, "share", now); return e },
		func() error {
			_, e := dead.ReviewSnapshot(ctx, actor, Review{SourceID: source.ID, SourceRevision: 1, Candidate: "candidate-a"}, "review", now)
			return e
		},
		func() error { _, e := dead.ListSources(ctx, actor, source.Owner, "", now); return e },
		func() error { _, e := dead.GetSnapshot(ctx, actor, source.ID, "", now); return e },
		func() error { _, e := dead.GetJob(ctx, actor, "job-a", now); return e },
		func() error {
			e := dead.ConsumeAdminProof(ctx, actor, identity.Proof{Thumbprint: identity.Hash([]byte("synthetic-thumb")), Claims: identity.ProofClaims{Jti: "synthetic-proof-identifier"}}, now)
			return e
		},
		func() error { _, e := (&Worker{Store: dead}).ProcessOne(ctx); return e },
	} {
		if e := call(); !errors.Is(e, ErrUnavailable) {
			t.Fatal("unavailable durable store acknowledged operation")
		}
	}
}

func TestSQLCancellationAtOutboxCommitRollsBackSnapshotAndHead(t *testing.T) {
	api, worker, actor, now := databaseFixture(t)
	source := mustSource(t, api, actor, sourceExample(now), "create", now)
	job, profiles := manualWork(t, api, worker, actor, source, "import", "http://proxy.example.invalid:443", now)
	block, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer block.Rollback()
	if _, e = block.Exec(`LOCK TABLE catalog_outbox IN ACCESS EXCLUSIVE MODE`); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := worker.Complete(ctx, job, profiles, subscriptions.Quota{}, subscriptions.Cache{}, now)
		done <- e
	}()
	deadline := time.Now().Add(8 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		var count int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE usename='syn443_source_worker' AND wait_event_type='Lock' AND query LIKE '%INSERT INTO catalog_outbox%'`).Scan(&count); e != nil {
			t.Fatal(e)
		}
		if count > 0 {
			waiting = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		cancel()
		block.Rollback()
		<-done
		t.Fatal("transaction never reached blocked outbox write")
	}
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, ErrUnavailable) {
			t.Fatal("failed outbox write acknowledged")
		}
	case <-time.After(8 * time.Second):
		block.Rollback()
		t.Fatal("SQL cancellation did not complete")
	}
	block.Rollback()
	read, e := api.GetSource(context.Background(), actor, source.ID, now)
	if e != nil || read.ActiveSnapshot != "" {
		t.Fatal("partially committed active head")
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_snapshots`).Scan(&count); e != nil || count != 0 {
		t.Fatal("partial immutable snapshot survived rollback")
	}
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_outbox`).Scan(&count); e != nil || count != 0 {
		t.Fatal("partial outbox event survived rollback")
	}
}
