//go:build postgres

package catalog

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSQLStalledSubscriptionDoesNotBlockOtherWorkerAndShutdownReturnsItsClaim(t *testing.T) {
	api, store, actor, now := databaseFixture(t)
	ctx := t.Context()
	service := func(handler http.HandlerFunc) *httptest.Server {
		server := httptest.NewTLSServer(handler)
		t.Cleanup(server.Close)
		return server
	}
	started := make(chan struct{})
	var slowHits, healthyHits atomic.Int32
	slow := service(func(w http.ResponseWriter, r *http.Request) {
		if slowHits.Add(1) == 1 {
			close(started)
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte("http://recovered.example.invalid:443"))
	})
	healthy := service(func(w http.ResponseWriter, r *http.Request) {
		healthyHits.Add(1)
		_, _ = w.Write([]byte("http://healthy.example.invalid:443"))
	})
	enqueue := func(id string, server *httptest.Server) {
		t.Helper()
		source := sourceExample(now)
		source.ID, source.Mode = id, "server"
		credential, err := json.Marshal(FetchCredential{URL: server.URL, AllowedNetworks: []string{"127.0.0.1/32"},
			RootCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = api.PutSource(ctx, actor, source, SecretPatch{Operation: "replace", Value: credential}, "create-"+id, now); err != nil {
			t.Fatal(err)
		}
		if count, err := store.Schedule(ctx, now); err != nil || count != 1 {
			t.Fatal("expected one scheduled source", count, err)
		}
	}
	enqueue("slow", slow)
	clock := func() time.Time { return now }
	first := Worker{Store: store, FixtureLoopback: true, Clock: clock}
	second := Worker{Store: store, FixtureLoopback: true, Clock: clock}
	fetch, cancelFetch := context.WithCancel(ctx)
	done := make(chan struct{})
	var interrupted Job
	var interruption error
	go func() { defer close(done); interrupted, interruption = first.ProcessOne(fetch) }()
	t.Cleanup(func() {
		cancelFetch()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("worker did not stop")
		}
	})
	select {
	case <-started:
	case <-done:
		t.Fatal("worker returned before the upstream request", interruption)
	case <-time.After(8 * time.Second):
		t.Fatal("upstream request did not arrive")
	}
	enqueue("healthy", healthy)
	wait, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	job, err := second.ProcessOne(wait)
	if err != nil || job.SourceID != "healthy" || job.Phase != "succeeded" || healthyHits.Load() != 1 {
		t.Fatal("healthy subscription blocked", err)
	}
	before, err := api.GetSource(ctx, actor, "healthy", now)
	if err != nil || before.ActiveSnapshot == "" {
		t.Fatal("healthy snapshot missing")
	}
	select {
	case <-done:
		t.Fatal("stalled worker returned before shutdown")
	default:
	}
	cancelFetch()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown exceeded its bound")
	}
	if interruption == nil || interrupted.SourceID != "slow" {
		t.Fatal("interrupted read acknowledged")
	}
	pending, err := api.GetJob(ctx, actor, interrupted.ID, now)
	if err != nil || pending.Job.Phase != "queued" || pending.Job.Reason != "worker_stopped" || pending.Job.Attempts != 1 || pending.LeaseExpiresAt != 0 {
		t.Fatal("interrupted claim still held", err)
	}
	retry, err := second.ProcessOne(ctx)
	if err != nil || retry.ID != interrupted.ID || retry.Attempts != 2 || retry.Deadline != interrupted.Deadline || retry.Phase != "succeeded" {
		t.Fatal("original work not restored", err)
	}
	snapshot, err := api.GetSource(ctx, actor, "slow", now)
	if err != nil || snapshot.ActiveSnapshot == "" || slowHits.Load() != 2 {
		t.Fatal("recovered source missing")
	}
	after, err := api.GetSource(ctx, actor, "healthy", now)
	if err != nil || after.ActiveSnapshot != before.ActiveSnapshot || healthyHits.Load() != 1 {
		t.Fatal("unrelated source was repeated or replaced")
	}
}
