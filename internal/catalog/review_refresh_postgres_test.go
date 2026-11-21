//go:build postgres

package catalog

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSQLReviewedSnapshotAndLateProviderOutcomes(t *testing.T) {
	for _, tc := range []struct{ name, phase, state, access string }{
		{"malformed", "cancelled", "active", "allowed"},
		{"unavailable", "cancelled", "active", "allowed"},
		{"gone", "failed", "revoked", "revoked"},
		{"expired", "failed", "expired", "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, store, actor, now := databaseFixture(t)
			ctx := context.Background()
			reviews := make(chan Review, 1)
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("unexpected provider method")
					w.WriteHeader(405)
					return
				}
				switch requests.Add(1) {
				case 1:
					fmt.Fprint(w, "http://one.example.invalid:443\nhttp://two.example.invalid:443\nhttp://three.example.invalid:443")
				case 2:
					fmt.Fprint(w, "http://one.example.invalid:443")
				case 3:
					// The real HTTP request has read its base. Commit an administrative
					// approval before the first byte of this response is received.
					review := <-reviews
					if _, err := api.ReviewSnapshot(ctx, actor, review, "approve-before-response", now); err != nil {
						t.Error("review was rejected", err)
						w.WriteHeader(500)
						return
					}
					switch tc.name {
					case "malformed":
						fmt.Fprint(w, "<html>invalid response</html>")
					case "unavailable":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "gone":
						w.WriteHeader(http.StatusGone)
					case "expired":
						w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=0; total=100; expire=%d", now.Unix()-1))
						fmt.Fprint(w, "http://one.example.invalid:443")
					}
				default:
					t.Error("unexpected repeated fetch")
					w.WriteHeader(500)
				}
			}))
			t.Cleanup(server.Close)
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			raw, err := json.Marshal(FetchCredential{URL: server.URL, RootCA: string(ca), AllowedNetworks: []string{"127.0.0.1/32"}})
			if err != nil {
				t.Fatal(err)
			}
			source := sourceExample(now)
			source.Mode = "server"
			source, err = api.PutSource(ctx, actor, source, SecretPatch{Operation: "replace", Value: raw}, "create", now)
			if err != nil {
				t.Fatal(err)
			}
			runAt := now
			worker := Worker{Store: store, FixtureLoopback: true, Clock: func() time.Time { return runAt }}
			refresh := func(request string) Job {
				t.Helper()
				queued, err := api.Queue(ctx, actor, source.ID, source.Revision, request, nil, now)
				if err != nil {
					t.Fatal(err)
				}
				job, err := worker.ProcessOne(ctx)
				if err != nil || job.ID != queued.ID {
					t.Fatal("worker did not finish queued request", err)
				}
				return job
			}
			if refresh("initial").Phase != "succeeded" || refresh("reduced").Phase != "succeeded" {
				t.Fatal("fixture imports failed")
			}
			before, err := api.GetSource(ctx, actor, source.ID, now)
			if err != nil || before.State != "quarantined" || before.ActiveSnapshot == "" || before.CandidateSnapshot == before.ActiveSnapshot {
				t.Fatal("candidate", err)
			}
			view, err := api.GetSnapshot(ctx, actor, source.ID, before.CandidateSnapshot, now)
			if err != nil {
				t.Fatal(err)
			}
			reviews <- Review{SourceID: source.ID, SourceRevision: source.Revision, Candidate: view.Snapshot.ID, Hash: view.Snapshot.Hash, Active: before.ActiveSnapshot, Approve: true}
			runAt = now.Add(5 * time.Second)
			job := refresh("interleaved")
			after, err := api.GetSource(ctx, actor, source.ID, now)
			if err != nil || after.State != tc.state || after.AccessState != tc.access || after.ActiveSnapshot != view.Snapshot.ID || after.CandidateSnapshot != "" {
				t.Fatal("review or access state changed unexpectedly", after.State, after.AccessState, err)
			}
			receipt, err := api.GetJob(ctx, actor, job.ID, now)
			if err != nil || job.Phase != tc.phase || receipt.Job.Phase != tc.phase || receipt.Job.Reason != job.Reason || requests.Load() != 3 {
				t.Fatal("terminal job", job.Phase, err)
			}
			if tc.phase == "cancelled" && (job.Reason != "stale_inputs" || after.NextSync != before.NextSync) {
				t.Fatal("stale failure changed schedule")
			}
		})
	}
}
