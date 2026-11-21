//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestSQLRemnawaveAndTwoIndependentFeedsPublishOneBoundPolicy(t *testing.T) {
	n := newNetworkFixture(t)
	ctx, now := t.Context(), n.f.now
	store, err := catalog.NewStore(fixtureSourceWorker, bytes.Repeat([]byte{81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker := catalog.Worker{Store: store, FixtureLoopback: true, Clock: func() time.Time { return now }}
	tags := []string{"panel", "feed-one", "feed-two"}
	graph := configuration.Graph{
		Profiles:  map[string]configuration.ProfileReference{},
		Balancers: map[string]configuration.Balancer{"pool": {Type: "selector", Members: tags, Default: tags[0]}},
		Final:     "pool",
	}
	var protected [][]byte
	var malformed atomic.Bool
	var feedCalls [3]atomic.Int32
	active := map[string]string{}
	sources := map[string]catalog.Source{}
	foreign := n.actor
	foreign.ID = "unassigned-reader"
	refresh := func(tag, operation string, wantSuccess bool) {
		t.Helper()
		source := sources[tag]
		job, err := n.api.Queue(ctx, n.actor, tag, source.Revision, operation, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		got, err := worker.ProcessOne(ctx)
		if err != nil || got.ID != job.ID || (wantSuccess && got.Phase != "succeeded") || (!wantSuccess && got.Phase != "failed") {
			t.Fatal("unexpected source sync", tag, got.Phase, err)
		}
	}
	for i, tag := range tags {
		token, err := random()
		if err != nil {
			t.Fatal(err)
		}
		protected = append(protected, []byte(token))
		outbound := "http://" + tag + ".example.invalid:443"
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			feedCalls[i].Add(1)
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+token {
				t.Error("provider received an unexpected method or credential", tag)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if i != 0 {
				if r.URL.Path != "/subscription" {
					http.NotFound(w, r)
					return
				}
				if i == 1 && malformed.Load() {
					fmt.Fprint(w, "<html>not a subscription</html>")
					return
				}
				fmt.Fprint(w, outbound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			expiry := now.Add(time.Hour).Format(time.RFC3339)
			switch r.URL.Path {
			case "/api/users/42":
				fmt.Fprintf(w, `{"response":{"id":42,"shortUuid":"fixture","status":"ACTIVE","expireAt":%q}}`, expiry)
			case "/api/subscriptions/by-id/42":
				fmt.Fprintf(w, `{"response":{"isFound":true,"user":{"shortUuid":"fixture","isActive":true,"userStatus":"ACTIVE","expiresAt":%q,"trafficUsedBytes":"0","trafficLimitBytes":"100"},"links":[%q]}}`, expiry, outbound)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		protected = append(protected, []byte(srv.URL))
		ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
		scope := []string{"127.0.0.1/32"}
		source := catalog.Source{ID: tag, Owner: n.target.Owner, Name: tag, Mode: "server", Format: "uri", Enabled: true,
			ValidUntil: now.Add(2 * time.Hour).Unix(), RefreshSeconds: 3600, MaxStaleSeconds: 3600, NetworkModes: []string{"wifi"}}
		var credential catalog.SecretPatch
		if i == 0 {
			source.Mode, source.ResourceID, source.ExternalUserID = "resource", "panel-resource", "42"
			raw, e := json.Marshal(catalog.ResourceCredential{Endpoint: srv.URL, Token: token, RootCA: ca, AllowedNetworks: scope})
			if e != nil {
				t.Fatal(e)
			}
			_, e = n.api.PutResource(ctx, n.actor, catalog.Resource{ID: source.ResourceID, Name: "Fixture panel", ProviderType: "panel.remnawave", APIVersion: "3.4", Enabled: true}, catalog.SecretPatch{Operation: "replace", Value: raw}, "", "add-panel-resource", now)
			if e != nil {
				t.Fatal(e)
			}
			credential.Operation = "keep"
		} else {
			raw, e := json.Marshal(catalog.FetchCredential{URL: srv.URL + "/subscription", Headers: map[string]string{"Authorization": "Bearer " + token}, RootCA: ca, AllowedNetworks: scope})
			if e != nil {
				t.Fatal(e)
			}
			credential = catalog.SecretPatch{Operation: "replace", Value: raw}
		}
		sources[tag], err = n.api.PutSource(ctx, n.actor, source, credential, "add-"+tag, now)
		if err != nil {
			t.Fatal(err)
		}
		refresh(tag, "import-"+tag, true)
		view, err := n.api.GetSnapshot(ctx, n.actor, tag, "", now)
		if err != nil || view.Snapshot.State != "active" || len(view.Profiles) != 1 {
			t.Fatal("missing source profile", tag, err)
		}
		active[tag] = view.Snapshot.ID
		graph.Profiles[tag] = configuration.ProfileReference{SourceID: tag, ProfileID: view.Profiles[0].ID}
		if _, err = n.api.GetSnapshot(ctx, foreign, tag, view.Snapshot.ID, now); !errors.Is(err, catalog.ErrDenied) {
			t.Fatal("foreign inventory", err)
		}
	}
	malformed.Store(true)
	refresh("feed-one", "bad-refresh", false)
	refresh("feed-two", "good-refresh", true)
	for _, tag := range tags {
		view, err := n.api.GetSource(ctx, n.actor, tag, now)
		if err != nil || view.ActiveSnapshot == "" || (view.ActiveSnapshot != active[tag]) != (tag == "feed-two") {
			t.Fatal("refresh isolation", tag, err)
		}
	}
	graphBody, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	n.approved.Layers[0].Changes[1].Value = graphBody
	if err = n.publisher.RunOnce(ctx, now); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	var revision int64
	if err = fixtureOwner.QueryRowContext(ctx, "SELECT revision,publication FROM identity_devices WHERE id=$1", n.target.Device).Scan(&revision, &sealed); err != nil || revision != 1 {
		t.Fatal("device revision", err)
	}
	plain, err := n.publisher.Store.Open(sealed, fmt.Sprintf("publication/v1/%s/%d", n.target.Device, revision))
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}
	p, err := policy.VerifyBound(string(plain), roots, n.target.Device, n.target.Thumbprint, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = policy.VerifyBound(string(plain), roots, "unassigned-device", n.target.Thumbprint, now); err == nil {
		t.Fatal("foreign device accepted publication")
	}
	engine, err := base64.RawURLEncoding.DecodeString(p.EngineConfigB64)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range protected {
		if bytes.Contains(engine, v) || bytes.Contains(plain, v) {
			t.Fatal("provider access material in device policy")
		}
	}
	var issued struct {
		Route     struct{ Final string }
		Outbounds []struct {
			Tag, Type, Server, Default string
			Outbounds                  []string
		}
	}
	if err = json.Unmarshal(engine, &issued); err != nil || issued.Route.Final != "pool" {
		t.Fatal("wrong compiled final", err)
	}
	seen := map[string]bool{}
	for _, out := range issued.Outbounds {
		if slices.Contains(tags, out.Tag) {
			if out.Server != out.Tag+".example.invalid" || out.Type != "http" {
				t.Fatal("mixed profile substitution")
			}
			seen[out.Tag] = true
		} else if out.Tag == "pool" && out.Type == "selector" && out.Default == tags[0] && slices.Equal(out.Outbounds, tags) {
			seen["pool"] = true
		}
	}
	if len(seen) != 4 || feedCalls[0].Load() != 2 || feedCalls[1].Load() != 2 || feedCalls[2].Load() != 2 {
		t.Fatal("missing selected profile, selector or independent fetch")
	}
}
