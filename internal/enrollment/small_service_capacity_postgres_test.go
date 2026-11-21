//go:build postgres && capacity

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

const capacityUsers = 100
const capacityDevicesPerUser = 3
const capacityPacing = 200 * time.Millisecond

type capacityDevice struct {
	key     *ecdsa.PrivateKey
	session Session
	client  *http.Client
}

type capacityResult struct {
	Elapsed time.Duration
	Valid   bool
}

type capacitySummary struct {
	Scheduled int    `json:"scheduled"`
	Verified  int    `json:"verified"`
	P95Ms     *int64 `json:"p95Ms"`
}

func summarizeCapacity(samples []capacityResult) capacitySummary {
	s := capacitySummary{Scheduled: len(samples)}
	values := make([]time.Duration, 0, len(samples))
	for _, r := range samples {
		if r.Valid && r.Elapsed > 0 {
			s.Verified++
			values = append(values, r.Elapsed)
		}
	}
	if s.Verified != s.Scheduled || s.Scheduled == 0 {
		return s
	}
	slices.Sort(values)
	latency := values[(95*s.Scheduled+99)/100-1]
	ms := int64((latency + time.Millisecond - 1) / time.Millisecond)
	s.P95Ms = &ms
	return s
}

func TestCapacityKeepsEveryScheduledOutcomeInEachPercentile(t *testing.T) {
	v := make([]capacityResult, 100)
	for i := range v {
		v[i] = capacityResult{time.Duration(i+1) * time.Millisecond, true}
	}
	if got := summarizeCapacity(v); got.P95Ms == nil || *got.P95Ms != 95 {
		t.Fatal(got)
	}
	v[99].Valid = false
	if got := summarizeCapacity(v); got.P95Ms != nil || got.Scheduled != 100 || got.Verified != 99 {
		t.Fatal(got)
	}
}

type capacityResponse struct {
	code    int
	raw     []byte
	nonce   string
	elapsed time.Duration
}

// The caller measures complete HTTP response bytes. Client-side signature and
// receipt verification are additional pass conditions, outside server latency.
func (d capacityDevice) request(t *testing.T, origin, method, path, token, nonce string, body []byte) capacityResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, origin+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", signed(t, d.key, method, origin+path, token, nonce, body, time.Now()))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	res, err := d.client.Do(req)
	if err != nil {
		return capacityResponse{elapsed: time.Since(start)}
	}
	defer res.Body.Close()
	const limit = 700_000
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || len(raw) > limit {
		return capacityResponse{elapsed: time.Since(start)}
	}
	return capacityResponse{res.StatusCode, raw, res.Header.Get("DPoP-Nonce"), time.Since(start)}
}

func TestSmallServiceCapacityWithIssuedPoliciesAndDurableTelemetry(t *testing.T) {
	engine, err := os.ReadFile(os.Getenv("SYN443_CAPACITY_ENGINE"))
	if err != nil {
		t.Fatal(err)
	}
	if len(engine) == 0 || len(engine) > 262144 {
		t.Fatal("unexpected prepared engine size")
	}
	hash := sha256.Sum256(engine)
	wantHash := hex.EncodeToString(hash[:])
	f := newFixture(t, capacityDevicesPerUser)
	now := time.Now().UTC().Truncate(time.Second)
	f.now = now
	f.api.Clock = time.Now
	f.api.ExternalTelemetry = true
	var ingest http.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == telemetryPath {
			ingest.ServeHTTP(w, r)
			return
		}
		f.api.ServeHTTP(w, r)
	}))
	defer server.Close()
	f.origin = server.URL
	f.api.Origin = server.URL
	receiver, err := OpenStandaloneIngest(t.Context(), fixtureIngestDSN, server.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ingest = receiver

	caps := []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", policy.RouteDecision, policy.RouteAdaptiveTCP, policy.RouteExitCountry}
	grant := f.grant
	grant.Until = now.Add(2 * time.Hour).Unix()
	publisher := f.publisher()
	prepared := &PreparedConfiguration{EngineConfig: engine, Activation: grant.Template.Activation,
		RequiredCapabilities: caps, AlgorithmRevision: policy.AdaptiveTCPAlgorithm, UntilMs: now.Add(90 * time.Minute).UnixMilli(), Fence: &fixtureConfigurationFence{}}
	publisher.Configurations = fixtureConfigurationAuthority(func(_ context.Context, _ ConfigurationTarget, _ time.Time) (*PreparedConfiguration, error) {
		return prepared, nil
	})
	active := make([]capacityDevice, 0, capacityUsers)
	for user := 0; user < capacityUsers; user++ {
		if user > 0 {
			grant.Subject = fmt.Sprintf("capacity-user-%03d", user)
		}
		f.grant = grant
		if err := Authorize(t.Context(), fixtureOwner, grant, time.Now()); err != nil {
			t.Fatal(err)
		}
		publisher.Grants[Owner(grant.Issuer, grant.Subject)] = grant
		transport := server.Client().Transport.(*http.Transport).Clone()
		dial := &net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(user+1))}}
		transport.DialContext = dial.DialContext
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		defer client.CloseIdleConnections()
		for seat := 0; seat < capacityDevicesPerUser; seat++ {
			d := capacityDevice{key: key(t), client: client}
			oidc := f.token(d.key)
			f.v.mu.Lock()
			principal := f.v.principals[oidc]
			principal.Expires = time.Now().Add(10 * time.Minute).Unix()
			f.v.principals[oidc] = principal
			f.v.mu.Unlock()
			body, err := json.Marshal(Request{random(), identity.PublicJWK(&d.key.PublicKey), caps})
			if err != nil {
				t.Fatal(err)
			}
			challenge := d.request(t, server.URL, http.MethodPost, "/v1/devices/enroll", oidc, "", body)
			if challenge.code != http.StatusUnauthorized || challenge.nonce == "" {
				t.Fatalf("capacity challenge status %d", challenge.code)
			}
			result := d.request(t, server.URL, http.MethodPost, "/v1/devices/enroll", oidc, challenge.nonce, body)
			if result.code != http.StatusOK || identity.Decode(result.raw, &d.session, true) != nil {
				t.Fatalf("capacity enrollment status %d", result.code)
			}
			if err := publisher.publish(t.Context(), d.session.DeviceID, time.Now()); err != nil {
				t.Fatalf("issue capacity policy: %v", err)
			}
			if seat == 0 {
				active = append(active, d)
			}
		}
	}
	var users, devices int
	if err := fixtureOwner.QueryRow(`SELECT count(DISTINCT owner),count(*) FROM identity_devices WHERE active AND approved AND revision=1 AND publication IS NOT NULL`).Scan(&users, &devices); err != nil || users != capacityUsers || devices != capacityUsers*capacityDevicesPerUser {
		t.Fatal("wrong enrolled population", users, devices, err)
	}
	read := make([]capacityResult, len(active))
	post := make([]capacityResult, len(active))
	var ready, finished sync.WaitGroup
	ready.Add(len(active))
	finished.Add(len(active))
	start := make(chan struct{})
	var epoch time.Time
	for i, device := range active {
		go func() {
			defer finished.Done()
			ready.Done()
			<-start
			time.Sleep(time.Until(epoch.Add(time.Duration(i) * capacityPacing)))
			r := device.request(t, server.URL, http.MethodGet, "/v1/device/policy", device.session.AccessToken, device.session.Nonce, nil)
			thumb, _ := identity.PublicJWK(&device.key.PublicKey).Thumbprint()
			cfg, proofErr := policy.VerifyBound(string(r.raw), f.api.Roots, device.session.DeviceID, thumb, time.Now())
			read[i] = capacityResult{r.elapsed, r.code == 200 && proofErr == nil && cfg.ContentHash == wantHash && cfg.Revision == 1}
			ids := make([]string, 8)
			batch := telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 65, AlgorithmRevision: 1, PolicyRevision: 1}
			for j := range ids {
				ids[j] = random()
				batch.Events = append(batch.Events, telemetry.Event{ID: ids[j], AtMS: time.Now().Add(-time.Duration(8-j) * time.Second).UnixMilli(), Kind: "vpn", Code: "online", Mode: "wifi"})
			}
			body, err := json.Marshal(batch)
			if err != nil {
				t.Error("capacity batch encoding")
				return
			}
			ack := device.request(t, server.URL, http.MethodPost, telemetryPath, device.session.AccessToken, device.session.Nonce, body)
			var receipt telemetry.Receipt
			post[i] = capacityResult{ack.elapsed, ack.code == 200 && json.Unmarshal(ack.raw, &receipt) == nil && slices.Equal(receipt.EventIDs, ids)}
		}()
	}
	ready.Wait()
	epoch = time.Now()
	close(start)
	finished.Wait()
	var persisted int
	if err := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_telemetry_events`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	type report struct {
		Users     int             `json:"users"`
		Devices   int             `json:"registeredDevices"`
		Clients   int             `json:"activeClients"`
		Profiles  int             `json:"profilesPerDevice"`
		PacingMs  int64           `json:"clientStartSpacingMs"`
		Rows      int             `json:"storedEvents"`
		Policy    capacitySummary `json:"policyRead"`
		Telemetry capacitySummary `json:"telemetryBatch"`
	}
	out := report{users, devices, len(active), 500, capacityPacing.Milliseconds(), persisted, summarizeCapacity(read), summarizeCapacity(post)}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("SYN443_CAPACITY_REPORT"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("capacity reference: %s", data)
	if out.Policy.P95Ms == nil || out.Telemetry.P95Ms == nil || *out.Policy.P95Ms > 500 || *out.Telemetry.P95Ms > 500 || persisted != len(active)*8 {
		t.Fatal("capacity reference target not met")
	}
}
