//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

// Owner-only immutable approved-availability fixture. The original signed
// enrollment request/key/grant stays unchanged. This does not claim acceptance
// of the separately tested capability negotiation HTTP/DPoP protocol.
func seedAdaptiveAvailability(t *testing.T, n *networkFixture) {
	t.Helper()
	var original []byte
	if err := fixtureOwner.QueryRow(`SELECT request_body FROM identity_devices WHERE id=$1 AND approved`, n.target.Device).Scan(&original); err != nil {
		t.Fatal(err)
	}
	var request enrollment.Request
	if identity.Decode(original, &request, true) != nil {
		t.Fatal("invalid original capability fixture")
	}
	base := append([]string(nil), request.Capabilities...)
	slices.Sort(base)
	baseRaw, _ := json.Marshal(base)
	caps := adaptiveAuthorityCapabilities()
	slices.Sort(caps)
	raw, _ := json.Marshal(caps)
	tx, err := fixtureSigner.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO identity_capability_versions(device,revision,previous_hash,body_hash,capabilities,original_request_hash,request_hash,proof_hash,approved_ms) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8)`,
		n.target.Device, identity.Hash(baseRaw), identity.Hash(raw), raw, identity.Hash(original), identity.Hash([]byte("synthetic-adaptive-availability-request")), identity.Hash([]byte("synthetic-adaptive-availability-proof")), n.f.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO identity_capability_heads(device,revision,body_hash) VALUES($1,1,$2)`, n.target.Device, identity.Hash(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE identity_devices SET refresh_after=0,retry_after=0 WHERE id=$1`, n.target.Device); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	available, err := enrollment.EffectiveCapabilities(context.Background(), fixtureSigner, n.target.Device, request.Capabilities)
	if err != nil || !slices.Equal(available.Capabilities, caps) || available.Version != 1 {
		t.Fatal("actual availability history was not independently read", err)
	}
	n.target.Capabilities = append([]string(nil), available.Capabilities...)
}

func configureAdaptiveNetworkFixture(t *testing.T, n *networkFixture, plan configuration.NetworkPlan) {
	t.Helper()
	raw, err := json.Marshal(plan)
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &fields) != nil {
		t.Fatal("invalid portable adaptive fixture")
	}
	changes := []configuration.Change{}
	for _, name := range []string{"schemaVersion", "graph", "network", "activation", "adaptive"} {
		changes = append(changes, configuration.Change{Path: "/" + name, Operation: "set", Value: fields[name]})
	}
	n.approved.Layers[0].Changes = changes
	n.approved.Target = n.target
	n.authority.Layers = networkLayersFunc(func(_ context.Context, actual enrollment.ConfigurationTarget, _ time.Time) (*ApprovedNetworkLayers, error) {
		if actual.Device != n.target.Device || actual.Owner != n.target.Owner || actual.Thumbprint != n.target.Thumbprint || actual.GrantHash != n.target.GrantHash {
			return nil, enrollment.ErrDenied
		}
		owned := *n.approved
		owned.Target = actual
		owned.Target.Capabilities = append([]string(nil), actual.Capabilities...)
		return &owned, nil
	})
}

func newAdaptiveNetworkFixture(t *testing.T) networkFixture {
	t.Helper()
	n := newNetworkFixture(t)
	if err := n.publisher.RunOnce(context.Background(), n.f.now); err != nil {
		t.Fatal(err)
	}
	if err := fixtureOwner.QueryRow(`SELECT revision FROM identity_devices WHERE id=$1 AND approved`, n.target.Device).Scan(&n.target.CurrentRevision); err != nil || n.target.CurrentRevision != 1 {
		t.Fatal("ordinary admission was not actually published", err)
	}
	seedAdaptiveAvailability(t, &n)
	plan := adaptiveAuthorityPlan(t, []configuration.ProfileReference{n.ref})
	plan.Graph.Profiles["proxy"] = n.ref // The same authorized source is both static and private.
	configureAdaptiveNetworkFixture(t, &n, plan)
	return n
}

func verifyAdaptivePublication(t *testing.T, n networkFixture, revision int64) policy.Payload {
	t.Helper()
	var actual int64
	var cipher []byte
	if err := fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&actual, &cipher); err != nil || actual != revision {
		t.Fatal("actual addressed publication revision", err)
	}
	plain, err := n.publisher.Store.Open(cipher, "publication/v1/"+n.target.Device+"/"+fmt.Sprint(revision))
	if err != nil {
		t.Fatal(err)
	}
	at := n.f.now.Add(3 * time.Second)
	verified, err := policy.VerifyBound(string(plain), map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}, n.target.Device, n.target.Thumbprint, at)
	if err != nil || verified.AlgorithmRevision != configuration.AdaptiveTCPAlgorithm || !slices.Contains(verified.RequiredCapabilities, adaptiveNetworkCapability) || !slices.Contains(verified.RequiredCapabilities, policy.RouteDecision) || !slices.Contains(verified.RequiredCapabilities, policy.RouteExitCountry) {
		t.Fatal("actual signed publication lost algorithm, primitive or key binding", err)
	}
	if _, err := policy.VerifyBound(string(plain), map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}, n.target.Device, identity.Hash([]byte("other-synthetic-device-key")), at); err == nil {
		t.Fatal("adaptive envelope accepted another device key")
	}
	engine, err := base64.RawURLEncoding.Strict().DecodeString(verified.EngineConfigB64)
	if err != nil || !bytes.Contains(engine, []byte(`"adaptive_routes"`)) || !bytes.Contains(engine, []byte(`"type":"syn443-adaptive"`)) {
		t.Fatal("signed envelope silently retained the baseline engine", err)
	}
	return verified
}

func TestSQLAdaptiveAuthoritySignsActualDeviceWithIndependentAvailabilityAndBothFences(t *testing.T) {
	n := newAdaptiveNetworkFixture(t)
	ctx := context.Background()
	prepared, err := n.authority.Prepare(ctx, n.target, n.f.now)
	if err != nil || prepared.AlgorithmRevision != configuration.AdaptiveTCPAlgorithm || len(prepared.RequiredCapabilities) != 7 || prepared.UntilMs != n.f.now.Add(time.Hour).UnixMilli() {
		t.Fatal("adaptive preparation did not bind capabilities/source lifetime", err)
	}
	fence, ok := prepared.Fence.(*networkFence)
	if !ok || fence.sources == nil || len(fence.sources.Dependencies()) != 1 {
		t.Fatal("static/adaptive union lost its actual source fence")
	}
	calls := 0
	n.approved.Fence = networkFenceFunc(func(ctx context.Context, tx *sql.Tx, _ time.Time) error {
		calls++
		var owner, key, grant string
		if err := tx.QueryRowContext(ctx, `SELECT d.owner,d.jkt,a.grant_hash FROM identity_devices d JOIN identity_accounts a ON a.owner=d.owner WHERE d.id=$1`, n.target.Device).Scan(&owner, &key, &grant); err != nil {
			return err
		}
		if owner != n.target.Owner || key != n.target.Thumbprint || grant != n.target.GrantHash {
			return enrollment.ErrDenied
		}
		return nil
	})
	if err := n.publisher.RunOnce(ctx, n.f.now); err != nil {
		t.Fatal(err)
	}
	verified := verifyAdaptivePublication(t, n, 2)
	if calls != 2 || verified.OfflineUntilMs != prepared.UntilMs {
		t.Fatal("actual issuance omitted initial/final SQL fence or extended the source permit")
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(verified.EngineConfigB64)
	if !bytes.Equal(raw, prepared.EngineConfig) {
		t.Fatal("actual publisher substituted another engine for the approved compilation")
	}
}

func TestSQLAdaptiveAuthoritySelectsTheEntire500Plus32UnionWithoutFallback(t *testing.T) {
	n := newAdaptiveNetworkFixture(t)
	ctx := context.Background()
	worker, err := catalog.NewStore(fixtureSourceWorker, bytes.Repeat([]byte{81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	urls := []string{"http://proxy.example.invalid:443"} // Preserve the old assigned profile.
	for i := 1; i < 532; i++ {
		urls = append(urls, fmt.Sprintf("http://proxy-%03d.example.invalid:443", i))
	}
	job, err := n.api.Queue(ctx, n.actor, n.source.ID, n.source.Revision, "import-adaptive-union", []byte(strings.Join(urls, "\n")), n.f.now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := worker.Claim(ctx, n.f.now)
	if err != nil || claimed.ID != job.ID {
		t.Fatal("union source job", err)
	}
	input, salt, _, payload, err := worker.JobInput(ctx, claimed, n.f.now)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := subscriptions.Import(input.ID, salt, input.Format, payload)
	if err != nil || len(profiles) != 532 {
		t.Fatal("union source import", err)
	}
	snapshot, err := worker.Complete(ctx, claimed, profiles, subscriptions.Quota{}, subscriptions.Cache{}, n.f.now)
	if err != nil || snapshot.State != "active" {
		t.Fatal("owned union snapshot was not active", err)
	}
	refs := make([]configuration.ProfileReference, len(profiles))
	for i, profile := range profiles {
		refs[i] = configuration.ProfileReference{SourceID: n.source.ID, ProfileID: profile.ID}
	}
	plan := adaptiveAuthorityPlan(t, refs[:500])
	for i, ref := range refs[500:] {
		plan.Graph.Profiles[fmt.Sprintf("static-%02d", i)] = ref
	}
	configureAdaptiveNetworkFixture(t, &n, plan)
	prepared, err := n.authority.Prepare(ctx, n.target, n.f.now)
	if err != nil || prepared.AlgorithmRevision != configuration.AdaptiveTCPAlgorithm {
		t.Fatal("actual adaptive source lane rejected its bounded union", err)
	}
	fence := prepared.Fence.(*networkFence)
	if fence.sources == nil || len(fence.sources.Dependencies()) != 1 || fence.sources.Dependencies()[0].SnapshotHash != snapshot.Hash {
		t.Fatal("union did not bind the exact current source snapshot")
	}
	for _, ref := range refs {
		if _, ok := fence.sources.Profile(catalog.ProfileReference{SourceID: ref.SourceID, ProfileID: ref.ProfileID}); !ok {
			t.Fatal("adaptive union was silently truncated to the ordinary64-reference lane")
		}
	}
	var engine struct {
		Outbounds []json.RawMessage `json:"outbounds"`
		Adaptive  struct {
			Catalogue string `json:"catalogueB64"`
		} `json:"adaptive_routes"`
	}
	if json.Unmarshal(prepared.EngineConfig, &engine) != nil || len(engine.Outbounds) != 34 {
		t.Fatal("private candidates were flattened or ordinary32 profiles were lost")
	}
	var catalogue map[string]json.RawMessage
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(engine.Adaptive.Catalogue)
	if err != nil || json.Unmarshal(decoded, &catalogue) != nil || len(catalogue) != 500 {
		t.Fatal("full private catalogue missing from actual prepared policy", err)
	}
}

func TestSQLAdaptiveAuthorityRejectsDowngradesForeignKeysAndLateSourceChanges(t *testing.T) {
	n := newAdaptiveNetworkFixture(t)
	ctx := context.Background()
	for _, capability := range adaptiveAuthorityCapabilities() {
		old := n.target
		old.Capabilities = slices.DeleteFunc(append([]string(nil), old.Capabilities...), func(c string) bool { return c == capability })
		if prepared, err := n.authority.Prepare(ctx, old, n.f.now); !errors.Is(err, enrollment.ErrDenied) || prepared != nil {
			t.Fatal("unadvertised device module was inferred from a grant or ready state", capability, err)
		}
	}
	for _, change := range []func(*enrollment.ConfigurationTarget){
		func(t *enrollment.ConfigurationTarget) { t.Thumbprint = identity.Hash([]byte("other-key")) },
		func(t *enrollment.ConfigurationTarget) { t.GrantHash = identity.Hash([]byte("other-grant")) },
		func(t *enrollment.ConfigurationTarget) { t.Owner = "other-owner" },
		func(t *enrollment.ConfigurationTarget) { t.Device = "other-device" },
	} {
		foreign := n.target
		change(&foreign)
		if prepared, err := n.authority.Prepare(ctx, foreign, n.f.now); !errors.Is(err, enrollment.ErrDenied) || prepared != nil {
			t.Fatal("adaptive preparation accepted another recipient/key/grant", err)
		}
	}
	prepared, err := n.authority.Prepare(ctx, n.target, n.f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureOwner.Exec(`UPDATE catalog_sources SET state='pending',access_state='revoked' WHERE id=$1`, n.source.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := fixtureSigner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := prepared.Fence.Lock(ctx, tx, n.f.now); !errors.Is(err, catalog.ErrDenied) {
		t.Fatal("source revoked after compilation passed the actual final fence", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if fallback, err := n.authority.Prepare(ctx, n.target, n.f.now); !errors.Is(err, catalog.ErrDenied) || fallback != nil {
		t.Fatal("revoked adaptive source silently returned a stale/static policy", err)
	}
	var revision int64
	if err := fixtureOwner.QueryRow(`SELECT revision FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&revision); err != nil || revision != 1 {
		t.Fatal("failed preparation changed the existing signed publication", err)
	}
}

func TestSQLAdaptivePublisherWaitsForSourceLockAndCannotPublishAfterConcurrentRevoke(t *testing.T) {
	n := newAdaptiveNetworkFixture(t)
	var previous []byte
	if err := fixtureOwner.QueryRow(`SELECT publication FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&previous); err != nil {
		t.Fatal(err)
	}
	hold, err := fixtureOwner.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := hold.Exec(`SELECT id FROM catalog_sources WHERE id=$1 FOR UPDATE`, n.source.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- n.publisher.RunOnce(ctx, n.f.now) }()
	running := true
	defer func() {
		cancel()
		_ = hold.Rollback()
		if running {
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Error("owned publisher worker did not exit after cancellation and source-lock release")
			}
		}
	}()
	blocked := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if err := fixtureOwner.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='syn443_identity_publisher' AND wait_event_type='Lock' AND query LIKE '%catalog_sources%FOR SHARE%')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-finished:
			running = false
			t.Fatal("publisher did not wait for the actual source lock", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("actual PostgreSQL source-row wait was not observed")
	}
	if _, err := hold.Exec(`UPDATE catalog_sources SET enabled=false WHERE id=$1`, n.source.ID); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		running = false
		if err != nil {
			t.Fatal("publisher retry bookkeeping failed", err)
		}
	case <-ctx.Done():
		t.Fatal("source lock owner was released but publisher did not finish")
	}
	var revision int64
	var publication []byte
	var code string
	if err := fixtureOwner.QueryRow(`SELECT revision,publication,publication_error FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&revision, &publication, &code); err != nil || revision != 1 || !bytes.Equal(publication, previous) || code == "" {
		t.Fatal("concurrent source revoke issued an adaptive policy or erased the previous receipt", err)
	}
}

func TestSQLAdaptiveLayerPreviewPublishAndRefreshBindTheRealAlgorithmAndDevice(t *testing.T) {
	n, control, proposal, publisher := layerPublisherFixture(t)
	if err := fixtureOwner.QueryRow(`SELECT revision FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&n.target.CurrentRevision); err != nil || n.target.CurrentRevision != 1 {
		t.Fatal("actual baseline publication missing", err)
	}
	seedAdaptiveAvailability(t, &n)
	configureAdaptiveNetworkFixture(t, &n, adaptiveAuthorityPlan(t, []configuration.ProfileReference{n.ref}))
	proposal.Bundles[0].Layers = n.approved.Layers
	preview := prepareLayerPreview(t, n, control, proposal, publisher, "actual adaptive preview")
	if preview.Preview.DependencyHash == "" || preview.Preview.EffectiveHash == "" {
		t.Fatal("adaptive compiler was not part of the signed actual preview")
	}
	queued := queueLayerPublish(t, n, control, preview, "actual adaptive publish")
	if err := publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := fixtureOwner.QueryRow(`SELECT state FROM managed_configuration_requests WHERE id=$1`, queued.ID).Scan(&state); err != nil || state != "published" {
		t.Fatal("actual adaptive desired head was not published", err)
	}
	reader := &SQLNetworkLayers{Store: publisher.Store, ControlOrigin: control.Origin, Roots: publisher.Roots}
	n.publisher.Configurations = &NetworkAuthority{Layers: reader, Sources: publisher.Sources}
	if err := n.publisher.RunOnce(context.Background(), n.f.now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	verified := verifyAdaptivePublication(t, n, 2)
	if verified.AlgorithmRevision != configuration.AdaptiveTCPAlgorithm {
		t.Fatal("actual SQL reader changed the previewed algorithm")
	}
	var sourceRevision, policyRevision int64
	var sourceHash string
	if err := fixtureOwner.QueryRow(`SELECT publication_source_revision,publication_source_policy_revision,publication_source_hash FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&sourceRevision, &policyRevision, &sourceHash); err != nil || sourceRevision != 1 || policyRevision != 2 || sourceHash != preview.Preview.DraftHash {
		t.Fatal("signed adaptive publication lost the actual approved configuration binding", err)
	}
}
