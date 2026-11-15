//go:build postgres

package deviceprovisioning

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

func TestConfigurationAssuranceChallengePreservesEveryMutationAndItsObjectScope(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	preview := prepareLayerPreview(t, n, c, p, publisher, "assurance-preview")
	queueLayerPublish(t, n, c, preview, "assurance-initial-publication")
	n.f.now = n.f.now.Add(time.Second)
	if e := publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	draft := ConfigurationDraft{ID: p.DraftID, Proposal: p}
	if _, e := draftCall(t, n, c, "configuration.layers.draft.put", "assurance-save", map[string]any{"draft": draft}); e != nil {
		t.Fatal(e)
	}
	n.f.v.p.ACR = "0"
	n.f.v.p.Methods = nil
	n.f.v.p.AuthTime = n.f.now.Add(-time.Hour).Unix()
	for _, v := range []struct {
		action  string
		payload any
	}{
		{"configuration.preview.request", configurationPreviewInput{p}},
		{"configuration.publish", configurationPublishInput{preview.PreviewID, preview.Ticket}},
		{"configuration.layers.draft.put", map[string]any{"draft": draft}},
		{"configuration.layers.draft.get", map[string]string{"id": p.DraftID}},
		{"configuration.layers.draft.discard", ConfigurationDraftDiscard{ID: p.DraftID, Revision: 1, TargetKind: p.TargetKind, TargetID: p.TargetID}},
		{"configuration.request.get", map[string]string{"id": preview.PreviewID}},
		{"configuration.history.get", map[string]any{"id": n.target.Device, "revision": 1, "hash": preview.Preview.DraftHash}},
	} {
		t.Run(v.action, func(t *testing.T) {
			raw, token, proof := configurationCall(t, n, c, v.action, identity.Hash([]byte("assurance "+v.action)), v.payload)
			if _, e := c.ControlAction(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, catalog.ErrReauthentication) || !errors.Is(e, catalog.ErrDenied) {
				t.Fatal("scoped assurance denial missing", e)
			}
			if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
				t.Fatal(e)
			}
			if _, e := c.ControlAction(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, catalog.ErrDenied) || errors.Is(e, catalog.ErrReauthentication) {
				t.Fatal("withdrawn scope produced a recovery challenge", e)
			}
			if _, e := fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'*','*','*',$2)`, n.actor.ID, n.f.now.Unix()+3600); e != nil {
				t.Fatal(e)
			}
		})
	}
	var queued, heads, revisions int
	if e := fixtureOwner.QueryRow(`SELECT (SELECT count(*) FROM managed_configuration_requests WHERE state='queued'),(SELECT count(*) FROM managed_configuration_heads),(SELECT max(revision) FROM managed_configuration_drafts)`).Scan(&queued, &heads, &revisions); e != nil || queued != 0 || heads != 1 || revisions != 1 {
		t.Fatal("reauthentication preflight changed a draft or publication", e)
	}
}

func TestConfigurationAssuranceRejectsInvalidProofForeignMetadataAndExpiredAuthority(t *testing.T) {
	n, c, p, publisher := layerPublisherFixture(t)
	r := prepareLayerPreview(t, n, c, p, publisher, "assurance-boundary-preview")
	n.f.v.p.ACR = "0"
	n.f.v.p.Methods = nil
	for _, v := range []struct {
		action  string
		payload any
	}{
		{"configuration.publish", configurationPublishInput{r.PreviewID, "wrong-ticket"}},
		{"configuration.layers.draft.get", map[string]string{"id": "another-private-draft"}},
		{"configuration.request.get", map[string]string{"id": identity.Hash([]byte("another-private-request"))}},
		{"configuration.layers.draft.discard", ConfigurationDraftDiscard{ID: "../invalid", Revision: 1, TargetKind: "device", TargetID: p.TargetID}},
		{"configuration.preview.request", configurationPreviewInput{LayerProposal{}}},
	} {
		raw, token, proof := configurationCall(t, n, c, v.action, identity.Hash([]byte("boundary "+v.action)), v.payload)
		if _, e := c.ControlAction(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, catalog.ErrDenied) || errors.Is(e, catalog.ErrReauthentication) {
			t.Fatal("foreign or invalid input received a recovery hint", e)
		}
	}
	raw, token, _ := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("bad assurance proof")), configurationPreviewInput{p})
	if _, e := c.ControlAction(context.Background(), token, "invalid", raw, n.f.now); !errors.Is(e, catalog.ErrDenied) || errors.Is(e, catalog.ErrReauthentication) {
		t.Fatal("unverified proof received a recovery hint", e)
	}
	input, _ := json.Marshal(configurationPreviewInput{p})
	envelope := invitation.Envelope{Version: 1, Action: "configuration.preview.request", RequestID: identity.Hash([]byte("expired assurance")), Payload: input}
	if e := c.reauthenticationAuthority(context.Background(), n.actor.ID, envelope, n.f.now.Unix(), n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("expired preflight authority", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := c.reauthenticationAuthority(ctx, n.actor.ID, envelope, n.f.now.Unix()+60, n.f.now); e == nil {
		t.Fatal("cancelled preflight succeeded")
	}
}
