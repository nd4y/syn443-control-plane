//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

func configurationControlFixture(t *testing.T) (networkFixture, *ConfigurationControl, LayerProposal) {
	t.Helper()
	n := newNetworkFixture(t)
	store, e := enrollment.NewStore(fixtureControl, bytes.Repeat([]byte{91}, 32))
	if e != nil {
		t.Fatal(e)
	}
	c := &ConfigurationControl{Store: store, Verifier: n.f.v, Origin: "https://control.example.invalid", AssuranceACR: "urn:syn443:loa:2"}
	p := LayerProposal{DraftID: "draft-a", DraftRevision: 1, TargetKind: "device", TargetID: n.target.Device, Mode: "wifi", ApprovalUntilMs: n.f.now.Add(24 * time.Hour).UnixMilli(), Bundles: []LayerBundle{{Device: n.target.Device, Layers: n.approved.Layers}}}
	return n, c, p
}

func configurationCall(t *testing.T, n networkFixture, c *ConfigurationControl, action, operation string, payload any) ([]byte, string, string) {
	t.Helper()
	body, e := json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(invitation.Envelope{Version: 1, Action: action, RequestID: operation, Payload: body})
	if e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("synthetic-control-token-", 2)
	proof := signed(t, n.f.key, c.Origin+"/v1/control/action", token, "", raw, n.f.now)
	return raw, token, proof
}

func TestSQLConfigurationQueuePreservesOriginalReceiptAndLostReplyOperation(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	ctx := context.Background()
	operation := identity.Hash([]byte("synthetic preview request"))
	raw, token, proof := configurationCall(t, n, c, "configuration.preview.request", operation, configurationPreviewInput{p})
	value, e := c.Dispatch(ctx, token, proof, raw, n.f.now)
	if e != nil {
		t.Fatal(e)
	}
	result := value.(ConfigurationRequestView)
	if result.State != "queued" {
		t.Fatal("not queued")
	}
	var encrypted []byte
	var bodyHash string
	if e = fixtureOwner.QueryRow(`SELECT receipt,body_hash FROM managed_configuration_requests WHERE id=$1`, result.ID).Scan(&encrypted, &bodyHash); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(encrypted, raw) || bytes.Contains(encrypted, []byte(token)) || bodyHash != configurationHash(raw) {
		t.Fatal("plaintext or unbound receipt")
	}
	plain, e := c.Store.Open(encrypted, configurationRequestAAD(result.ID))
	var receipt invitation.Receipt
	if e != nil || identity.DecodeConfiguration(plain, &receipt) != nil || !bytes.Equal(receipt.Body, raw) || receipt.Token != token || receipt.Proof != proof {
		t.Fatal("original authority was not retained", e)
	}
	actor, envelope, until, e := verifyConfigurationReceipt(ctx, c.Verifier, receipt, c.Origin, c.AssuranceACR, n.f.now)
	if e != nil || actor != n.actor.ID || envelope.RequestID != operation || until <= n.f.now.Unix() {
		t.Fatal("independent replay verification", e)
	}
	_, _, newProof := configurationCall(t, n, c, "configuration.preview.request", operation, configurationPreviewInput{p})
	value, e = c.Dispatch(ctx, token, newProof, raw, n.f.now)
	if e != nil || value.(ConfigurationRequestView).ID != result.ID {
		t.Fatal("lost reply changed operation", e)
	}
	var count int
	var unchanged []byte
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_requests`).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate request", e)
	}
	if e = fixtureOwner.QueryRow(`SELECT receipt FROM managed_configuration_requests WHERE id=$1`, result.ID).Scan(&unchanged); e != nil || !bytes.Equal(unchanged, encrypted) {
		t.Fatal("retry replaced original receipt", e)
	}
	get, token, getProof := configurationCall(t, n, c, "configuration.request.get", identity.Hash([]byte("synthetic request get")), map[string]string{"id": result.ID})
	value, e = c.Dispatch(ctx, token, getProof, get, n.f.now)
	if e != nil || value.(ConfigurationRequestView).State != "queued" {
		t.Fatal("queue view", e)
	}
	p.DraftRevision++
	changed, token, changedProof := configurationCall(t, n, c, "configuration.preview.request", operation, configurationPreviewInput{p})
	if _, e = c.Dispatch(ctx, token, changedProof, changed, n.f.now); !errors.Is(e, enrollment.ErrConflict) {
		t.Fatal("same operation overwrote input", e)
	}
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl`); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Dispatch(ctx, token, getProof, get, n.f.now); e == nil {
		t.Fatal("read survived current ACL revoke")
	}
	if _, e = c.Dispatch(ctx, token, newProof, raw, n.f.now); e == nil {
		t.Fatal("retry survived current ACL revoke")
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", c, c, result, result), result.ID) {
		t.Fatal("administrative diagnostic leak")
	}
}

func TestSQLConfigurationQueueCannotApproveHeadsOrBorrowAdministrativeScope(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	ctx := context.Background()
	raw, token, proof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("synthetic scope request")), configurationPreviewInput{p})
	original := n.f.v.p
	for _, change := range []string{"expired", "mfa", "method", "acr", "scope", "key", "subject", "tampered", "missing-verifier"} {
		t.Run(change, func(t *testing.T) {
			n.f.v.p = original
			copy := *c
			body := raw
			switch change {
			case "expired":
				n.f.v.p.Expires = n.f.now.Unix()
			case "mfa":
				n.f.v.p.AuthTime = n.f.now.Add(-10 * time.Minute).Unix()
			case "method":
				n.f.v.p.Methods = nil
			case "acr":
				n.f.v.p.ACR = "untrusted-acr"
			case "scope":
				n.f.v.p.Scope = "syn443.chat"
			case "key":
				n.f.v.p.Thumbprint = identity.Hash([]byte("different DPoP key"))
			case "subject":
				n.f.v.p.Subject = "foreign-admin"
			case "tampered":
				body = append(append([]byte(nil), raw...), ' ')
			case "missing-verifier":
				copy.Verifier = nil
			}
			if _, e := copy.Dispatch(ctx, token, proof, body, n.f.now); e == nil {
				t.Fatal("untrusted administrative input queued")
			}
		})
	}
	n.f.v.p = original
	for _, query := range []string{`INSERT INTO managed_configuration_requests(id,state) VALUES('untrusted','ready')`, `UPDATE managed_configuration_requests SET state='applied'`, `UPDATE managed_configuration_requests SET receipt=decode('00','hex')`} {
		if _, e := fixtureControl.Exec(query); e == nil {
			t.Fatal("API acquired result/authority mutation")
		}
	}
	if _, e := fixtureSourceWorker.Exec(`SELECT receipt FROM managed_configuration_requests`); e == nil {
		t.Fatal("fetch worker obtained admin bearer/DPoP input")
	}
	var heads, versions int
	if e := fixtureOwner.QueryRow(`SELECT (SELECT count(*) FROM managed_configuration_heads),(SELECT count(*) FROM managed_configuration_versions)`).Scan(&heads, &versions); e != nil || heads != 0 || versions != 0 {
		t.Fatal("queue changed an active configuration", e)
	}
	if _, e := (*ConfigurationControl)(nil).Dispatch(ctx, token, proof, raw, n.f.now); e == nil {
		t.Fatal("nil control")
	}
	if _, e := c.Dispatch(nil, token, proof, raw, n.f.now); e == nil {
		t.Fatal("nil context")
	}
}

func TestSQLConfigurationQueueRejectsInvalidShapesAndBoundsAdmission(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	ctx := context.Background()
	for _, change := range []string{"kind", "target", "draft", "revision", "expiry", "mode", "bundle", "base", "plan"} {
		t.Run(change, func(t *testing.T) {
			raw, _ := json.Marshal(p)
			var proposal LayerProposal
			if json.Unmarshal(raw, &proposal) != nil {
				t.Fatal("copy")
			}
			switch change {
			case "kind":
				proposal.TargetKind = "all"
			case "target":
				proposal.TargetID = "../escape"
			case "draft":
				proposal.DraftID = ""
			case "revision":
				proposal.DraftRevision = 0
			case "expiry":
				proposal.ApprovalUntilMs = n.f.now.UnixMilli()
			case "mode":
				proposal.Mode = "unimplemented"
			case "bundle":
				proposal.Bundles = nil
			case "base":
				proposal.Bundles[0].BaseRevision = 1
			case "plan":
				proposal.Bundles[0].Layers = nil
			}
			body, token, proof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte(change)), configurationPreviewInput{proposal})
			if _, e := c.Dispatch(ctx, token, proof, body, n.f.now); e == nil {
				t.Fatal("invalid proposal admitted")
			}
		})
	}
	if _, e := fixtureOwner.Exec(`INSERT INTO managed_configuration_requests(id,actor,request_id,action,target_kind,target_id,created_ms,deadline_ms,body_hash,receipt) SELECT md5('fixture-job-'||i::text),$1,md5('fixture-op-'||i::text),'configuration.preview.request','device',$2,$3,$3+180000,repeat('0',64),decode(repeat('00',29),'hex') FROM generate_series(1,64) i`, n.actor.ID, n.target.Device, n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	raw, token, proof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("after quota")), configurationPreviewInput{p})
	if _, e := c.Dispatch(ctx, token, proof, raw, n.f.now); e == nil {
		t.Fatal("64 pending requests bound ignored")
	}
	if _, e := fixtureSigner.Exec(`UPDATE managed_configuration_requests SET body_hash='changed'`); e == nil {
		t.Fatal("publisher rewrote original input")
	}
}

func TestSQLConfigurationPublishQueueRetainsTicketAndCannotActivateItself(t *testing.T) {
	f := newStoredLayersFixture(t, "")
	store, e := enrollment.NewStore(fixtureControl, bytes.Repeat([]byte{62}, 32))
	if e != nil {
		t.Fatal(e)
	}
	c := &ConfigurationControl{Store: store, Verifier: f.n.f.v, Origin: f.preview.Origin, AssuranceACR: "urn:syn443:loa:2"}
	var ticket string
	if e = fixtureOwner.QueryRow(`SELECT ticket FROM managed_configuration_previews WHERE id=$1`, f.id).Scan(&ticket); e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"missing", "different-ticket", "invalid-shape", "wrong-key", "valid"} {
		t.Run(change, func(t *testing.T) {
			copy := *c
			input := configurationPublishInput{PreviewID: f.id, Ticket: ticket}
			var payload any = input
			switch change {
			case "missing":
				input.PreviewID = identity.Hash([]byte("foreign preview"))
				payload = input
			case "different-ticket":
				input.Ticket = "untrusted"
				payload = input
			case "invalid-shape":
				payload = map[string]any{"previewId": f.id, "ticket": ticket, "ready": true}
			case "wrong-key":
				copy.Store, e = enrollment.NewStore(fixtureControl, bytes.Repeat([]byte{92}, 32))
				if e != nil {
					t.Fatal(e)
				}
			}
			raw, token, proof := configurationCall(t, f.n, &copy, "configuration.publish", identity.Hash([]byte("publish/"+change)), payload)
			value, e := copy.Dispatch(context.Background(), token, proof, raw, f.n.f.now)
			if change == "valid" {
				if e != nil || value.(ConfigurationRequestView).State != "queued" {
					t.Fatal("publish request", e)
				}
			} else if e == nil {
				t.Fatal("untrusted ticket queued")
			}
		})
	}
	var revision int64
	if e = fixtureOwner.QueryRow(`SELECT revision FROM managed_configuration_heads WHERE device=$1`, f.n.target.Device).Scan(&revision); e != nil || revision != 1 {
		t.Fatal("API activated its own request", e)
	}
}

func TestConfigurationOriginalReceiptBoundsPurposeTimeAndBodyBinding(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	raw, token, proof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("receipt bounds")), configurationPreviewInput{p})
	base := invitation.Receipt{Token: token, Proof: proof, URI: c.Origin + "/v1/control/action", Body: raw, AcceptedAt: n.f.now.Unix()}
	for _, change := range []string{"future", "old", "uri", "short-token", "long-token", "large", "duplicate", "version", "action", "request-id", "proof"} {
		t.Run(change, func(t *testing.T) {
			r := base
			switch change {
			case "future":
				r.AcceptedAt++
			case "old":
				r.AcceptedAt -= 181
			case "uri":
				r.URI = "https://foreign.example.invalid/v1/control/action"
			case "short-token":
				r.Token = "short"
			case "long-token":
				r.Token = strings.Repeat("x", 16385)
			case "large":
				r.Body = bytes.Repeat([]byte("x"), 262145)
			case "duplicate":
				r.Body = []byte(`{"version":1,"version":1}`)
			case "version":
				r.Body = []byte(`{"version":2}`)
			case "action":
				r.Body = []byte(`{"version":1,"action":"invite.get","requestId":"synthetic-configuration-request","payload":{}}`)
			case "request-id":
				r.Body = []byte(`{"version":1,"action":"configuration.publish","requestId":"short","payload":{}}`)
			case "proof":
				r.Proof = "untrusted"
			}
			if actor, _, _, e := verifyConfigurationReceipt(context.Background(), c.Verifier, r, c.Origin, c.AssuranceACR, n.f.now); e == nil || actor != "" {
				t.Fatal("invalid original authority accepted")
			}
		})
	}
	// Exactly256KiB authentication input is supported; payload semantics remain
	// a separate closed validation and cannot be bypassed by a valid signature.
	payload := map[string]string{"padding": ""}
	body, _, _ := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("large bounded request")), payload)
	payload["padding"] = strings.Repeat("x", 262144-len(body))
	body, largeToken, largeProof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("large bounded request")), payload)
	if len(body) != 262144 {
		t.Fatal("size fixture")
	}
	r := invitation.Receipt{Token: largeToken, Proof: largeProof, URI: base.URI, Body: body, AcceptedAt: base.AcceptedAt}
	if _, _, _, e := verifyConfigurationReceipt(context.Background(), c.Verifier, r, c.Origin, c.AssuranceACR, n.f.now); e != nil {
		t.Fatal("bounded large receipt", e)
	}
	if _, e := c.Dispatch(context.Background(), largeToken, largeProof, body, n.f.now); e == nil {
		t.Fatal("signed unknown payload bypassed schema")
	}
}

func TestSQLConfigurationQueueExpiresAuthorityWhileWaitingForAdmission(t *testing.T) {
	n, c, p := configurationControlFixture(t)
	n.f.v.p.Expires = n.f.now.Unix() + 1
	lock, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback()
	if _, e = lock.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "configuration-requests/"+n.actor.ID); e != nil {
		t.Fatal(e)
	}
	raw, token, proof := configurationCall(t, n, c, "configuration.preview.request", identity.Hash([]byte("late authority request")), configurationPreviewInput{p})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := c.Dispatch(ctx, token, proof, raw, n.f.now); done <- e }()
	// Observe the real role waiting, not an arbitrary sleep before work starts.
	until := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if e = fixtureOwner.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='syn443_control_api' AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock%')`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		if time.Now().After(until) {
			t.Fatal("admission did not reach its lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(1100 * time.Millisecond)
	if e = lock.Rollback(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("expired token authority committed after admission wait", e)
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM managed_configuration_requests`).Scan(&count); e != nil || count != 0 {
		t.Fatal("expired authority left a queue side effect", e)
	}
}
