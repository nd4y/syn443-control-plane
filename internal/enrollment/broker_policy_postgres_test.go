//go:build postgres

package enrollment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func brokerPolicyFixture(t *testing.T) (*brokerFixture, *Publisher, *BrokerPolicies) {
	t.Helper()
	f := newBrokerFixture(t)
	f.grant.OverlayGroups = map[string][]string{f.binding.Address.ResourceID: {"group-a"}}
	if e := Authorize(context.Background(), fixtureOwner, f.grant, f.now); e != nil {
		t.Fatal(e)
	}
	resource := BrokerPolicyResource{ResourceID: f.binding.Address.ResourceID, Revision: 1, AccountID: "account-a", ManagementOrigin: f.binding.Address.ManagementURL, NetworkID: f.binding.Address.NetworkID, Groups: []string{"group-a"}}
	m, e := NewBrokerPolicies(f.overlayFixture.worker, f.api.OverlayServiceID, []BrokerPolicyResource{resource})
	if e != nil {
		t.Fatal(e)
	}
	p := f.publisher()
	p.Brokers = m
	return f, p, m
}
func currentBrokerHead(t *testing.T, m *BrokerPolicies, namespace string) brokerPolicyHead {
	t.Helper()
	h, e := m.readHead(context.Background(), namespace)
	if e != nil || h == nil {
		t.Fatal("missing materialized reference head", e)
	}
	return *h
}
func TestSQLBrokerPolicyReservesReferenceWithPublicationAndDeliversWithoutWaitingForRefresh(t *testing.T) {
	f, p, m := brokerPolicyFixture(t)
	if e := p.publish(context.Background(), f.session.DeviceID, f.now); e != nil {
		t.Fatal("materialized publication", e)
	}
	head := currentBrokerHead(t, m, f.request.Namespace)
	if head.reference == f.binding.Reference || head.version != 1 {
		t.Fatal("caller-supplied setup reference was trusted")
	}
	b, state, _, e := m.readHeadScope(context.Background(), head)
	if e != nil || state != "queued" || b.GrantHash != f.grant.Hash() {
		t.Fatal("broker scope not atomic with policy", e)
	}
	f.scope = b
	f.request.Reference = head.reference
	f.request.Version = head.version
	f.binding = b.Binding
	f.store.OverlayBrokerPending = true
	expect(t, f.call(t, false), 202)
	f.run(t)
	if e = m.DeliverReady(context.Background(), p, f.api.Roots, f.clock); e != nil {
		t.Fatal("short addressed delivery poll", e)
	}
	f.clock = f.clock.Add(time.Second)
	f.api.Clock = func() time.Time { return f.clock }
	reply := f.call(t, false)
	expect(t, reply, 200)
	var delivered OverlayReply
	if json.Unmarshal(reply.Body.Bytes(), &delivered) != nil || delivered.Envelope == "" {
		t.Fatal("managed credential not delivered")
	}
	if e = p.publish(context.Background(), f.session.DeviceID, f.clock); e != nil {
		t.Fatal("ordinary policy renewal", e)
	}
	if after := currentBrokerHead(t, m, f.request.Namespace); after != head {
		t.Fatal("policy refresh changed SDK identity/reference")
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_broker`).Scan(&count); e != nil || count != 1 {
		t.Fatal("policy refresh queued another key", e)
	}
}
func TestSQLBrokerPolicyRenewsOnlyConfirmedUnusedClearedKeyAndRetainsNamespace(t *testing.T) {
	f, p, m := brokerPolicyFixture(t)
	if e := p.publish(context.Background(), f.session.DeviceID, f.now); e != nil {
		t.Fatal(e)
	}
	before := currentBrokerHead(t, m, f.request.Namespace)
	scope, _, _, e := m.readHeadScope(context.Background(), before)
	if e != nil {
		t.Fatal(e)
	}
	f.scope = scope
	f.run(t)
	f.clock = f.now.Add(6 * time.Minute)
	f.run(t)
	f.run(t)
	if f.state(t) != "cleared" {
		t.Fatal("fixture did not preserve unused cleanup")
	}
	if e = m.Schedule(context.Background(), f.clock); e != nil {
		t.Fatal(e)
	}
	if e = p.RunOnce(context.Background(), f.clock); e != nil {
		t.Fatal(e)
	}
	after := currentBrokerHead(t, m, f.request.Namespace)
	if after.namespace != before.namespace || after.reference == before.reference || after.version != before.version+1 {
		t.Fatal("safe renewal lost stable namespace or reused a reference")
	}
	var retired bool
	if e = fixtureOwner.QueryRow(`SELECT retire FROM identity_overlay_broker WHERE reference=$1`, before.reference).Scan(&retired); e != nil || !retired {
		t.Fatal("old unused record not queued for retirement", e)
	}
}
func TestSQLBrokerPolicyNeverReissuesKnownRegisteredNamespaceOrUnknownCreation(t *testing.T) {
	for _, state := range []string{"established", "uncertain"} {
		t.Run(state, func(t *testing.T) {
			f, p, m := brokerPolicyFixture(t)
			if e := p.publish(context.Background(), f.session.DeviceID, f.now); e != nil {
				t.Fatal(e)
			}
			before := currentBrokerHead(t, m, f.request.Namespace)
			used := 0
			if state == "established" {
				used = 1
			}
			if _, e := fixtureOwner.Exec(`UPDATE identity_overlay_broker SET state=$1,provider_used=$2`, state, used); e != nil {
				t.Fatal(e)
			}
			if e := p.publish(context.Background(), f.session.DeviceID, f.now.Add(6*time.Minute)); e != nil {
				t.Fatal(e)
			}
			if after := currentBrokerHead(t, m, f.request.Namespace); after != before {
				t.Fatal("existing or unknown registration silently re-enrolled")
			}
		})
	}
}
func TestSQLBrokerPolicyRejectsForeignResourceGroupsCapabilityAndCompetingHead(t *testing.T) {
	for _, scenario := range []string{"groups", "resource", "missing-user-groups", "owner"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, m := brokerPolicyFixture(t)
			switch scenario {
			case "groups":
				f.grant.OverlayGroups[f.binding.Address.ResourceID] = []string{"foreign"}
			case "resource":
				delete(m.resources, f.binding.Address.ResourceID)
			case "missing-user-groups":
				f.grant.OverlayGroups = nil
			case "owner":
				f.grant.Subject = "foreign-owner"
			}
			p.Grants = map[string]Grant{Owner(f.grant.Issuer, f.grant.Subject): f.grant}
			if scenario != "owner" {
				if e := Authorize(context.Background(), fixtureOwner, f.grant, f.now); e != nil {
					t.Fatal(e)
				}
			}
			if e := p.publish(context.Background(), f.session.DeviceID, f.now); e == nil {
				t.Fatal("unauthorized broker policy published")
			}
			var count int
			if e := fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_reference_heads`).Scan(&count); e != nil || count != 0 {
				t.Fatal("failed publication left side-effect head", e)
			}
		})
	}
	f, p, m := brokerPolicyFixture(t)
	if e := p.publish(context.Background(), f.session.DeviceID, f.now); e != nil {
		t.Fatal(e)
	}
	before := currentBrokerHead(t, m, f.request.Namespace)
	// A competing head observed after preparation is a CAS conflict, never an
	// instruction to overwrite the winner's operation or delete its provider key.
	var protected []byte
	var revision int64
	if e := fixtureOwner.QueryRow(`SELECT publication,revision FROM identity_devices WHERE id=$1`, f.session.DeviceID).Scan(&protected, &revision); e != nil {
		t.Fatal(e)
	}
	raw, e := f.overlayFixture.worker.Open(protected, "publication/v1/"+f.session.DeviceID+"/"+formatInt(revision))
	if e != nil {
		t.Fatal(e)
	}
	payload, e := policy.VerifyBound(string(raw), f.api.Roots, f.session.DeviceID, f.binding.KeyThumbprint, f.now)
	if e != nil {
		t.Fatal(e)
	}
	target := ConfigurationTarget{Device: f.session.DeviceID, Owner: f.scope.Owner, Thumbprint: f.binding.KeyThumbprint, GrantHash: f.grant.Hash(), CurrentRevision: revision, Capabilities: []string{"overlay.credentials.v1"}}
	fence, e := m.Prepare(context.Background(), target, f.grant, &payload, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_overlay_reference_heads SET reference=$1,version=version+1`, random()); e != nil {
		t.Fatal(e)
	}
	tx, e := fixturePublisher.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = fence.Lock(context.Background(), tx, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("competing reference head not fenced", e)
	}
	if before.reference == "" {
		t.Fatal("invalid before head")
	}
}
func TestSQLBrokerPolicyReferenceIsInActualSignedEngineAndPreservesOriginalDeadline(t *testing.T) {
	f, p, m := brokerPolicyFixture(t)
	if e := p.publish(context.Background(), f.session.DeviceID, f.now); e != nil {
		t.Fatal(e)
	}
	_, _, envelope := publishedConfiguration(t, f.fixture, f.session.DeviceID)
	payload, e := policy.VerifyBound(envelope, f.api.Roots, f.session.DeviceID, f.binding.KeyThumbprint, f.now)
	if e != nil {
		t.Fatal(e)
	}
	engine, e := base64.RawURLEncoding.DecodeString(payload.EngineConfigB64)
	if e != nil {
		t.Fatal(e)
	}
	var document struct {
		Outbounds []struct {
			Managed ManagedOverlayReference `json:"managed"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(engine, &document) != nil {
		t.Fatal("signed engine shape")
	}
	head := currentBrokerHead(t, m, f.request.Namespace)
	if document.Outbounds[0].Managed.SetupReference != head.reference {
		t.Fatal("head not bound into signed engine")
	}
	scope, _, _, e := m.readHeadScope(context.Background(), head)
	if e != nil || scope.DeadlineMs != f.now.Add(5*time.Minute).UnixMilli() {
		t.Fatal("unexpected setup-key lifetime", e)
	}
}

func TestSQLBrokerPoliciesDoNotRequireOverlayCapabilityForAPlainAuthorizedDevice(t *testing.T) {
	f := newFixture(t, 2)
	session, _, _ := f.register(t, key(t))
	p := f.publisher()
	m, e := NewBrokerPolicies(f.worker, "fixture-service", []BrokerPolicyResource{brokerPolicyResourceExample()})
	if e != nil {
		t.Fatal(e)
	}
	p.Brokers = m
	if e = p.publish(context.Background(), session.DeviceID, f.now); e != nil {
		t.Fatal("plain policy was blocked by optional broker", e)
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM identity_overlay_reference_heads`).Scan(&count); e != nil || count != 0 {
		t.Fatal("plain policy allocated overlay state", e)
	}
}
func TestSQLBrokerPolicyMissingCapabilityAndPostPrepareExpiryCannotReserve(t *testing.T) {
	f, _, m := brokerPolicyFixture(t)
	payload := f.grant.Template
	target := ConfigurationTarget{Device: f.session.DeviceID, Owner: Owner(f.grant.Issuer, f.grant.Subject), Thumbprint: f.binding.KeyThumbprint, GrantHash: f.grant.Hash(), Capabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}}
	if _, e := m.Prepare(context.Background(), target, f.grant, &payload, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("missing advertised runtime capability accepted", e)
	}
	if _, e := m.Prepare(nil, target, f.grant, &payload, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("nil context accepted", e)
	}
	if e := (&brokerPolicyFence{policies: m, until: f.now.UnixMilli()}).Lock(context.Background(), nil, f.now); !errors.Is(e, ErrDenied) {
		t.Fatal("expired unowned transaction accepted")
	}
}
