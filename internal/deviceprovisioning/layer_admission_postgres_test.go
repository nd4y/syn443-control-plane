//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestFreshInvitationIdentityCanReceiveFirstApprovedLayeredConfiguration(t *testing.T) {
	n, c, p, s := configurationWorkFixture(t)
	roots := map[string]*ecdsa.PublicKey{"fixture-root": &n.f.key.PublicKey}
	n.publisher.Configurations = &NetworkAuthority{Sources: n.authority.Sources, Layers: &SQLNetworkLayers{Store: s.Store, ControlOrigin: c.Origin, Roots: roots}}
	if e := n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	var approved bool
	var cipher []byte
	var revision int64
	if e := fixtureOwner.QueryRow(`SELECT approved,publication,revision FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&approved, &cipher, &revision); e != nil || !approved || cipher != nil || revision != 0 {
		t.Fatal("fresh identity not admitted independently", e)
	}
	view, e := inventoryCall(t, n, c, n.target.Device, "fresh identity inventory")
	if e != nil || view.State != "unassigned" {
		t.Fatal("fresh identity not configurable", e)
	}
	publisher := &ConfigurationPublisher{Store: s.Store, Sources: n.authority.Sources, Verifier: c.Verifier, Origin: c.Origin, AssuranceACR: c.AssuranceACR, Key: n.f.key, KeyID: "fixture-root", Roots: roots}
	r := prepareLayerPreview(t, n, c, p, publisher, "fresh identity first preview")
	queueLayerPublish(t, n, c, r, "fresh identity first publish")
	if e = publisher.RunOnce(context.Background(), n.f.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = n.publisher.RunOnce(context.Background(), n.f.now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, n.target.Device).Scan(&revision, &cipher); e != nil || revision != 1 || len(cipher) == 0 {
		t.Fatal("first layered policy not issued", e)
	}
	raw, e := n.publisher.Store.Open(cipher, "publication/v1/"+n.target.Device+"/"+fmt.Sprint(revision))
	if e != nil {
		t.Fatal(e)
	}
	verified, e := policy.VerifyBound(string(raw), roots, n.target.Device, n.target.Thumbprint, n.f.now.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	native, e := base64.RawURLEncoding.DecodeString(verified.EngineConfigB64)
	if e != nil || !bytes.Contains(native, []byte("proxy.example.invalid")) {
		t.Fatal("raw owner grant substituted for approved layered plan", e)
	}
}
