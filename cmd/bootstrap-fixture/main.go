// Generates public interoperability certificates only in disposable Actions.
// Private fixture keys are ephemeral and are never serialized or uploaded.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type parts struct {
	Header    string `json:"header"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func split(raw string) parts { v := strings.Split(raw, "."); return parts{v[0], v[1], v[2]} }
func key(id string, epoch int64) (bootstrap.Anchor, *ecdsa.PrivateKey, error) {
	private, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return bootstrap.Anchor{}, nil, e
	}
	public, e := bootstrap.Public(&private.PublicKey)
	return bootstrap.Anchor{ID: id, Epoch: epoch, SPKI: public}, private, e
}
func run() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return bootstrap.ErrUntrusted
	}
	old, oldKey, e := key("offline-fixture-a", 1)
	if e != nil {
		return e
	}
	next, newKey, e := key("offline-fixture-b", 2)
	if e != nil {
		return e
	}
	online, _, e := key("online-fixture-a", 1)
	if e != nil {
		return e
	}
	now := time.Unix(1800000000, 0)
	d := bootstrap.Descriptor{SchemaVersion: 1, Audience: "syn443-client-bootstrap", RootEpoch: 1, Revision: 1, ServiceID: "fixture-service", Issuer: "https://identity.example.invalid/realms/test", ClientID: "syn443-android", APIOrigin: "https://api.example.invalid", Roots: map[string]string{online.ID: online.SPKI}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	manifest, e := bootstrap.SignDescriptor(d, old, oldKey, now)
	if e != nil {
		return e
	}
	_, floor, e := bootstrap.VerifyDescriptor(manifest, old, bootstrap.Floor{}, now)
	if e != nil {
		return e
	}
	transition := bootstrap.Transition{SchemaVersion: 1, Audience: "syn443-root-transition", From: old.ID, To: next.ID, SPKI: next.SPKI, Epoch: 2, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	rotation, e := bootstrap.SignRotation(transition, old, oldKey, newKey, now)
	if e != nil {
		return e
	}
	advanced, e := bootstrap.AdvanceRoot(rotation, old, now)
	if e != nil {
		return e
	}
	d.RootEpoch = 2
	d.Revision = 2
	fresh, e := bootstrap.SignDescriptor(d, advanced, newKey, now)
	if e != nil {
		return e
	}
	_, newFloor, e := bootstrap.VerifyDescriptor(fresh, advanced, floor, now)
	if e != nil {
		return e
	}
	// Parts are public signature evidence, not bearer tokens. The synthetic code
	// is unassigned: no test service/account is enrolled by this command.
	fixture := struct {
		Version  int              `json:"version"`
		Now      int64            `json:"now"`
		Anchor   bootstrap.Anchor `json:"anchor"`
		Manifest parts            `json:"manifest"`
		Floor    bootstrap.Floor  `json:"floor"`
		Previous parts            `json:"previous"`
		Next     parts            `json:"next"`
		Advanced bootstrap.Anchor `json:"advanced"`
		Fresh    parts            `json:"fresh"`
		NewFloor bootstrap.Floor  `json:"newFloor"`
		Code     string           `json:"code"`
	}{1, now.Unix(), old, split(manifest), floor, split(rotation.Previous), split(rotation.Next), advanced, split(fresh), newFloor, identity.Hash([]byte("unassigned-synthetic-invitation"))}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(fixture)
}
func main() {
	if run() != nil {
		os.Stderr.WriteString("bootstrap_fixture_failed\n")
		os.Exit(1)
	}
}
