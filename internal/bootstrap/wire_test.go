package bootstrap

import (
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type wireParts struct {
	Header    string `json:"header"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func (p wireParts) compact() string {
	return strings.Join([]string{p.Header, p.Payload, p.Signature}, ".")
}
func TestSharedGoKotlinBootstrapCertificates(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/bootstrap-wire-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Version  int       `json:"version"`
		Now      int64     `json:"now"`
		Anchor   Anchor    `json:"anchor"`
		Manifest wireParts `json:"manifest"`
		Floor    Floor     `json:"floor"`
		Previous wireParts `json:"previous"`
		Next     wireParts `json:"next"`
		Advanced Anchor    `json:"advanced"`
		Fresh    wireParts `json:"fresh"`
		NewFloor Floor     `json:"newFloor"`
		Code     string    `json:"code"`
	}
	if identity.Decode(raw, &fixture, true) != nil || fixture.Version != 1 {
		t.Fatal("shared bootstrap fixture")
	}
	now := time.Unix(fixture.Now, 0)
	d, floor, e := VerifyDescriptor(fixture.Manifest.compact(), fixture.Anchor, Floor{}, now)
	if e != nil || floor != fixture.Floor {
		t.Fatal("shared service floor", e)
	}
	advanced, e := AdvanceRoot(Rotation{fixture.Previous.compact(), fixture.Next.compact()}, fixture.Anchor, now)
	if e != nil || advanced != fixture.Advanced {
		t.Fatal("shared dual-authority transition", e)
	}
	_, next, e := VerifyDescriptor(fixture.Fresh.compact(), advanced, floor, now)
	if e != nil || next != fixture.NewFloor {
		t.Fatal("shared new root descriptor", e)
	}
	if _, _, e := VerifyDescriptor(fixture.Manifest.compact(), advanced, Floor{}, now); e == nil {
		t.Fatal("shared retired root remained enrollment authority")
	}
	link, e := Link(Invitation{ServiceID: d.ServiceID, Origin: d.APIOrigin, Code: fixture.Code, Manifest: fixture.Manifest.compact()})
	if e != nil {
		t.Fatal(e)
	}
	if value, e := AuthenticateLink(link, fixture.Anchor, Floor{}, now); e != nil || value.Floor != floor || value.Code != fixture.Code {
		t.Fatal("shared authenticated invitation", e)
	}
}
