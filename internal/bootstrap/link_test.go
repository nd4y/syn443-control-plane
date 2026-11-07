package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestInvitationAuthenticatesBeforeAnyDiscoveryAndNeverSerializesCode(t *testing.T) {
	d, root, key, now := descriptorFixture(t)
	manifest, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	invite := Invitation{ServiceID: d.ServiceID, Origin: d.APIOrigin, Code: identity.Hash([]byte("synthetic-high-entropy-invite")), Manifest: manifest}
	raw, e := Link(invite)
	if e != nil {
		t.Fatal(e)
	}
	trusted, e := AuthenticateLink(raw, root, Floor{}, now)
	if e != nil || trusted.Code != invite.Code || trusted.Descriptor.ServiceID != invite.ServiceID {
		t.Fatal("invitation authentication", e)
	}
	for _, value := range []any{invite, trusted} {
		encoded, _ := json.Marshal(value)
		if bytes.Contains(encoded, []byte(invite.Code)) || bytes.Contains(encoded, []byte(manifest)) {
			t.Fatal("invitation credential serialized")
		}
	}
	for _, bad := range []string{raw + "&code=other", raw + "&extra=x", raw + "#fragment", strings.Replace(raw, "/v1?", "/v2?", 1), strings.Replace(raw, "syn443://enroll", "syn443://other", 1), strings.Replace(raw, "syn443:", "other:", 1), raw + "&%63ode=other", strings.Replace(raw, "service-a", "service-b", 1), strings.Repeat("x", MaxLink+1)} {
		if _, e = AuthenticateLink(bad, root, Floor{}, now); e == nil {
			t.Fatal("untrusted invitation accepted")
		}
	}
	changed := invite
	changed.Origin = "https://other.example.invalid"
	wrong, _ := Link(changed)
	if _, e = AuthenticateLink(wrong, root, Floor{}, now); e == nil {
		t.Fatal("manifest sent code to different origin")
	}
	changed = invite
	decoded, _ := base64.RawURLEncoding.DecodeString(changed.Code)
	decoded[len(decoded)-1] ^= 1
	changed.Code = base64.RawURLEncoding.EncodeToString(decoded)
	if _, e = Link(changed); e != nil {
		t.Fatal("independent valid random code", e)
	}
	changed.Code = "invalid"
	if _, e = Link(changed); e == nil {
		t.Fatal("short invitation credential")
	}
	if RedactLink(raw) != "syn443:[redacted]" || RedactLink("other") != "[redacted]" {
		t.Fatal("diagnostic redaction")
	}
}

func FuzzInvitationLink(f *testing.F) {
	f.Add("syn443://enroll/v1?service=synthetic")
	f.Add("syn443://enroll/v1?code=a&code=b")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > MaxLink+1 {
			return
		}
		parsed, e := ParseLink(raw)
		if e == nil {
			encoded, e := Link(parsed)
			if e != nil || len(encoded) > MaxLink {
				t.Fatal("valid parse cannot re-encode")
			}
		}
	})
}
