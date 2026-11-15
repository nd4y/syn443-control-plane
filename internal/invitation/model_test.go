package invitation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestClaimBoundsAndProtectedDataDomains(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := random()
	code, _ := random()
	base := Claim{RequestID: id, Code: code, Key: identity.PublicJWK(&key.PublicKey), Capabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}}
	if base.validate() != nil {
		t.Fatal("valid claim")
	}
	for _, change := range []func(*Claim){func(c *Claim) { c.Code = "short" }, func(c *Claim) { c.RequestID = "short" }, func(c *Claim) { c.Key.X = "invalid" }, func(c *Claim) {
		c.Capabilities = []string{"engine-config.v1", "engine-config.v1", "policy.keybound.v2"}
	}, func(c *Claim) { c.Capabilities = []string{"one", "two", "three"} }, func(c *Claim) { c.Capabilities = make([]string, 17) }} {
		bad := base
		change(&bad)
		if bad.validate() == nil {
			t.Fatal("invalid claim")
		}
	}
	// No actual connection is used by the cryptographic envelope unit tests.
	store, e := NewStore(&sql.DB{}, bytes.Repeat([]byte{37}, 32))
	if e != nil {
		t.Fatal(e)
	}
	plain := []byte("synthetic-private-claim-payload")
	sealed, e := store.seal(plain, "claim/a")
	if e != nil || bytes.Contains(sealed, plain) {
		t.Fatal("private claim envelope", e)
	}
	opened, e := store.open(sealed, "claim/a")
	if e != nil || !bytes.Equal(opened, plain) {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{nil, sealed[:8], append(append([]byte(nil), sealed[:len(sealed)-1]...), sealed[len(sealed)-1]^1)} {
		if _, e = store.open(bad, "claim/a"); e == nil {
			t.Fatal("corrupt envelope accepted")
		}
	}
	if _, e = store.open(sealed, "claim/b"); e == nil {
		t.Fatal("cross-invitation ciphertext reused")
	}
	if _, e = store.seal(make([]byte, 262145), "claim/a"); e == nil {
		t.Fatal("unbounded private payload")
	}
	if _, e = NewStore(nil, make([]byte, 32)); e == nil {
		t.Fatal("nil durable store")
	}
	if _, e = NewStore(&sql.DB{}, make([]byte, 31)); e == nil {
		t.Fatal("invalid envelope key")
	}
	for _, value := range []any{store, base, Receipt{Token: "synthetic-secret"}, Issued{Link: "syn443://synthetic-secret"}, ClaimState{Nonce: "synthetic-secret"}, View{PairCode: "synthetic-secret"}} {
		if strings.Contains(fmt.Sprintf("%v %#v", value, value), "synthetic-secret") {
			t.Fatal("secret formatter")
		}
	}
	raw, e := base.EnrollmentRequest()
	if e != nil {
		t.Fatal(e)
	}
	var request map[string]any
	json.Unmarshal(raw, &request)
	if len(request) != 3 || request["code"] != nil {
		t.Fatal("code exported to public device request")
	}
	for i := 0; i < 32; i++ {
		value, e := pair()
		if e != nil || len(value) != 6 || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			t.Fatal("pairing comparison code", e)
		}
	}
}
