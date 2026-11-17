//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func operationVersionBusinessCounts(t *testing.T) map[string]int {
	t.Helper()
	values := map[string]int{}
	for _, table := range []string{"managed_configuration_drafts", "managed_configuration_draft_ops", "managed_configuration_requests", "managed_configuration_operations", "managed_configuration_operation_counters", "managed_configuration_previews", "managed_configuration_versions", "managed_configuration_heads", "managed_configuration_layer_versions", "managed_configuration_layer_heads", "managed_configuration_assignments"} {
		var count int
		if e := fixtureOwner.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil {
			t.Fatal(e)
		}
		values[table] = count
	}
	return values
}

func TestSQLOperationVersionReadUsesCurrentProofAndOwnerDeclarationWithoutTargetAclOrFreshMfa(t *testing.T) {
	n, c, _ := configurationControlFixture(t)
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	n.f.v.p.ACR = "0"
	n.f.v.p.Methods = nil
	n.f.v.p.AuthTime = n.f.now.Add(-time.Hour).Unix()
	before := operationVersionBusinessCounts(t)
	for _, version := range []int{0, 1, 2} {
		c.ConfigurationRequestVersion = version
		raw, token, proof := configurationCall(t, n, c, "configuration.protocol.get", identity.Hash([]byte("protocol-read/"+string(rune('0'+version)))), struct{}{})
		value, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
		got, ok := value.(ConfigurationProtocol)
		want := 1
		if version == 2 {
			want = 2
		}
		if e != nil || !ok || got.Version != 1 || got.ConfigurationRequestVersion != want {
			t.Fatal("closed eligibility read", e)
		}
	}
	if !reflect.DeepEqual(before, operationVersionBusinessCounts(t)) {
		t.Fatal("protocol read changed configuration state")
	}
}

func TestSQLOperationVersionReadRejectsInvalidExpiredForeignProofScopeRoleAndCancellation(t *testing.T) {
	for _, mode := range []string{"proof", "body", "scope", "expired", "key", "role", "cancel"} {
		n, c, _ := configurationControlFixture(t)
		c.ConfigurationRequestVersion = 2
		raw, token, proof := configurationCall(t, n, c, "configuration.protocol.get", identity.Hash([]byte("protocol-denied/"+mode)), struct{}{})
		ctx, cancel := context.WithCancel(context.Background())
		before := operationVersionBusinessCounts(t)
		switch mode {
		case "proof":
			proof = "invalid-proof"
		case "body":
			raw = append(raw, ' ')
		case "scope":
			n.f.v.p.Scope = "openid"
		case "expired":
			n.f.v.p.Expires = n.f.now.Unix()
		case "key":
			n.f.v.p.Thumbprint = identity.Hash([]byte("foreign-key"))
		case "role":
			var e error
			c.Store, e = enrollment.NewStore(fixtureOwner, bytes.Repeat([]byte{91}, 32))
			if e != nil {
				t.Fatal(e)
			}
		case "cancel":
			cancel()
		}
		if _, e := c.Dispatch(ctx, token, proof, raw, n.f.now); e == nil {
			t.Fatal("unbound or unauthorized read", mode)
		}
		cancel()
		if !reflect.DeepEqual(before, operationVersionBusinessCounts(t)) {
			t.Fatal("denied read changed configuration state", mode)
		}
	}
}

func TestSQLOperationVersionDeclarationNeverGrantsMutationAclMfaOrChangesExistingV2Acceptance(t *testing.T) {
	// CP58 acceptance is independent: a conservative owner advertisement does
	// not rewrite or disable an already body-bound version-two request.
	n, c, p := configurationControlFixture(t)
	raw, token, proof := operationOriginal(t, n, c, p, "v2-before-advertisement", 2)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e != nil {
		t.Fatal("existing v2 mutation acceptance changed", e)
	}
	read, token, proof := configurationCall(t, n, c, "configuration.protocol.get", identity.Hash([]byte("conservative-version")), struct{}{})
	value, e := c.Dispatch(context.Background(), token, proof, read, n.f.now)
	if e != nil || value.(ConfigurationProtocol).ConfigurationRequestVersion != 1 {
		t.Fatal("v2 use automatically advertised an upgrade", e)
	}
	// A positive declaration remains non-authoritative for another mutation.
	n, c, p = configurationControlFixture(t)
	c.ConfigurationRequestVersion = 2
	original := n.f.v.p
	n.f.v.p.ACR = "0"
	n.f.v.p.Methods = nil
	n.f.v.p.AuthTime = n.f.now.Add(-time.Hour).Unix()
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	read, token, proof = configurationCall(t, n, c, "configuration.protocol.get", identity.Hash([]byte("no-grant-version")), struct{}{})
	if value, e = c.Dispatch(context.Background(), token, proof, read, n.f.now); e != nil || value.(ConfigurationProtocol).ConfigurationRequestVersion != 2 {
		t.Fatal("nonsecret service eligibility denied", e)
	}
	before := operationVersionBusinessCounts(t)
	raw, token, proof = operationOriginal(t, n, c, p, "no-grant-mutation", 2)
	if _, e = c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("declaration promoted MFA", e)
	}
	n.f.v.p = original
	if _, e = c.Dispatch(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("declaration promoted object ACL", e)
	}
	if !reflect.DeepEqual(before, operationVersionBusinessCounts(t)) {
		t.Fatal("eligibility created an effect or ledger fence")
	}
}

func TestSQLOperationVersionMalformedPayloadAndVersionTwoReadCannotCreateBusinessRows(t *testing.T) {
	n, c, _ := configurationControlFixture(t)
	c.ConfigurationRequestVersion = 2
	before := operationVersionBusinessCounts(t)
	for _, payload := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`[]`), json.RawMessage(`{"actor":"foreign"}`), json.RawMessage(`{"configurationRequestVersion":2}`), json.RawMessage(`{"x":1,"x":2}`)} {
		raw, token, proof := configurationCall(t, n, c, "configuration.protocol.get", identity.Hash([]byte("bad-protocol/"+string(payload))), payload)
		if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e == nil {
			t.Fatal("malformed protocol payload admitted")
		}
	}
	raw, token, _ := configurationCall(t, n, c, "configuration.protocol.get", identity.Hash([]byte("v2-read")), struct{}{})
	raw = []byte(strings.Replace(string(raw), `"version":1`, `"version":2`, 1))
	proof := signed(t, n.f.key, c.Origin+"/v1/control/action", token, "", raw, n.f.now)
	if _, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now); e == nil {
		t.Fatal("read action accepted as version-two mutation")
	}
	if !reflect.DeepEqual(before, operationVersionBusinessCounts(t)) {
		t.Fatal("malformed read changed configuration state")
	}
}
