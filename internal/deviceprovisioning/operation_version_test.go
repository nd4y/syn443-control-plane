package deviceprovisioning

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

type operationVersionPrincipal struct{ value identity.Principal }

func (v *operationVersionPrincipal) Verify(context.Context, string, time.Time) (identity.Principal, error) {
	return v.value, nil
}

func operationVersionReceipt(t *testing.T, action string, version int, payload json.RawMessage) (invitation.Receipt, *operationVersionPrincipal, time.Time) {
	t.Helper()
	now := time.Unix(1800000000, 0)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	jwk := identity.PublicJWK(&key.PublicKey)
	thumb, e := jwk.Thumbprint()
	if e != nil {
		t.Fatal(e)
	}
	p := &operationVersionPrincipal{identity.Principal{Issuer: "https://identity.example.invalid/realms/admin", Subject: "synthetic-admin", Thumbprint: thumb, Expires: now.Add(5 * time.Minute).Unix(), Scope: "openid syn443.control", ACR: "0", AuthTime: now.Add(-time.Hour).Unix()}}
	body, e := json.Marshal(invitation.Envelope{Version: version, Action: action, RequestID: identity.Hash([]byte("synthetic-protocol/" + action)), Payload: payload})
	if e != nil {
		t.Fatal(e)
	}
	r := invitation.Receipt{Token: "synthetic-control-access-token", URI: "https://control.example.invalid/v1/control/action", Body: body, AcceptedAt: now.Unix()}
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk})
	claims, _ := json.Marshal(identity.ProofClaims{Jti: identity.Hash([]byte("synthetic-proof/" + action)), Htm: "POST", Htu: r.URI, Iat: now.Unix(), Ath: identity.Hash([]byte(r.Token)), RequestHash: identity.Hash(body)})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	a, b, e := ecdsa.Sign(rand.Reader, key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	r.Proof = input + "." + base64.RawURLEncoding.EncodeToString(append(a.FillBytes(make([]byte, 32)), b.FillBytes(make([]byte, 32))...))
	return r, p, now
}

func TestOperationVersionOwnerDefaultsStayOneAndTwoRequiresExplicitDeclaration(t *testing.T) {
	c := runtimeConfiguration(t)
	before, e := json.Marshal(c)
	if e != nil || bytes.Contains(before, []byte("configurationRequestVersion")) {
		t.Fatal("default owner wire changed")
	}
	for _, version := range []int{0, 1, 2} {
		var fields map[string]json.RawMessage
		if json.Unmarshal(before, &fields) != nil {
			t.Fatal("invalid source fixture")
		}
		fields["configurationRequestVersion"] = json.RawMessage(fmt.Sprint(version))
		raw, _ := json.Marshal(fields)
		got, e := ParseConfigurationRuntime(raw)
		if e != nil || got.ConfigurationRequestVersion != version {
			t.Fatal("explicit declaration rejected", e)
		}
		declared, e := declaredConfigurationRequestVersion(got.ConfigurationRequestVersion)
		want := 1
		if version == 2 {
			want = 2
		}
		if e != nil || declared != want {
			t.Fatal("owner default automatically enabled new mutations")
		}
	}
	got, e := ParseConfigurationRuntime(before)
	if e != nil || got.ConfigurationRequestVersion != 0 {
		t.Fatal("old owner file no longer compatible", e)
	}
}

func TestOperationVersionOwnerDeclarationRejectsNullCoercionCaseDuplicatesAndOutOfRangeIntegers(t *testing.T) {
	raw, _ := json.Marshal(runtimeConfiguration(t))
	for _, value := range []string{"null", "-1", "3", "2.0", "2e0", "true", "\"2\"", "9007199254740992", "-0"} {
		body := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"configurationRequestVersion":`+value+`}`)...)
		if _, e := ParseConfigurationRuntime(body); e == nil {
			t.Fatal("invalid owner protocol declaration", value)
		}
	}
	for _, fields := range []string{`,"ConfigurationRequestVersion":2}`, `,"configurationRequestVersion":1,"configurationRequestVersion":2}`, `,"configurationRequestVersions":2}`} {
		if _, e := ParseConfigurationRuntime(append(append([]byte(nil), raw[:len(raw)-1]...), []byte(fields)...)); e == nil {
			t.Fatal("non-closed owner declaration")
		}
	}
	for _, version := range []int{-1, 3} {
		if _, e := declaredConfigurationRequestVersion(version); e == nil {
			t.Fatal("unsafe in-memory declaration")
		}
	}
}

func TestOperationVersionReplyIsClosedNonsecretRedactedEligibilityWithoutGrantFields(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, version := range []int{0, 1, 2} {
		c := &ConfigurationControl{ConfigurationRequestVersion: version}
		got, e := c.protocolInformation(context.Background(), json.RawMessage(`{}`), now.Unix()+60, func() time.Time { return now })
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(got)
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || string(fields["version"]) != "1" {
			t.Fatal("reply widened")
		}
		want := 1
		if version == 2 {
			want = 2
		}
		if string(fields["configurationRequestVersion"]) != fmt.Sprint(want) {
			t.Fatal("wrong service eligibility")
		}
		if fmt.Sprintf("%v %#v", got, got) != "ConfigurationProtocol([redacted]) ConfigurationProtocol([redacted])" {
			t.Fatal("unredacted protocol diagnostics")
		}
	}
}

func TestOperationVersionReadPayloadRemainsEmptyClosedAndVersionOneOnly(t *testing.T) {
	now := time.Unix(1800000000, 0)
	c := &ConfigurationControl{ConfigurationRequestVersion: 2}
	for _, payload := range []string{"null", "[]", "\"{}\"", `{"configurationRequestVersion":2}`, `{"actor":"foreign"}`, `{"x":1,"x":2}`, `{} {}`} {
		if _, e := c.protocolInformation(context.Background(), json.RawMessage(payload), now.Unix()+60, func() time.Time { return now }); e == nil {
			t.Fatal("nonempty or malformed payload accepted")
		}
	}
	if configurationVersion(2, "configuration.protocol.get") || configurationVersion(3, "configuration.protocol.get") {
		t.Fatal("v2 read envelope enabled")
	}
	for _, action := range []string{"configuration.layers.draft.put", "configuration.layers.draft.discard", "configuration.preview.request", "configuration.publish"} {
		if !configurationVersion(2, action) {
			t.Fatal("existing CP58 mutation support changed")
		}
	}
}

func TestOperationVersionReadRechecksOriginalDeadlineAndCancellationBeforeReturning(t *testing.T) {
	now := time.Unix(1800000000, 0)
	c := &ConfigurationControl{ConfigurationRequestVersion: 2}
	clock := func() time.Time { return now }
	if _, e := c.protocolInformation(nil, json.RawMessage(`{}`), now.Unix()+1, clock); e == nil {
		t.Fatal("nil context")
	}
	if _, e := c.protocolInformation(context.Background(), json.RawMessage(`{}`), now.Unix(), clock); e == nil {
		t.Fatal("expired read")
	}
	if _, e := c.protocolInformation(context.Background(), json.RawMessage(`{}`), now.Unix()+1, nil); e == nil {
		t.Fatal("missing clock")
	}
	var missing *ConfigurationControl
	if _, e := missing.protocolInformation(context.Background(), json.RawMessage(`{}`), now.Unix()+1, clock); e == nil {
		t.Fatal("missing control")
	}
	count := 0
	if _, e := c.protocolInformation(context.Background(), json.RawMessage(`{}`), now.Unix()+1, func() time.Time {
		count++
		if count > 1 {
			return now.Add(time.Second)
		}
		return now
	}); e == nil || count != 2 {
		t.Fatal("late read returned stale eligibility")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, e := c.protocolInformation(ctx, json.RawMessage(`{}`), now.Unix()+60, func() time.Time { cancel(); return now }); e == nil {
		t.Fatal("cancelled read returned data")
	}
	c.ConfigurationRequestVersion = 3
	if _, e := c.protocolInformation(context.Background(), json.RawMessage(`{}`), now.Unix()+60, clock); e == nil {
		t.Fatal("invalid process declaration fell back")
	}
}

func TestOperationVersionBoundProofAndCurrentControlScopeRemainRequiredWithoutFreshMfaPromotion(t *testing.T) {
	r, p, now := operationVersionReceipt(t, "configuration.protocol.get", 1, json.RawMessage(`{}`))
	actor, body, until, e := verifyConfigurationReceipt(context.Background(), p, r, "https://control.example.invalid", "urn:syn443:loa:2", now)
	if e != nil || actor != identity.Hash([]byte(p.value.Issuer+"\x00"+p.value.Subject)) || body.Action != "configuration.protocol.get" || until <= now.Unix() {
		t.Fatal("nonsecret proof-bound read denied", e)
	}
	for _, changed := range []invitation.Receipt{func() invitation.Receipt { x := r; x.Proof = "invalid-proof"; return x }(), func() invitation.Receipt { x := r; x.Body = append(append([]byte(nil), r.Body...), ' '); return x }()} {
		if _, _, _, e := verifyConfigurationReceipt(context.Background(), p, changed, "https://control.example.invalid", "urn:syn443:loa:2", now); e == nil {
			t.Fatal("proof/body substitution admitted")
		}
	}
	p.value.Scope = "openid"
	if _, _, _, e := verifyConfigurationReceipt(context.Background(), p, r, "https://control.example.invalid", "urn:syn443:loa:2", now); e == nil {
		t.Fatal("missing control scope")
	}
	p.value.Scope = "syn443.control"
	p.value.Expires = now.Unix()
	if _, _, _, e := verifyConfigurationReceipt(context.Background(), p, r, "https://control.example.invalid", "urn:syn443:loa:2", now); e == nil {
		t.Fatal("expired token")
	}
	r, p, now = operationVersionReceipt(t, "configuration.layers.draft.put", 2, json.RawMessage(`{}`))
	if _, _, _, e := verifyConfigurationReceipt(context.Background(), p, r, "https://control.example.invalid", "urn:syn443:loa:2", now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("protocol read promoted fresh MFA", e)
	}
}

func TestOperationVersionOwnerFileAndActualApiWiringCannotInferOrOverrideEligibility(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX owner file evidence is required in Actions")
	}
	c := runtimeConfiguration(t)
	c.ConfigurationRequestVersion = 2
	raw, _ := json.Marshal(c)
	p := filepath.Join(t.TempDir(), "owner.json")
	if e := os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := ReadConfigurationRuntime(p); e != nil || got.ConfigurationRequestVersion != 2 {
		t.Fatal("owner declaration unreadable", e)
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadConfigurationRuntime(p); e == nil {
		t.Fatal("world-readable owner declaration")
	}
	_, here, _, _ := runtime.Caller(0)
	set := gotoken.NewFileSet()
	source, e := parser.ParseFile(set, filepath.Join(filepath.Dir(here), "../../cmd/control-api/main.go"), nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	bound := 0
	ast.Inspect(source, func(node ast.Node) bool {
		lit, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typ, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || typ.Sel.Name != "ConfigurationControl" {
			return true
		}
		for _, entry := range lit.Elts {
			kv, ok := entry.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			name, ok := kv.Key.(*ast.Ident)
			if !ok || name.Name != "ConfigurationRequestVersion" {
				continue
			}
			value, ok := kv.Value.(*ast.SelectorExpr)
			if ok && value.Sel.Name == "ConfigurationRequestVersion" {
				if owner, ok := value.X.(*ast.Ident); ok && owner.Name == "cc" {
					bound++
				}
			}
		}
		return true
	})
	if bound != 1 {
		t.Fatal("API eligibility is not pinned to the explicit owner configuration")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c, c), c.LayerEncryptionKey) {
		t.Fatal("owner key exposed")
	}
}
