//go:build postgres

package catalog

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestSQLConfigurationProtocolHttpUsesExistingBoundProofRouteWithoutObjectAclOrFreshMfa(t *testing.T) {
	f := adminHTTPFixture(t)
	f.Verifier.Principal.ACR = "0"
	f.Verifier.Principal.Methods = nil
	f.Verifier.Principal.AuthTime = f.Now.Add(-time.Hour).Unix()
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, f.Actor.ID); e != nil {
		t.Fatal(e)
	}
	const businessQuery = `SELECT (SELECT count(*) FROM catalog_jobs)+(SELECT count(*) FROM catalog_operations)+(SELECT count(*) FROM catalog_audit)`
	var beforeBusiness int
	if e := fixtureOwner.QueryRow(businessQuery).Scan(&beforeBusiness); e != nil {
		t.Fatal(e)
	}
	calls := 0
	f.API.Configurations = func(ctx context.Context, token, proof string, raw []byte, now time.Time) (any, error) {
		calls++
		var value Action
		if identity.DecodeConfiguration(raw, &value) != nil || value.Version != 1 || value.Action != "configuration.protocol.get" || string(value.Payload) != "{}" || token != adminToken || proof == "" || now != f.Now || ctx.Err() != nil {
			t.Fatal("protocol read lost exact control route admission")
		}
		return struct {
			Version                     int `json:"version"`
			ConfigurationRequestVersion int `json:"configurationRequestVersion"`
		}{1, 2}, nil
	}
	raw := []byte(`{"version":1,"action":"configuration.protocol.get","requestId":"synthetic-protocol-http-request","payload":{}}`)
	proof := f.proof(t, raw)
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, f.request(raw, proof))
	if w.Code != 200 || calls != 1 {
		t.Fatal("protocol action did not reach the existing configuration callback", w.Code)
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result) != 2 || string(result["version"]) != "1" || string(result["configurationRequestVersion"]) != "2" {
		t.Fatal("reply has grant or target fields")
	}
	w = httptest.NewRecorder()
	f.API.ServeHTTP(w, f.request(raw, proof))
	if w.Code != 403 || calls != 1 {
		t.Fatal("reused DPoP admitted")
	}
	var business int
	if e := fixtureOwner.QueryRow(businessQuery).Scan(&business); e != nil || business != beforeBusiness {
		t.Fatal("protocol callback created catalog work", e)
	}
}

func TestSQLConfigurationProtocolHttpMalformedOrForeignRequestsNeverInvokeTheService(t *testing.T) {
	f := adminHTTPFixture(t)
	calls := 0
	f.API.Configurations = func(context.Context, string, string, []byte, time.Time) (any, error) { calls++; return nil, nil }
	base := []byte(`{"version":1,"action":"configuration.protocol.get","requestId":"synthetic-protocol-http-denied","payload":{}}`)
	for _, raw := range [][]byte{[]byte(`{"version":1,"action":"configuration.protocol.get","requestId":"synthetic-protocol-http-denied","payload":null}`), []byte(`{"version":1,"action":"configuration.protocol.get","requestId":"synthetic-protocol-http-denied","payload":{"actor":"foreign"}}`), []byte(`{"version":1,"action":"configuration.protocol.get","requestId":"synthetic-protocol-http-denied","payload":{"configurationRequestVersion":2}}`)} {
		w := httptest.NewRecorder()
		f.API.ServeHTTP(w, f.request(raw, f.proof(t, raw)))
		if w.Code != 400 || calls != 0 {
			t.Fatal("nonempty payload escaped the closed protocol schema", w.Code)
		}
	}
	for _, mode := range []string{"proof", "body", "scope", "expired"} {
		original := f.Verifier.Principal
		proof := f.proof(t, base)
		raw := append([]byte(nil), base...)
		switch mode {
		case "proof":
			proof = "invalid-proof"
		case "body":
			raw = append(raw, ' ')
		case "scope":
			f.Verifier.Principal.Scope = "openid"
		case "expired":
			f.Verifier.Principal.Expires = f.Now.Unix()
		}
		w := httptest.NewRecorder()
		f.API.ServeHTTP(w, f.request(raw, proof))
		f.Verifier.Principal = original
		if w.Code != 403 || calls != 0 {
			t.Fatal("unbound current control request admitted", mode, w.Code)
		}
	}
}

func TestSQLConfigurationProtocolHttpDoesNotBroadenV2ActionsOrTreatFeatureDenialAsUnsupported(t *testing.T) {
	f := adminHTTPFixture(t)
	calls := 0
	raw := []byte(`{"version":1,"action":"configuration.protocol.get","requestId":"synthetic-protocol-disabled-read","payload":{}}`)
	w := httptest.NewRecorder()
	f.API.ServeHTTP(w, f.request(raw, f.proof(t, raw)))
	if w.Code != 403 {
		t.Fatal("disabled feature was described as unsupported", w.Code)
	}
	f.API.Configurations = func(context.Context, string, string, []byte, time.Time) (any, error) { calls++; return nil, nil }
	raw = []byte(`{"version":2,"action":"configuration.protocol.get","requestId":"synthetic-protocol-version-read","payload":{}}`)
	w = httptest.NewRecorder()
	f.API.ServeHTTP(w, f.request(raw, f.proof(t, raw)))
	if w.Code != 400 || calls != 0 || controlActionVersion(2, "configuration.protocol.get") {
		t.Fatal("version-two read escaped the mutation-only fence", w.Code)
	}
	for _, action := range []string{"source.upload", "invite.create", "configuration.inventory.get", "configuration.request.get"} {
		if controlActionVersion(2, action) {
			t.Fatal("protocol advertisement broadened unrelated version-two actions")
		}
	}
}
