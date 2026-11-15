//go:build postgres

package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
)

func TestDeviceControlPanelHintRequiresLiveScopedGrantAndBoundProof(t *testing.T) {
	f := newFixture(t, 1)
	if _, err := fixtureOwner.Exec(catalog.Schema + `GRANT EXECUTE ON FUNCTION catalog_control_panel_expiry(text,bigint) TO syn443_identity_api;`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureAPI.Exec(`SELECT actor FROM catalog_acl`); err == nil {
		t.Fatal("device API acquired catalog ACL inventory")
	}
	if err := f.store.ControlPanelRole(context.Background()); err != nil {
		t.Fatal("navigation role scope", err)
	}
	k := key(t)
	session, _, _ := f.register(t, k)
	expect(t, f.call(t, k, "GET", controlPanelPath, session.AccessToken, session.Nonce, nil), http.StatusNotFound)
	f.api.ControlPanelDiscovery = true
	read := func(want int64) {
		t.Helper()
		r := f.call(t, k, "GET", controlPanelPath, session.AccessToken, session.Nonce, nil)
		expect(t, r, http.StatusOK)
		var reply ControlPanelHint
		if err := json.Unmarshal(r.Body.Bytes(), &reply); err != nil || reply.SchemaVersion != 1 || reply.UntilMs != want {
			t.Fatal("unexpected device panel hint", err)
		}
	}
	read(0)
	owner := Owner(f.grant.Issuer, f.grant.Subject)
	if _, err := fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'sources.read','user',$1,$2),('foreign','control.open','control','panel',$2)`, owner, f.now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	read(0)
	deadline := f.now.Add(time.Minute)
	if _, err := fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'control.open','control','panel',$2)`, owner, deadline.Unix()); err != nil {
		t.Fatal(err)
	}
	read(deadline.UnixMilli())
	expect(t, f.call(t, key(t), "GET", controlPanelPath, session.AccessToken, session.Nonce, nil), http.StatusForbidden)
	proof := signed(t, k, "GET", f.origin+controlPanelPath, session.AccessToken, session.Nonce, nil, f.now)
	expect(t, f.rawCall("GET", controlPanelPath, session.AccessToken, proof, nil), http.StatusOK)
	expect(t, f.rawCall("GET", controlPanelPath, session.AccessToken, proof, nil), http.StatusUnauthorized)
	if _, err := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1 AND action='control.open'`, owner); err != nil {
		t.Fatal(err)
	}
	read(0)
}
