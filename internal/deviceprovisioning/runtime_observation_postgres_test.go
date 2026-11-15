//go:build postgres

package deviceprovisioning

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func runtimeViewFixture(t *testing.T) (networkFixture, *ConfigurationControl) {
	t.Helper()
	n, c, _ := configurationControlFixture(t)
	if e := n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	n.f.v.p.ACR = "0"
	n.f.v.p.Methods = nil
	return n, c
}
func runtimeSeed(t *testing.T, n networkFixture, key string, received int64) {
	t.Helper()
	_, e := fixtureOwner.Exec(`INSERT INTO identity_runtime_observations(device,key_thumbprint,sequence,report_hash,build,phase,policy_revision,engine_known,engine_active,network,sampled_at_ms,received_at_ms) VALUES($1,$2,1,$3,74,'online',1,true,true,'wifi',$4,$4)`, n.target.Device, key, identity.Hash([]byte("synthetic-runtime-observation")), received)
	if e != nil {
		t.Fatal(e)
	}
}
func TestRuntimeViewSeparatesUnknownRecentStaleAndPreviousKeysWithoutNewMFA(t *testing.T) {
	n, c := runtimeViewFixture(t)
	view, e := c.runtimeObservation(context.Background(), n.actor.ID, n.target.Device, "runtime-empty", n.f.now.Unix()+600, n.f.now)
	if e != nil || view.State != "none" || view.Report != nil {
		t.Fatal("empty observation invented online state", e)
	}
	runtimeSeed(t, n, n.target.Thumbprint, n.f.now.UnixMilli())
	view, e = c.runtimeObservation(context.Background(), n.actor.ID, n.target.Device, "runtime-recent", n.f.now.Unix()+600, n.f.now)
	if e != nil || view.State != "recent" || view.Report == nil || view.Report.Phase != "online" {
		t.Fatal("scoped current-key view", e)
	}
	raw, token, proof := configurationCall(t, n, c, "configuration.runtime.get", identity.Hash([]byte("runtime-no-mfa")), map[string]string{"id": n.target.Device})
	value, e := c.ControlAction(context.Background(), token, proof, raw, n.f.now)
	if e != nil || value.(ConfigurationRuntimeObservation).State != "recent" {
		t.Fatal("metadata incorrectly requested fresh MFA", e)
	}
	later := n.f.now.Add(181 * time.Second)
	view, e = c.runtimeObservation(context.Background(), n.actor.ID, n.target.Device, "runtime-stale", later.Unix()+60, later)
	if e != nil || view.State != "stale" || view.Report == nil || view.Report.ReceivedAtMs != n.f.now.UnixMilli() {
		t.Fatal("old report remained current", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_runtime_observations SET key_thumbprint=$1,sequence=2,sampled_at_ms=sampled_at_ms+30000,received_at_ms=received_at_ms+30000 WHERE device=$2`, identity.Hash([]byte("previous-public-key")), n.target.Device); e != nil {
		t.Fatal(e)
	}
	view, e = c.runtimeObservation(context.Background(), n.actor.ID, n.target.Device, "runtime-previous-key", later.Unix()+60, later)
	if e != nil || view.State != "none" || view.Report != nil {
		t.Fatal("previous-key observation leaked into current binding", e)
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_audit WHERE action='configuration.runtime.get'`).Scan(&count); e != nil || count != 5 {
		t.Fatal("runtime read missing audit", e)
	}
}
func TestRuntimeViewRequiresItsLiveDeviceGrantAndCannotWriteObservations(t *testing.T) {
	n, c := runtimeViewFixture(t)
	runtimeSeed(t, n, n.target.Thumbprint, n.f.now.UnixMilli())
	for _, target := range []string{n.target.Device, "foreign-device"} {
		actor := n.actor.ID
		if target == n.target.Device {
			actor = identity.Hash([]byte("foreign-actor"))
		}
		if _, e := c.runtimeObservation(context.Background(), actor, target, "runtime-denied", n.f.now.Unix()+60, n.f.now); !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("foreign runtime disclosed", e)
		}
	}
	if _, e := fixtureControl.Exec(`UPDATE identity_runtime_observations SET phase='unknown'`); e == nil {
		t.Fatal("control role acquired device observation write")
	}
	if _, e := fixtureSigner.Exec(`SELECT * FROM identity_runtime_observations`); e == nil {
		t.Fatal("publisher acquired observation read")
	}
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	raw, token, proof := configurationCall(t, n, c, "configuration.runtime.get", identity.Hash([]byte("withdrawn-runtime")), map[string]string{"id": n.target.Device})
	if _, e := c.ControlAction(context.Background(), token, proof, raw, n.f.now); !errors.Is(e, catalog.ErrDenied) {
		t.Fatal("withdrawn runtime scope", e)
	}
}
func TestRuntimeViewRejectsInactiveUnapprovedDisabledExpiredAndCorruptedRows(t *testing.T) {
	for _, kind := range []string{"inactive", "unapproved", "disabled", "expired", "future", "future-policy", "audit", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			n, c := runtimeViewFixture(t)
			received := n.f.now.UnixMilli()
			if kind == "future" {
				received += 10000
			}
			runtimeSeed(t, n, n.target.Thumbprint, received)
			query := ""
			switch kind {
			case "inactive":
				query = `UPDATE identity_devices SET active=false`
			case "unapproved":
				query = `UPDATE identity_devices SET approved=false`
			case "disabled":
				query = `UPDATE identity_accounts SET enabled=false`
			case "expired":
				query = `UPDATE identity_accounts SET valid_until=1`
			case "future-policy":
				query = `UPDATE identity_runtime_observations SET policy_revision=9007199254740991,sequence=2,sampled_at_ms=sampled_at_ms+30000,received_at_ms=received_at_ms+30000`
			case "audit":
				query = `REVOKE INSERT ON catalog_audit FROM syn443_control_api`
				t.Cleanup(func() { fixtureOwner.Exec(`GRANT INSERT ON catalog_audit TO syn443_control_api`) })
			}
			if query != "" {
				if _, e := fixtureOwner.Exec(query); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "future-policy" {
				n.f.now = n.f.now.Add(31 * time.Second)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			if _, e := c.runtimeObservation(ctx, n.actor.ID, n.target.Device, "runtime-boundary", n.f.now.Unix()+60, n.f.now); e == nil {
				t.Fatal("invalid runtime view succeeded")
			}
		})
	}
}
func TestRuntimeViewGrantExpiryWhileAuditIsLockedCannotEscape(t *testing.T) {
	n, c := runtimeViewFixture(t)
	if _, e := fixtureOwner.Exec(`UPDATE catalog_acl SET expires=$1 WHERE actor=$2`, n.f.now.Unix()+1, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	tx, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`LOCK TABLE catalog_audit IN ACCESS EXCLUSIVE MODE`); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := c.runtimeObservation(context.Background(), n.actor.ID, n.target.Device, "runtime-lock-expiry", n.f.now.Unix()+60, n.f.now)
		done <- e
	}()
	time.Sleep(1200 * time.Millisecond)
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("expired grant escaped a late audit wait", e)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("runtime read exceeded bounded deadline")
	}
	var count int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_audit WHERE request_id='runtime-lock-expiry'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("expired read committed audit/result", e)
	}
}
