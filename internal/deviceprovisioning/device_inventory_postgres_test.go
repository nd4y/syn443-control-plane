//go:build postgres

package deviceprovisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func listDevices(t *testing.T, n networkFixture, c *ConfigurationControl, after string) (DeviceInventory, error) {
	t.Helper()
	raw, token, proof := configurationCall(t, n, c, "configuration.devices.list", identity.Hash([]byte("device inventory "+after)), map[string]string{"after": after})
	v, e := c.Dispatch(context.Background(), token, proof, raw, n.f.now)
	if e != nil {
		return DeviceInventory{}, e
	}
	return v.(DeviceInventory), nil
}

func TestDeviceInventoryUsesExactCardACLWithoutMFAOrPrivateBodies(t *testing.T) {
	n, c, _ := configurationControlFixture(t)
	seedConfigurationDevice(t, storedLayersFixture{n: n}, "another-device", true)
	seedConfigurationDevice(t, storedLayersFixture{n: n}, "unapproved-device", false)
	if _, e := fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires) VALUES($1,'configuration.drafts.read','device',$2,$3)`, n.actor.ID, n.target.Device, n.f.now.Unix()+300); e != nil {
		t.Fatal(e)
	}
	n.f.v.p.ACR = "0"
	n.f.v.p.Methods = nil
	n.f.v.p.AuthTime = n.f.now.Add(-time.Hour).Unix()
	page, e := listDevices(t, n, c, "")
	if e != nil || len(page.Devices) != 1 || page.Devices[0].Device != n.target.Device || page.Next != "" || page.ObservedAtMs != n.f.now.UnixMilli() {
		t.Fatal("exact device grant discovery", e)
	}
	raw, _ := json.Marshal(page)
	for _, secret := range []string{n.target.Owner, n.target.Thumbprint, "another-device", "unapproved-device", "source-a", "proxy.example.invalid"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("device list exposed unauthorized or configuration data")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v %#v", page, page, page.Devices[0], page.Devices[0]), n.target.Device) {
		t.Fatal("device metadata leaked through diagnostics")
	}
	var audits int
	if e = fixtureOwner.QueryRow(`SELECT count(*) FROM catalog_audit WHERE actor=$1 AND action='configuration.devices.list' AND outcome='read'`, n.actor.ID).Scan(&audits); e != nil || audits != 1 {
		t.Fatal("metadata read was not audited", e)
	}
	if _, e = fixtureOwner.Exec(`DELETE FROM catalog_acl WHERE actor=$1`, n.actor.ID); e != nil {
		t.Fatal(e)
	}
	page, e = listDevices(t, n, c, "")
	if e != nil || page.Devices == nil || len(page.Devices) != 0 {
		t.Fatal("withdrawn grant retained device existence", e)
	}
}

func TestDeviceInventoryPaginatesAuthorizedActiveDevicesWithoutDuplicates(t *testing.T) {
	n, c, _ := configurationControlFixture(t)
	expected := []string{n.target.Device}
	for i := 0; i < 35; i++ {
		id := fmt.Sprintf("device-%02d", i)
		seedConfigurationDevice(t, storedLayersFixture{n: n}, id, true)
		expected = append(expected, id)
	}
	seedConfigurationDevice(t, storedLayersFixture{n: n}, "pending-device", false)
	seedConfigurationDevice(t, storedLayersFixture{n: n}, "revoked-device", true)
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET active=false WHERE id='revoked-device'`); e != nil {
		t.Fatal(e)
	}
	sort.Strings(expected)
	page, e := listDevices(t, n, c, "")
	if e != nil || len(page.Devices) != 32 || page.Next != page.Devices[31].Device {
		t.Fatal("bounded first device page", e)
	}
	var actual []string
	for _, row := range page.Devices {
		actual = append(actual, row.Device)
	}
	page, e = listDevices(t, n, c, page.Next)
	if e != nil || len(page.Devices) != 4 || page.Next != "" {
		t.Fatal("bounded final device page", e)
	}
	for _, row := range page.Devices {
		actual = append(actual, row.Device)
	}
	if fmt.Sprint(actual) != fmt.Sprint(expected) {
		t.Fatal("device ordering, duplicate or omission")
	}
	if page, e = listDevices(t, n, c, "zzzzzz"); e != nil || len(page.Devices) != 0 || page.Next != "" {
		t.Fatal("empty page", e)
	}
	if _, e = listDevices(t, n, c, "invalid/cursor"); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("invalid device cursor accepted", e)
	}
}

func TestDeviceInventorySeparatesReportedHistoricalAndUnissuedPolicies(t *testing.T) {
	n, c, _ := configurationControlFixture(t)
	if e := n.publisher.RunOnce(context.Background(), n.f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET offline_until=$2,publication_grant_hash=$3 WHERE id=$1`, n.target.Device, n.f.now.Add(time.Hour).Unix(), n.target.GrantHash); e != nil {
		t.Fatal(e)
	}
	if _, e := fixtureOwner.Exec(`INSERT INTO identity_policy_activation VALUES($1,1,$2,1,'committed',1,$3)`, n.target.Device, identity.Hash([]byte("device-list-fixture")), n.f.now.UnixMilli()); e != nil {
		t.Fatal(e)
	}
	page, e := listDevices(t, n, c, "")
	if e != nil || len(page.Devices) != 1 || page.Devices[0].Report.State != "reported" || page.Devices[0].Report.Outcome != "committed" || page.Devices[0].DesiredRevision != 0 {
		t.Fatal("report metadata confused desired configuration or connectivity", e)
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_devices SET offline_until=$2 WHERE id=$1`, n.target.Device, n.f.now.Unix()); e != nil {
		t.Fatal(e)
	}
	page, e = listDevices(t, n, c, "")
	if e != nil || page.Devices[0].Report.State != "historical" {
		t.Fatal("expired publication presented as a current report", e)
	}
	seedConfigurationDevice(t, storedLayersFixture{n: n}, "unissued-device", true)
	page, e = listDevices(t, n, c, "")
	if e != nil || len(page.Devices) != 2 {
		t.Fatal(e)
	}
	for _, row := range page.Devices {
		if row.Device == "unissued-device" && row.Report.State != "not_issued" {
			t.Fatal("unissued device invented an activation")
		}
	}
	if _, e = fixtureOwner.Exec(`UPDATE identity_accounts SET enabled=false`); e != nil {
		t.Fatal(e)
	}
	page, e = listDevices(t, n, c, "")
	if e != nil || len(page.Devices) != 0 {
		t.Fatal("disabled account remained discoverable", e)
	}
}

func TestDeviceInventoryRefusesExpiredAuthorityCancellationAndUnauditedReads(t *testing.T) {
	n, c, _ := configurationControlFixture(t)
	request := identity.Hash([]byte("device-list-boundary"))
	if _, e := c.deviceInventory(context.Background(), n.actor.ID, "", request, n.f.now.Unix(), n.f.now); !errors.Is(e, enrollment.ErrDenied) {
		t.Fatal("expired authority", e)
	}
	if _, e := c.deviceInventory(nil, n.actor.ID, "", request, n.f.now.Unix()+300, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal("missing context", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.deviceInventory(ctx, n.actor.ID, "", request, n.f.now.Unix()+300, n.f.now); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal("cancelled discovery", e)
	}
	if _, e := fixtureOwner.Exec(`REVOKE INSERT ON catalog_audit FROM syn443_control_api`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { fixtureOwner.Exec(`GRANT INSERT ON catalog_audit TO syn443_control_api`) })
	if _, e := listDevices(t, n, c, ""); !errors.Is(e, enrollment.ErrUnavailable) {
		t.Fatal("unaudited metadata escaped", e)
	}
}

func TestDeviceInventoryRechecksAuthorityAfterWaitingForDeviceLock(t *testing.T) {
	n, c, _ := configurationControlFixture(t)
	lock, e := fixtureOwner.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback()
	if _, e = lock.Exec(`SELECT id FROM identity_devices WHERE id=$1 FOR UPDATE`, n.target.Device); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := c.deviceInventory(context.Background(), n.actor.ID, "", identity.Hash([]byte("delayed device list")), n.f.now.Unix()+1, n.f.now)
		done <- e
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var waiting int
		if e = fixtureOwner.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT d.id,d.revision,COALESCE%'`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("device discovery did not reach its owned lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(1100 * time.Millisecond)
	lock.Rollback()
	select {
	case e = <-done:
		if !errors.Is(e, enrollment.ErrDenied) {
			t.Fatal("expired discovery authority returned rows", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("device discovery exceeded its deadline")
	}
}
