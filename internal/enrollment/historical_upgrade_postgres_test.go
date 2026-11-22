//go:build postgres

package enrollment

import (
	"database/sql"
	"os"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/telemetry"
)

// Restore the same historical custom-format dump into an upgrade database and
// an independent rollback database. All rows and roles belong to this fixture.
func TestHistoricalSQLUpgradePreservesDeviceConversationAndRollback(t *testing.T) {
	const source = "syn443_ci_upgrade_source"
	if _, err := fixtureOwner.Exec(`CREATE DATABASE syn443_ci_upgrade_source TEMPLATE template0`); err != nil {
		t.Fatal("create historical database", err)
	}
	t.Cleanup(func() {
		if _, err := fixtureOwner.Exec(`DROP DATABASE syn443_ci_upgrade_source WITH (FORCE)`); err != nil {
			t.Error("clean up historical database", err)
		}
	})
	ownerDSN := os.Getenv("SYN443_TEST_DATABASE")
	legacy := openRestoreDatabase(t, ownerDSN, source)
	raw, err := os.ReadFile(os.Getenv("SYN443_TEST_PREVIOUS_SCHEMA"))
	if err != nil || len(raw) == 0 || len(raw) > 256*1024 {
		t.Fatal("read previous public identity and chat schema", err)
	}
	if _, err := legacy.Exec(string(raw)); err != nil {
		t.Fatal("install previous schema", err)
	}
	const seed = `
INSERT INTO identity_accounts(owner,issuer,subject,enabled,device_limit,valid_until,grant_hash)
 VALUES ('fixture-owner','https://id.example.invalid','fixture-subject',true,1,1800000000,'fixture-grant');
INSERT INTO identity_devices(id,owner,jkt,active,approved,request_body,receipt,publication,revision)
 VALUES ('fixture-device','fixture-owner','fixture-thumbprint',true,true,'request','receipt','published-policy',17);
INSERT INTO chat_conversations(id,owner,next_seq,updated_at) VALUES (repeat('a',32),'fixture-owner',2,1);
INSERT INTO chat_messages(id,conversation,sender,sender_role,client_id,body_hash,sequence,text,created_at)
 VALUES (repeat('b',32),repeat('a',32),'fixture-owner','user',repeat('c',32),repeat('e',64),1,'fixture message',1);
INSERT INTO chat_uploads(id,conversation,sender,client_id,name,mime,kind,size,sha256,created_at,expires_at,complete,message_id)
 VALUES (repeat('d',32),repeat('a',32),'fixture-owner',repeat('e',32),'fixture.bin','application/octet-stream','file',3,
         encode(sha256(decode('010203','hex')),'hex'),1,100,true,repeat('b',32));
INSERT INTO chat_chunks(upload,part,data,sha256) SELECT id,0,decode('010203','hex'),sha256 FROM chat_uploads;
INSERT INTO identity_telemetry_hourly(hour_start_ms,kind,code,mode,events,timed,duration_total_ms,baseline_reselections,conservative_reselections)
 VALUES (3600000,'route','reselected','wifi',3,0,0,1,1);`
	if _, err := legacy.Exec(seed); err != nil {
		t.Fatal("seed historical records", err)
	}

	verifyData := func(db *sql.DB) {
		t.Helper()
		var valid bool
		err := db.QueryRow(`SELECT a.enabled AND a.device_limit=1 AND a.grant_hash='fixture-grant'
 AND d.active AND d.approved AND d.jkt='fixture-thumbprint' AND d.revision=17 AND d.publication='published-policy'::bytea
 AND d.request_body='request'::bytea AND d.receipt='receipt'::bytea
 AND m.text='fixture message' AND m.sequence=1 AND u.complete AND u.size=3 AND chunk.data=decode('010203','hex')
 AND encode(sha256(chunk.data),'hex')=u.sha256 AND u.sha256=chunk.sha256
 AND h.events=3 AND h.baseline_reselections=1 AND h.conservative_reselections=1
 FROM identity_devices d JOIN identity_accounts a ON a.owner=d.owner
 JOIN chat_conversations c ON c.owner=a.owner JOIN chat_messages m ON m.conversation=c.id
 JOIN chat_uploads u ON u.message_id=m.id JOIN chat_chunks chunk ON chunk.upload=u.id
 CROSS JOIN identity_telemetry_hourly h
 WHERE d.id='fixture-device' AND m.id=repeat('b',32) AND u.id=repeat('d',32) AND chunk.part=0
 AND h.hour_start_ms=3600000 AND h.kind='route' AND h.code='reselected' AND h.mode='wifi'`).Scan(&valid)
		if err != nil || !valid {
			t.Fatal("stored binding, policy, conversation, chunk or aggregate changed", err)
		}
	}
	isHistorical := func(db *sql.DB) bool {
		t.Helper()
		var previous bool
		err := db.QueryRow(`SELECT to_regclass('public.chat_incident_reference') IS NULL
 AND NOT EXISTS (SELECT FROM information_schema.columns WHERE table_schema='public' AND
   (table_name='identity_telemetry_hourly' AND column_name='adaptive_reselections'
    OR table_name='identity_devices' AND column_name='ingest_lock_guard'))`).Scan(&previous)
		if err != nil {
			t.Fatal("inspect historical schema", err)
		}
		return previous
	}
	verifyData(legacy)
	if !isHistorical(legacy) {
		t.Fatal("fixture already has the current schema")
	}
	restoreFixtureFrom(t, source)
	upgraded := openRestoreDatabase(t, ownerDSN, restoreDatabase)
	rollback := openRestoreDatabase(t, ownerDSN, "syn443_ci_upgrade_rollback")
	if !isHistorical(upgraded) || !isHistorical(rollback) {
		t.Fatal("restores do not start with the historical schema")
	}
	for range 2 {
		for _, migration := range []string{Schema, Roles, telemetry.ReportRoles} {
			if _, err := upgraded.Exec(migration); err != nil {
				t.Fatal("apply current owner migration", err)
			}
		}
		verifyData(upgraded)
		var applied bool
		err := upgraded.QueryRow(`SELECT to_regclass('public.chat_incident_reference') IS NOT NULL
 AND ingest_lock_guard=0 FROM identity_devices WHERE id='fixture-device'`).Scan(&applied)
		if err != nil || !applied {
			t.Fatal("current device guard or incident index missing", err)
		}
	}
	reader := openRestoreDatabase(t, fixtureTelemetryReaderDSN, restoreDatabase)
	var adaptive int
	if err := reader.QueryRow(`SELECT adaptive_reselections FROM identity_telemetry_hourly WHERE hour_start_ms=3600000`).Scan(&adaptive); err != nil || adaptive != 0 {
		t.Fatal("historical aggregate gained attribution", err)
	}
	if _, err := reader.Exec(`SELECT jkt FROM identity_devices`); err == nil {
		t.Fatal("aggregate reader gained device-key access")
	}
	verifyData(rollback)
	if !isHistorical(rollback) {
		t.Fatal("rollback restore changed with upgraded schema")
	}
}
