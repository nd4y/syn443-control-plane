//go:build postgres

package deviceprovisioning

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestHistoricalConfigurationRestorePreservesDraftReplayAndFencesOldWriter(t *testing.T) {
	container := os.Getenv("SYN443_RESTORE_FIXTURE_CONTAINER")
	if container == "" && os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("requires the disposable PostgreSQL restore fixture")
	}
	if _, err := hex.DecodeString(container); err != nil || len(container) != 64 {
		t.Fatal("invalid PostgreSQL fixture container")
	}
	previousSQL, err := os.ReadFile(os.Getenv("SYN443_TEST_PREVIOUS_CONFIGURATION_SQL"))
	if err != nil || len(previousSQL) == 0 || len(previousSQL) > 256*1024 {
		t.Fatal("read pinned prior configuration schema and roles", err)
	}

	const source = "syn443_ci_configuration_old"
	const restored = "syn443_ci_configuration_restored"
	for _, name := range []string{source, restored} {
		if _, err := fixtureOwner.Exec(`CREATE DATABASE ` + name + ` TEMPLATE template0`); err != nil {
			t.Fatal("create restore fixture database", err)
		}
		t.Cleanup(func() {
			if _, err := fixtureOwner.Exec(`DROP DATABASE ` + name + ` WITH (FORCE)`); err != nil {
				t.Error("drop restore fixture database", err)
			}
		})
	}
	ownerDSN := os.Getenv("SYN443_TEST_DATABASE")
	legacyOwner := configurationRestoreDB(t, ownerDSN, source)
	// Isolate the configuration upgrade while using the current shared dependencies.
	for _, sqlText := range []string{enrollment.Schema, catalog.Schema, enrollment.Roles, catalog.Roles, string(previousSQL)} {
		if _, err := legacyOwner.Exec(sqlText); err != nil {
			t.Fatal("install historical configuration fixture", err)
		}
	}

	n, control, proposal := configurationControlFixture(t)
	now, actor := n.f.now, n.actor.ID
	if _, err := legacyOwner.Exec(`INSERT INTO catalog_acl(actor,action,target_kind,target_id,expires)
		VALUES($1,'configuration.drafts.read','device',$2,$3),($1,'configuration.drafts.write','device',$2,$3)`,
		actor, proposal.TargetID, now.Add(time.Hour).Unix()); err != nil {
		t.Fatal("seed fixture authorization", err)
	}
	const original = "historical-draft-operation"
	raw, token, _ := operationOriginal(t, n, control, proposal, original, 1)
	originalDraft := ConfigurationDraft{ID: proposal.DraftID, Revision: 1, Proposal: proposal, SavedAtMs: now.UnixMilli()}
	writeOld := func(db *sql.DB, request, hash string, draft ConfigurationDraft) error {
		t.Helper()
		tx, err := db.Begin()
		if err != nil {
			t.Fatal("begin legacy operation", err)
		}
		defer tx.Rollback()
		if err := oldDraftSQL(t.Context(), tx, control, actor, request, hash, draft, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := writeOld(configurationRestoreDB(t, fixtureControlDSN, source), identity.Hash([]byte(original)), configurationHash(raw), originalDraft); err != nil {
		t.Fatal("historical restricted writer could not commit draft and receipt", err)
	}

	const drill = `
umask 077
scratch=$(mktemp -d)
trap 'rm -f "$scratch/snapshot.dump"; rmdir "$scratch"' EXIT
pg_dump --username=postgres --format=custom --file="$scratch/snapshot.dump" --dbname="$1"
pg_restore --username=postgres --single-transaction --exit-on-error --dbname="$2" "$scratch/snapshot.dump"
`
	cmd := exec.CommandContext(t.Context(), "docker", "exec", "--user", "postgres", container, "sh", "-ec", drill, "syn443-configuration-restore", source, restored)
	if err := cmd.Run(); err != nil {
		t.Fatal("configuration fixture dump or transactional restore failed", err)
	}
	currentOwner := configurationRestoreDB(t, ownerDSN, restored)
	var before bool
	if err := currentOwner.QueryRow(`SELECT to_regclass('public.managed_configuration_operations') IS NULL`).Scan(&before); err != nil || !before {
		t.Fatal("restored database did not start with the pre-ledger schema", err)
	}
	for range 2 {
		for _, sqlText := range []string{ConfigurationSchema, ConfigurationRoles} {
			if _, err := currentOwner.Exec(sqlText); err != nil {
				t.Fatal("apply current owner configuration migration", err)
			}
		}
	}

	api := configurationRestoreDB(t, fixtureControlDSN, restored)
	store := *control.Store
	store.DB = api
	control.Store = &store
	recorded := func(drafts, receipts, operations int) {
		t.Helper()
		var counts [3]int
		err := currentOwner.QueryRow(`SELECT (SELECT count(*) FROM managed_configuration_drafts),
			(SELECT count(*) FROM managed_configuration_draft_ops), (SELECT count(*) FROM managed_configuration_operations)`).
			Scan(&counts[0], &counts[1], &counts[2])
		if err != nil || counts != [3]int{drafts, receipts, operations} {
			t.Fatalf("unexpected draft, receipt and operation counts: %v (%v)", counts, err)
		}
	}
	assertOriginal := func(got any, err error) {
		t.Helper()
		want, wantErr := json.Marshal(originalDraft)
		data, dataErr := json.Marshal(got)
		if err != nil || wantErr != nil || dataErr != nil || !bytes.Equal(data, want) {
			t.Fatal("restored draft or original retry receipt changed", err)
		}
	}
	sameOperation := func() (any, error) {
		proof := signed(t, n.f.key, control.Origin+"/v1/control/action", token, "", raw, now)
		return control.Dispatch(t.Context(), token, proof, raw, now)
	}
	read, readToken, readProof := configurationCall(t, n, control, "configuration.layers.draft.get",
		identity.Hash([]byte("historical-draft-read")), map[string]string{"id": originalDraft.ID})
	assertOriginal(control.Dispatch(t.Context(), readToken, readProof, read, now))
	assertOriginal(sameOperation())
	recorded(1, 1, 0)

	fresh := originalDraft
	fresh.ID, fresh.Proposal.DraftID = "legacy-fresh", "legacy-fresh"
	err = writeOld(api, identity.Hash([]byte("historical-fresh-write")), configurationHash([]byte("new old-format operation")), fresh)
	var sqlErr *pgconn.PgError
	if !errors.As(err, &sqlErr) || sqlErr.Message != "configuration operation fence" {
		t.Fatal("legacy writer was not rejected by the current gateway", err)
	}
	recorded(1, 1, 0)

	next := ConfigurationDraft{ID: proposal.DraftID, Revision: 1, Proposal: proposal}
	next.Proposal.DraftRevision = 2
	request := identity.Hash([]byte("historical-current-write"))
	body, access, proof := configurationCall(t, n, control, "configuration.layers.draft.put", request, map[string]any{"draft": next})
	got, err := control.Dispatch(t.Context(), access, proof, body, now)
	saved, ok := got.(ConfigurationDraft)
	if err != nil || !ok || saved.Revision != 2 {
		t.Fatal("current writer did not update the restored draft", err)
	}
	var bound bool
	err = currentOwner.QueryRow(`SELECT o.action='configuration.layers.draft.put'
		AND o.target_kind='device' AND o.target_id=d.target_id AND o.disposition='recorded'
		AND o.effect_revision=2 AND d.revision=2 AND o.body_hash=n.body_hash AND o.body_hash=$3
		FROM managed_configuration_operations o
		JOIN managed_configuration_drafts d ON d.actor=o.actor AND d.id=o.effect_id
		JOIN managed_configuration_draft_ops n ON n.actor=o.actor AND n.request_id=o.request_id
		WHERE o.actor=$1 AND o.family='draft' AND o.request_id=$2`, actor, request, configurationHash(body)).Scan(&bound)
	if err != nil || !bound {
		t.Fatal("current write did not bind the draft, receipt and ledger", err)
	}
	assertOriginal(sameOperation())
	recorded(1, 2, 1)
}

func configurationRestoreDB(t *testing.T, dsn, database string) *sql.DB {
	t.Helper()
	uri, err := url.Parse(dsn)
	if err != nil || uri.Scheme != "postgres" || uri.Hostname() != "127.0.0.1" {
		t.Fatal("invalid restore fixture connection")
	}
	uri.Path = "/" + database
	db, err := sql.Open("pgx", uri.String())
	if err != nil {
		t.Fatal("open fixture database")
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
