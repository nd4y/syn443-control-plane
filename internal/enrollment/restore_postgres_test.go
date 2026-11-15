//go:build postgres

package enrollment

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/nd4y/syn443-control-plane/internal/supportchat"
)

const restoreDatabase = "syn443_ci_restore"

// Use the pinned PostgreSQL tools inside the short-lived test container.
// The dump never leaves that container or becomes a CI artifact.
func restoreFixture(t *testing.T) *sql.DB {
	t.Helper()
	container := os.Getenv("SYN443_RESTORE_FIXTURE_CONTAINER")
	if container == "" && os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("container-local pg_dump and pg_restore are required for this drill")
	}
	if _, err := hex.DecodeString(container); err != nil || len(container) != 64 {
		t.Fatal("restore drill requires the test PostgreSQL container")
	}
	t.Cleanup(func() {
		if _, err := fixtureOwner.Exec(`DROP DATABASE IF EXISTS syn443_ci_restore WITH (FORCE)`); err != nil {
			t.Error("temporary restored database cleanup failed")
		}
	})
	const drill = `
umask 077
scratch=$(mktemp -d)
trap 'rm -f "$scratch/snapshot.dump"; rmdir "$scratch"' EXIT
pg_dump --username=postgres --format=custom --file="$scratch/snapshot.dump" --dbname=postgres
createdb --username=postgres --template=template0 syn443_ci_restore
pg_restore --username=postgres --single-transaction --exit-on-error --dbname=syn443_ci_restore "$scratch/snapshot.dump"
`
	cmd := exec.CommandContext(t.Context(), "docker", "exec", "--user", "postgres", container, "sh", "-ec", drill)
	if err := cmd.Run(); err != nil {
		t.Fatal("temporary PostgreSQL dump or transactional restore failed", err)
	}
	dsn, err := url.Parse(fixtureAPIDSN)
	if err != nil {
		t.Fatal("fixture API address is invalid")
	}
	dsn.Path = "/" + restoreDatabase
	restored, err := sql.Open("pgx", dsn.String())
	if err != nil {
		t.Fatal("fixture API connection setup failed")
	}
	t.Cleanup(func() { _ = restored.Close() })
	return restored
}

func TestSQLBackupRestorePreservesPolicyAndChatAttachment(t *testing.T) {
	f, c := chatSetup(t)
	other := chatOther(t, f, "synthetic-restore-other")
	if err := f.publisher().RunOnce(t.Context(), f.now); err != nil {
		t.Fatal("fixture policy publication failed", err)
	}
	const policyPath = "/v1/device/policy"
	before := f.call(t, c.key, http.MethodGet, policyPath, c.session.AccessToken, c.session.Nonce, nil)
	expect(t, before, http.StatusOK)

	conversation := chatSelf(t, f, c)
	data := bytes.Repeat([]byte{91, 7, 32}, 141)
	upload := chatBegin(t, f, c, conversation, chatID("a"), data, "application/octet-stream", "file")
	chatCall(t, f, c, "uploads/part", map[string]any{"upload": upload, "part": 0, "data": data, "sha256": supportchat.Hash(data)}, http.StatusOK)
	chatCall(t, f, c, "uploads/complete", map[string]any{"upload": upload}, http.StatusOK)
	message := supportchat.SendRequest{Conversation: conversation, ClientID: chatID("b"), Text: "fixture before backup", Attachments: []string{upload}}
	sent := chatCall(t, f, c, "send", message, http.StatusOK)
	historyRequest := map[string]any{"conversation": conversation}
	history := chatCall(t, f, c, "messages", historyRequest, http.StatusOK)

	restored := restoreFixture(t)
	// This write proves the restored API uses the snapshot, not the source.
	chatCall(t, f, c, "send", supportchat.SendRequest{Conversation: conversation, ClientID: chatID("c"), Text: "fixture after backup"}, http.StatusOK)
	var rows int
	if err := fixtureOwner.QueryRow(`SELECT count(*) FROM chat_messages WHERE conversation=$1`, conversation).Scan(&rows); err != nil || rows != 2 {
		t.Fatal("source did not advance after the snapshot")
	}
	store, err := NewStore(restored, f.encryption)
	if err != nil {
		t.Fatal("restored API store setup failed")
	}
	f.api.Store = store
	after := f.call(t, c.key, http.MethodGet, policyPath, c.session.AccessToken, c.session.Nonce, nil)
	expect(t, after, http.StatusOK)
	thumb, _ := identity.PublicJWK(&c.key.PublicKey).Thumbprint()
	payload, err := policy.VerifyBound(after.Body.String(), f.api.Roots, c.session.DeviceID, thumb, f.now)
	if err != nil || payload.Revision != 1 || !bytes.Equal(after.Body.Bytes(), before.Body.Bytes()) {
		t.Fatal("restored policy is not the same signed device policy")
	}
	if retry := chatCall(t, f, c, "send", message, http.StatusOK); !bytes.Equal(retry.Body.Bytes(), sent.Body.Bytes()) {
		t.Fatal("restored idempotency receipt changed")
	}
	if got := chatCall(t, f, c, "messages", historyRequest, http.StatusOK); !bytes.Equal(got.Body.Bytes(), history.Body.Bytes()) {
		t.Fatal("restored chat history differs from the snapshot")
	}
	req := map[string]any{"attachment": upload, "part": 0}
	download := chatCall(t, f, c, "download", req, http.StatusOK)
	var restoredFile struct {
		Data   []byte `json:"data"`
		SHA256 string `json:"sha256"`
	}
	if err := identity.DecodeAttachmentChunk(download.Body.Bytes(), &restoredFile); err != nil ||
		!bytes.Equal(restoredFile.Data, data) || restoredFile.SHA256 != supportchat.Hash(data) {
		t.Fatal("restored attachment contents or digest changed")
	}
	chatCall(t, f, other, "download", req, http.StatusForbidden)
	if _, err := restored.Exec(`TRUNCATE chat_messages CASCADE`); err == nil {
		t.Fatal("database restore unexpectedly broadened the API role")
	}
}
