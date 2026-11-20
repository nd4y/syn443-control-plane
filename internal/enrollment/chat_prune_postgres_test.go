//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/supportchat"
)

func TestChatPruneWhileMessageWithAttachmentCommits(t *testing.T) {
	f, client := chatSetup(t)
	conversation := chatSelf(t, f, client)
	data := []byte("synthetic upload to keep")
	upload := chatBegin(t, f, client, conversation, chatID("a"), data, "text/plain", "file")
	chatCall(t, f, client, "uploads/part", map[string]any{"upload": upload, "part": 0, "data": data, "sha256": supportchat.Hash(data)}, http.StatusOK)
	chatCall(t, f, client, "uploads/complete", map[string]any{"upload": upload}, http.StatusOK)
	chatBegin(t, f, client, conversation, chatID("b"), data, "text/plain", "file")

	// A real send has validated the attachment and holds its update lock.
	tx, err := fixtureAPI.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	msg, err := json.Marshal(supportchat.SendRequest{Conversation: conversation, ClientID: chatID("c"), Text: "fixture", Attachments: []string{upload}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = supportchat.Dispatch(t.Context(), tx, client.owner, "send", msg, f.now); err != nil {
		t.Fatal(err)
	}
	cutoff := f.now.Add(24 * time.Hour)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	n, err := supportchat.DrainExpiredUploads(ctx, fixtureOwner, cutoff)
	if err != nil || n != 1 {
		t.Fatalf("expected only the unlocked orphan to expire, got %d: %v", n, err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	n, err = supportchat.PruneExpiredUploads(t.Context(), fixtureOwner, cutoff)
	if err != nil || n != 0 {
		t.Fatalf("linked upload selected after commit: %d, %v", n, err)
	}
	response := chatCall(t, f, client, "download", map[string]any{"attachment": upload, "part": 0}, http.StatusOK)
	var chunk struct{ Data []byte }
	if err := json.Unmarshal(response.Body.Bytes(), &chunk); err != nil || !bytes.Equal(chunk.Data, data) {
		t.Fatal("linked bytes changed")
	}
}

func seedChatExpiryBoundary(t *testing.T) time.Time {
	t.Helper()
	f, client := chatSetup(t)
	conversation := chatSelf(t, f, client)
	_, err := fixtureOwner.ExecContext(t.Context(), `INSERT INTO chat_uploads
        (id,conversation,sender,client_id,name,mime,kind,size,sha256,created_at,expires_at)
        SELECT md5(i::text),$1,$2,md5(i::text),'fixture.bin','application/octet-stream','file',1,repeat('0',64),$3::bigint-1,
            CASE WHEN i=131 THEN $3::bigint+1 ELSE $3::bigint END
        FROM generate_series(1,131) AS i`, conversation, client.owner, f.now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	return f.now
}

func TestChatPruneBatchLimitExpiryBoundaryAndRetry(t *testing.T) {
	now := seedChatExpiryBoundary(t)
	for _, want := range []int64{128, 2, 0} {
		got, err := supportchat.PruneExpiredUploads(t.Context(), fixtureOwner, now)
		if err != nil || got != want {
			t.Fatalf("pruned %d, want %d: %v", got, want, err)
		}
	}
	var remaining int
	if err := fixtureOwner.QueryRowContext(t.Context(), `SELECT count(*) FROM chat_uploads WHERE id=md5('131') AND expires_at=$1`, now.Unix()+1).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatal("unexpired upload was removed", err)
	}
}

func TestChatMaintenanceDrainsBacklogWithinOneInvocation(t *testing.T) {
	now := seedChatExpiryBoundary(t)
	stopped, cancel := context.WithCancel(t.Context())
	cancel()
	if n, err := supportchat.DrainExpiredUploads(stopped, fixtureOwner, now); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled cleanup did not return the cancellation", n, err)
	}
	for _, want := range []int64{130, 0} {
		if n, err := supportchat.DrainExpiredUploads(t.Context(), fixtureOwner, now); err != nil || n != want {
			t.Fatalf("pruned %d, want %d: %v", n, want, err)
		}
	}
	if n, err := supportchat.DrainExpiredUploads(t.Context(), fixtureOwner, now.Add(time.Second)); err != nil || n != 1 {
		t.Fatal("next cutoff must remove the remaining upload", n, err)
	}
}
