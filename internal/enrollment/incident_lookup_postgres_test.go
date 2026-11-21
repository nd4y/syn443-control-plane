//go:build postgres

package enrollment

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/supportchat"
)

func TestSQLIncidentLookupRequiresLiveGrantAndRejectsCollisionsAndForeignThreads(t *testing.T) {
	f, first := chatSetup(t)
	own := chatSelf(t, f, first)
	second := chatOther(t, f, "incident-second")
	theirs := chatSelf(t, f, second)
	admin := chatOther(t, f, "incident-admin")
	chatAdmin(t, admin, true)
	const ref = "SYN-0123456789ab"
	prefix := ref[4:]
	message := "Обращение " + ref + "\nСлой сбоя - TLS"
	send := func(who chatClient, dest, suffix, text string) {
		t.Helper()
		chatCall(t, f, who, "send", supportchat.SendRequest{Conversation: dest, ClientID: prefix + strings.Repeat(suffix, 20), Text: text}, 200)
	}
	lookup := func(reference string) map[string]any {
		t.Helper()
		r := chatCall(t, f, admin, "incident/lookup", map[string]string{"reference": reference}, 200)
		var result map[string]any
		if e := json.Unmarshal(r.Body.Bytes(), &result); e != nil || result["reference"] != reference {
			t.Fatal("wrong lookup shape", e)
		}
		return result
	}
	query := map[string]string{"reference": ref}
	chatCall(t, f, first, "incident/lookup", query, 403)
	for _, bad := range []map[string]string{{"reference": ref + "0"}, {"reference": "SYN-0123%"}, {"reference": ref, "conversation": own}} {
		chatCall(t, f, admin, "incident/lookup", bad, 400)
	}
	// An ordinary message and administrator speech in another owner's thread cannot become their incident.
	send(first, own, "a", "ordinary")
	send(admin, own, "b", message)
	if r := lookup(ref); r["state"] != "missing" || len(r) != 2 {
		t.Fatal("non-owner or ordinary message matched")
	}
	send(first, own, "c", message)
	r := lookup(ref)
	report, ok := r["report"].(map[string]any)
	if r["state"] != "found" || !ok || len(report) != 2 || report["text"] != message || report["createdAt"] != float64(f.now.Unix()) {
		t.Fatal("missing original owner report")
	}
	send(second, theirs, "d", message)
	if r := lookup(ref); r["state"] != "ambiguous" || len(r) != 2 {
		t.Fatal("a collision revealed one owner's message")
	}
	var cursors int
	if err := fixtureOwner.QueryRow(`SELECT count(*) FROM chat_read_cursors WHERE reader=$1`, admin.owner).Scan(&cursors); err != nil || cursors != 0 {
		t.Fatal("lookup moved the admin cursor", err, cursors)
	}
	chatAdmin(t, admin, false)
	chatCall(t, f, admin, "incident/lookup", query, 403)
}
