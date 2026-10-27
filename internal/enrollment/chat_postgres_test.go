//go:build postgres

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/supportchat"
)

type chatClient struct {
	key     *ecdsa.PrivateKey
	session Session
	owner   string
}

func chatSetup(t *testing.T) (*fixture, chatClient) {
	f := newFixture(t, 4)
	f.api.ChatEnabled = true
	k := key(t)
	s, _, _ := f.register(t, k)
	return f, chatClient{k, s, Owner(f.grant.Issuer, f.grant.Subject)}
}
func chatOther(t *testing.T, f *fixture, subject string) chatClient {
	old := f.grant
	f.grant.Subject = subject
	if e := Authorize(context.Background(), fixtureOwner, f.grant, f.now); e != nil {
		t.Fatal(e)
	}
	k := key(t)
	s, _, _ := f.register(t, k)
	c := chatClient{k, s, Owner(f.grant.Issuer, subject)}
	f.grant = old
	return c
}
func chatCall(t *testing.T, f *fixture, c chatClient, action string, value any, status int) *httptest.ResponseRecorder {
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	r := f.call(t, c.key, "POST", "/v1/chat/"+action, c.session.AccessToken, c.session.Nonce, raw)
	expect(t, r, status)
	return r
}
func chatSelf(t *testing.T, f *fixture, c chatClient) string {
	r := chatCall(t, f, c, "self", struct{}{}, 200)
	var out struct {
		Conversation supportchat.Conversation `json:"conversation"`
		Admin        bool                     `json:"admin"`
	}
	if identity.Decode(r.Body.Bytes(), &out, true) != nil {
		t.Fatal("self shape")
	}
	return out.Conversation.ID
}
func chatID(n string) string { return strings.Repeat(n, 32) }
func chatAdmin(t *testing.T, c chatClient, on bool) {
	if _, e := fixtureOwner.Exec(`INSERT INTO chat_admins(owner,enabled) VALUES($1,$2) ON CONFLICT(owner) DO UPDATE SET enabled=excluded.enabled`, c.owner, on); e != nil {
		t.Fatal(e)
	}
}
func TestChatMessageIdempotencyPersistenceAndRead(t *testing.T) {
	f, c := chatSetup(t)
	id := chatSelf(t, f, c)
	secondKey := key(t)
	s, _, _ := f.register(t, secondKey)
	second := chatClient{secondKey, s, c.owner}
	if chatSelf(t, f, second) != id {
		t.Fatal("duplicate per-device conversation")
	}
	request := supportchat.SendRequest{Conversation: id, ClientID: chatID("a"), Text: "<script>synthetic</script>"}
	a := chatCall(t, f, c, "send", request, 200)
	b := chatCall(t, f, second, "send", request, 200)
	if a.Body.String() != b.Body.String() {
		t.Fatal("lost-response retry changed message")
	}
	request.Text = "different"
	chatCall(t, f, c, "send", request, 409)
	chatCall(t, f, c, "messages", map[string]any{"conversation": id}, 200)
	chatCall(t, f, c, "messages", map[string]any{"conversation": id, "after": 1}, 200)
	chatCall(t, f, c, "messages", map[string]any{"conversation": id, "before": 2}, 200)
	chatCall(t, f, c, "messages", map[string]any{"conversation": id, "before": 2, "after": 1}, 400)
	chatCall(t, f, c, "read", map[string]any{"conversation": id, "sequence": 1}, 200)
	chatCall(t, f, c, "read", map[string]any{"conversation": id, "sequence": 0}, 200)
	chatCall(t, f, c, "read", map[string]any{"conversation": id, "sequence": 2}, 400)
	var seq, count int
	if e := fixtureOwner.QueryRow(`SELECT last_seq FROM chat_read_cursors WHERE conversation=$1 AND reader=$2`, id, c.owner).Scan(&seq); e != nil || seq != 1 {
		t.Fatal("read cursor regression")
	}
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM chat_messages WHERE conversation=$1`, id).Scan(&count); e != nil || count != 1 {
		t.Fatal("message duplicated")
	}
	recreated, _ := NewStore(fixtureAPI, f.encryption)
	f.api.Store = recreated
	if got := chatCall(t, f, second, "send", supportchat.SendRequest{Conversation: id, ClientID: chatID("a"), Text: "<script>synthetic</script>"}, 200); got.Body.String() != a.Body.String() {
		t.Fatal("persistent receipt")
	}
	chatCall(t, f, c, "self", map[string]string{"owner": "other"}, 400)
	chatCall(t, f, c, "send", map[string]string{"conversation": id, "clientId": chatID("b"), "text": ""}, 400)
}
func TestChatOwnershipAndLiveAdminRevocation(t *testing.T) {
	f, user := chatSetup(t)
	id := chatSelf(t, f, user)
	other := chatOther(t, f, "synthetic-other")
	admin := chatOther(t, f, "synthetic-admin")
	chatAdmin(t, admin, true)
	for _, c := range []chatClient{user, other} {
		chatCall(t, f, c, "inbox", struct{}{}, 403)
	}
	chatCall(t, f, other, "messages", map[string]any{"conversation": id}, 403)
	chatCall(t, f, other, "send", supportchat.SendRequest{Conversation: id, ClientID: chatID("a"), Text: "forbidden"}, 403)
	chatCall(t, f, other, "read", map[string]any{"conversation": id, "sequence": 0}, 403)
	chatCall(t, f, admin, "inbox", struct{}{}, 200)
	chatCall(t, f, admin, "inbox", map[string]any{"before": f.now.Unix(), "beforeId": chatID("f")}, 200)
	chatCall(t, f, admin, "inbox", map[string]any{"before": 1}, 400)
	chatCall(t, f, admin, "send", supportchat.SendRequest{Conversation: id, ClientID: chatID("b"), Text: "reply"}, 200)
	data := []byte("synthetic")
	upload := chatBegin(t, f, admin, id, chatID("a"), data, "application/octet-stream", "file")
	chatAdmin(t, admin, false)
	chatCall(t, f, admin, "messages", map[string]any{"conversation": id}, 403)
	chatCall(t, f, admin, "uploads/status", map[string]any{"upload": upload}, 403)
	chatCall(t, f, admin, "uploads/part", map[string]any{"upload": upload, "part": 0, "data": data, "sha256": supportchat.Hash(data)}, 403)
	chatCall(t, f, admin, "uploads/complete", map[string]any{"upload": upload}, 403)
	if _, e := fixtureOwner.Exec(`UPDATE identity_devices SET active=false WHERE id=$1`, user.session.DeviceID); e != nil {
		t.Fatal(e)
	}
	chatCall(t, f, user, "messages", map[string]any{"conversation": id}, 403)
	if _, e := fixtureAPI.Exec(`UPDATE chat_admins SET enabled=true WHERE owner=$1`, admin.owner); e == nil {
		t.Fatal("API escalated chat authority")
	}
	if _, e := fixturePublisher.Exec(`SELECT * FROM chat_messages`); e == nil {
		t.Fatal("publisher read chat contents")
	}
}
func chatBegin(t *testing.T, f *fixture, c chatClient, conv, client string, data []byte, mime, kind string) string {
	req := supportchat.UploadRequest{Conversation: conv, ClientID: client, Name: "synthetic.bin", MIME: mime, Size: int64(len(data)), SHA256: supportchat.Hash(data), Kind: kind}
	r := chatCall(t, f, c, "uploads/begin", req, 200)
	var out struct {
		Attachment supportchat.Attachment `json:"attachment"`
		Complete   bool                   `json:"complete"`
		Parts      []int                  `json:"parts"`
	}
	if identity.Decode(r.Body.Bytes(), &out, true) != nil {
		t.Fatal("upload status shape")
	}
	return out.Attachment.ID
}
func TestChatTwentyFiveMiBResumeCommitAndPrivateDownload(t *testing.T) {
	f, c := chatSetup(t)
	id := chatSelf(t, f, c)
	other := chatOther(t, f, "synthetic-other")
	data := bytes.Repeat([]byte{42}, supportchat.MaxFileBytes)
	upload := chatBegin(t, f, c, id, chatID("a"), data, "application/octet-stream", "file")
	for n := 0; n < 100; n++ {
		chunk := data[n*supportchat.ChunkBytes : (n+1)*supportchat.ChunkBytes]
		chatCall(t, f, c, "uploads/part", map[string]any{"upload": upload, "part": n, "data": chunk, "sha256": supportchat.Hash(chunk)}, 200)
		if n == 1 {
			chatCall(t, f, c, "uploads/complete", map[string]any{"upload": upload}, 409)
			chatCall(t, f, c, "download", map[string]any{"attachment": upload, "part": 0}, 403)
		}
	}
	chatCall(t, f, c, "uploads/status", map[string]any{"upload": upload}, 200)
	chunk := data[:supportchat.ChunkBytes]
	chatCall(t, f, c, "uploads/part", map[string]any{"upload": upload, "part": 0, "data": chunk, "sha256": supportchat.Hash(chunk)}, 200)
	changed := bytes.Repeat([]byte{43}, supportchat.ChunkBytes)
	chatCall(t, f, c, "uploads/part", map[string]any{"upload": upload, "part": 0, "data": changed, "sha256": supportchat.Hash(changed)}, 409)
	chatCall(t, f, c, "uploads/complete", map[string]any{"upload": upload}, 200)
	chatCall(t, f, c, "uploads/complete", map[string]any{"upload": upload}, 200)
	chatCall(t, f, c, "send", supportchat.SendRequest{Conversation: id, ClientID: chatID("b"), Attachments: []string{upload}}, 200)
	chatCall(t, f, c, "send", supportchat.SendRequest{Conversation: id, ClientID: chatID("c"), Attachments: []string{upload}}, 409)
	r := chatCall(t, f, c, "download", map[string]any{"attachment": upload, "part": 99}, 200)
	var out struct {
		Data   []byte `json:"data"`
		SHA256 string `json:"sha256"`
	}
	if identity.DecodeAttachmentChunk(r.Body.Bytes(), &out) != nil || !bytes.Equal(out.Data, chunk) || out.SHA256 != supportchat.Hash(chunk) || r.Header().Get("X-Content-Type-Options") != "nosniff" || r.Header().Get("Content-Disposition") == "" {
		t.Fatal("download integrity or headers")
	}
	chatCall(t, f, other, "download", map[string]any{"attachment": upload, "part": 0}, 403)
	chatCall(t, f, c, "uploads/cancel", map[string]any{"upload": upload}, 409)
}
func TestChatUploadLimitsExpiryQuotaAndMediaSignature(t *testing.T) {
	f, c := chatSetup(t)
	id := chatSelf(t, f, c)
	data := []byte("not an image")
	upload := chatBegin(t, f, c, id, chatID("a"), data, "image/jpeg", "photo")
	chatCall(t, f, c, "uploads/part", map[string]any{"upload": upload, "part": 0, "data": data, "sha256": supportchat.Hash(data)}, 200)
	chatCall(t, f, c, "uploads/complete", map[string]any{"upload": upload}, 409)
	chatCall(t, f, c, "uploads/part", map[string]any{"upload": upload, "part": 1, "data": data, "sha256": supportchat.Hash(data)}, 400)
	chatCall(t, f, c, "uploads/part", map[string]any{"upload": upload, "part": 0, "data": data, "sha256": strings.Repeat("0", 64)}, 400)
	chatCall(t, f, c, "uploads/cancel", map[string]any{"upload": upload}, 200)
	chatCall(t, f, c, "uploads/status", map[string]any{"upload": upload}, 403)
	for i := 1; i <= 8; i++ {
		chatBegin(t, f, c, id, fmt.Sprintf("%032x", i), data, "application/octet-stream", "file")
	}
	req := supportchat.UploadRequest{Conversation: id, ClientID: chatID("9"), Name: "fixture.bin", MIME: "application/octet-stream", Size: 1, SHA256: supportchat.Hash([]byte{1}), Kind: "file"}
	chatCall(t, f, c, "uploads/begin", req, 413)
	if _, e := fixtureOwner.Exec(`UPDATE chat_uploads SET expires_at=$1 WHERE sender=$2`, f.now.Unix()-1, c.owner); e != nil {
		t.Fatal(e)
	}
	chatCall(t, f, c, "uploads/begin", req, 200)
	var count int
	if e := fixtureOwner.QueryRow(`SELECT count(*) FROM chat_uploads WHERE sender=$1`, c.owner).Scan(&count); e != nil || count != 1 {
		t.Fatal("expired upload cleanup")
	}
	req.Size = supportchat.MaxFileBytes + 1
	req.ClientID = chatID("8")
	chatCall(t, f, c, "uploads/begin", req, 400)
	chatCall(t, f, c, "download", map[string]any{"attachment": chatID("0"), "part": 0}, 403)
	chatCall(t, f, c, "download", map[string]any{"attachment": chatID("0"), "part": 100}, 400)
}
func TestChatWebAdminRequiresSeparateVerifierLiveAuthorityAndNonce(t *testing.T) {
	f, user := chatSetup(t)
	id := chatSelf(t, f, user)
	admin := chatOther(t, f, "synthetic-admin")
	chatAdmin(t, admin, true)
	token := random()
	thumb, _ := identity.PublicJWK(&admin.key.PublicKey).Thumbprint()
	f.api.ChatVerifier = &verifier{principals: map[string]identity.Principal{token: {Issuer: f.grant.Issuer, Subject: "synthetic-admin", Thumbprint: thumb}}}
	body := []byte(`{}`)
	path := "/v1/admin/chat/inbox"
	r := f.call(t, admin.key, "POST", path, token, "", body)
	expect(t, r, 401)
	nonce := r.Header().Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("web challenge")
	}
	expect(t, f.call(t, admin.key, "POST", path, token, nonce, body), 200)
	expect(t, f.call(t, admin.key, "POST", path, admin.session.AccessToken, nonce, body), 401)
	expect(t, f.call(t, user.key, "POST", path, token, nonce, body), 403)
	raw, _ := json.Marshal(map[string]any{"conversation": id})
	expect(t, f.call(t, admin.key, "POST", "/v1/admin/chat/messages", token, nonce, raw), 200)
	chatAdmin(t, admin, false)
	expect(t, f.call(t, admin.key, "POST", path, token, nonce, body), 403)
	f.api.ChatWebOrigin = "https://panel.example.invalid"
	request := httptest.NewRequest("OPTIONS", f.origin+path, nil)
	request.Header.Set("Origin", f.api.ChatWebOrigin)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, request)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != f.api.ChatWebOrigin || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("CORS boundary")
	}
	request.Header.Set("Origin", "https://other.example.invalid")
	w = httptest.NewRecorder()
	f.api.ServeHTTP(w, request)
	expect(t, w, 403)
}

func TestChatConcurrentIdempotencyAndReplay(t *testing.T) {
	f, c := chatSetup(t)
	id := chatSelf(t, f, c)
	req := supportchat.SendRequest{Conversation: id, ClientID: chatID("a"), Text: "one"}
	raw, _ := json.Marshal(req)
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses <- f.call(t, c.key, "POST", "/v1/chat/send", c.session.AccessToken, c.session.Nonce, raw)
		}()
	}
	wg.Wait()
	close(responses)
	first := ""
	for r := range responses {
		if r.Code == 503 {
			if r.Body.String() != "capacity_unavailable\n" {
				t.Fatal("unexpected overload")
			}
			// Bounded admission is intentional. Retry the same message with a fresh
			// proof after capacity returns, never manufacture a second client ID.
			r = f.call(t, c.key, "POST", "/v1/chat/send", c.session.AccessToken, c.session.Nonce, raw)
		}
		expect(t, r, 200)
		if first == "" {
			first = r.Body.String()
		} else if first != r.Body.String() {
			t.Fatal("concurrent duplicate")
		}
	}
	body := []byte(`{}`)
	proof := signed(t, c.key, "POST", f.origin+"/v1/chat/self", c.session.AccessToken, c.session.Nonce, body, f.now)
	expect(t, f.rawCall("POST", "/v1/chat/self", c.session.AccessToken, proof, body), 200)
	expect(t, f.rawCall("POST", "/v1/chat/self", c.session.AccessToken, proof, body), 401)
	f.api.ChatEnabled = false
	chatCall(t, f, c, "self", struct{}{}, 404)
}

func TestChatHTTPBoundariesDoNotReachSQLOrAcceptForeignOrigins(t *testing.T) {
	f, c := chatSetup(t)
	call := func(method, path, body string, change func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.17:1234"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+c.session.AccessToken)
		req.Header.Set("DPoP", "invalid")
		if change != nil {
			change(req)
		}
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, req)
		return w
	}
	expect(t, call("POST", "/v1/chat/unknown", "{}", nil), 404)
	expect(t, call("GET", "/v1/chat/self", "{}", nil), 401)
	expect(t, call("POST", "/v1/chat/self", "{}", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example.invalid") }), 403)
	expect(t, call("POST", "/v1/chat/self", "{}", func(r *http.Request) { r.Header.Add("Authorization", "DPoP duplicate") }), 401)
	expect(t, call("POST", "/v1/chat/self", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+c.session.AccessToken) }), 401)
	expect(t, call("POST", "/v1/chat/self", strings.Repeat("x", 32769), nil), 413)
	expect(t, call("POST", "/v1/chat/uploads/part", strings.Repeat("x", 352*1024+1), nil), 413)
	expect(t, call("POST", "/v1/chat/self", "{}", nil), 401)
	expect(t, call("POST", "/v1/chat/self", "{}", func(r *http.Request) { r.RemoteAddr = "invalid" }), 401)
	for range cap(f.api.chatSlots) {
		f.api.chatSlots <- struct{}{}
	}
	expect(t, call("POST", "/v1/chat/self", "{}", nil), 503)
	for range cap(f.api.chatSlots) {
		<-f.api.chatSlots
	}
	path := "/v1/admin/chat/self"
	raw := []byte(`{}`)
	expect(t, f.rawCall("POST", path, c.session.AccessToken, signed(t, c.key, "POST", f.origin+path, c.session.AccessToken, "", raw, f.now), raw), 403)
	chatCall(t, f, c, "send", supportchat.SendRequest{Conversation: chatID("a"), ClientID: chatID("b"), Text: ""}, 400)
}
