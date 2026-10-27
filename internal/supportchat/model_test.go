package supportchat

import (
	"strings"
	"testing"
)

func TestSendBoundsAndUnicode(t *testing.T) {
	base := SendRequest{Conversation: strings.Repeat("a", 32), ClientID: strings.Repeat("b", 32), Text: "hello"}
	for _, text := range []string{"hello", "<script>alert(1)</script>", strings.Repeat("😀", 4096), "line\nnext"} {
		r := base
		r.Text = text
		if r.Validate() != nil {
			t.Fatal("valid text rejected")
		}
	}
	for _, text := range []string{"", " \t\n", strings.Repeat("x", 4097), strings.Repeat("😀", 4097), "a\x00b", string([]byte{255})} {
		r := base
		r.Text = text
		if r.Validate() == nil {
			t.Fatal("invalid text accepted")
		}
	}
	r := base
	r.Text = ""
	r.Attachments = []string{strings.Repeat("c", 32)}
	if r.Validate() != nil {
		t.Fatal("attachment-only message")
	}
	r.Attachments = append(r.Attachments, r.Attachments[0])
	if r.Validate() == nil {
		t.Fatal("duplicate attachment")
	}
	r = base
	r.Attachments = make([]string, 5)
	if r.Validate() == nil {
		t.Fatal("attachment count")
	}
	r = base
	r.Attachments = []string{"../invalid"}
	if r.Validate() == nil {
		t.Fatal("attachment ID")
	}
	r = base
	r.ClientID = strings.Repeat("G", 32)
	if r.Validate() == nil {
		t.Fatal("client ID")
	}
	r = base
	r.Conversation = "unknown"
	if r.Validate() == nil {
		t.Fatal("conversation ID")
	}
}
func TestUploadBoundariesAndSafeNames(t *testing.T) {
	base := UploadRequest{Conversation: strings.Repeat("a", 32), ClientID: strings.Repeat("b", 32), Name: "example.bin", MIME: "application/octet-stream", Size: MaxFileBytes, SHA256: strings.Repeat("c", 64), Kind: "file"}
	if base.Validate() != nil {
		t.Fatal("maximum file")
	}
	for _, size := range []int64{-1, 0, MaxFileBytes + 1} {
		r := base
		r.Size = size
		if r.Validate() == nil {
			t.Fatal("file size")
		}
	}
	for _, name := range []string{"", " ", ".", "..", "../a", "a/b", "a\\b", "a\x00b", "a\nb", "a\u202eb", strings.Repeat("x", 161), strings.Repeat("я", 128), string([]byte{255})} {
		r := base
		r.Name = name
		if r.Validate() == nil {
			t.Fatal("filename accepted")
		}
	}
	r := base
	r.Name = strings.Repeat("x", 160)
	if r.Validate() != nil {
		t.Fatal("name boundary")
	}
	for _, mime := range []string{"text/html", "image/svg+xml", "application/javascript", "Image/Jpeg", "image/jpeg; charset=utf-8"} {
		r := base
		r.MIME = mime
		if r.Validate() == nil {
			t.Fatal("MIME allowlist")
		}
	}
	for _, kind := range []string{"photo", "video", "unknown"} {
		r := base
		r.Kind = kind
		if r.Validate() == nil {
			t.Fatal("media kind mismatch")
		}
	}
	for _, mime := range []string{"image/jpeg", "image/png", "image/webp"} {
		r := base
		r.Kind = "photo"
		r.MIME = mime
		if r.Validate() != nil {
			t.Fatal("photo")
		}
	}
	r = base
	r.Kind = "video"
	r.MIME = "video/mp4"
	if r.Validate() != nil {
		t.Fatal("video")
	}
	r = base
	r.SHA256 = strings.Repeat("g", 64)
	if r.Validate() == nil {
		t.Fatal("digest")
	}
	r = base
	r.ClientID = "bad"
	if r.Validate() == nil {
		t.Fatal("ID")
	}
}
func TestMediaSniffDoesNotTrustDeclaredType(t *testing.T) {
	samples := map[string][]byte{"image/jpeg": {255, 216, 255}, "image/png": {137, 80, 78, 71, 13, 10, 26, 10}, "image/webp": []byte("RIFFxxxxWEBP"), "video/mp4": []byte("xxxxftypisom"), "application/pdf": []byte("%PDF-1.7"), "application/zip": {'P', 'K', 3, 4}, "text/plain": []byte("hello"), "application/octet-stream": {0}}
	for mime, data := range samples {
		if !mediaType(mime, data) {
			t.Fatal("valid signature")
		}
		if mime != "application/octet-stream" && mediaType(mime, []byte("<html>script")) {
			t.Fatal("mismatched signature")
		}
	}
	if mediaType("text/plain", []byte{0}) || mediaType("image/svg+xml", []byte("<svg/>")) {
		t.Fatal("unsafe preview")
	}
	if !mediaType("application/zip", []byte{'P', 'K', 5, 6}) {
		t.Fatal("empty archive")
	}
}
func TestRandomIDsAndHashes(t *testing.T) {
	a, b := newID(), newID()
	if !ID.MatchString(a) || a == b || Hash([]byte("a")) == Hash([]byte("b")) || !digest.MatchString(Hash(nil)) {
		t.Fatal("identity/hash")
	}
}
func FuzzSendValidation(f *testing.F) {
	f.Add("hello")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, text string) {
		r := SendRequest{Conversation: strings.Repeat("a", 32), ClientID: strings.Repeat("b", 32), Text: text}
		_ = r.Validate()
	})
}
