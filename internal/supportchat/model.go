// Package supportchat implements the private SQL support mailbox, not public messaging.
package supportchat

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxFileBytes = 25 * 1024 * 1024
const ChunkBytes = 256 * 1024
const MaxTextBytes = 16384
const MaxTextRunes = 4096
const MaxAttachments = 4

var ErrInvalid = errors.New("chat_invalid")
var ErrDenied = errors.New("chat_denied")
var ErrConflict = errors.New("chat_conflict")
var ErrQuota = errors.New("chat_quota")
var ErrNotReady = errors.New("chat_upload_incomplete")
var ID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Conversation struct {
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	UpdatedAt int64  `json:"updatedAt"`
	LastSeq   int64  `json:"lastSeq"`
	ReadSeq   int64  `json:"readSeq"`
}
type Attachment struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	MIME   string `json:"mime"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
}
type Message struct {
	ID           string       `json:"id"`
	Conversation string       `json:"conversation"`
	Sender       string       `json:"sender"`
	SenderRole   string       `json:"senderRole"`
	ClientID     string       `json:"clientId"`
	Sequence     int64        `json:"sequence"`
	Text         string       `json:"text"`
	CreatedAt    int64        `json:"createdAt"`
	Attachments  []Attachment `json:"attachments"`
}
type UploadRequest struct {
	Conversation string `json:"conversation"`
	ClientID     string `json:"clientId"`
	Name         string `json:"name"`
	MIME         string `json:"mime"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	Kind         string `json:"kind"`
}
type SendRequest struct {
	Conversation string   `json:"conversation"`
	ClientID     string   `json:"clientId"`
	Text         string   `json:"text"`
	Attachments  []string `json:"attachments"`
}

func (r SendRequest) Validate() error {
	if !ID.MatchString(r.Conversation) || !ID.MatchString(r.ClientID) || !utf8.ValidString(r.Text) || len(r.Text) > MaxTextBytes || utf8.RuneCountInString(r.Text) > MaxTextRunes || strings.ContainsRune(r.Text, 0) || len(r.Attachments) > MaxAttachments || (strings.TrimSpace(r.Text) == "" && len(r.Attachments) == 0) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range r.Attachments {
		if !ID.MatchString(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}
func (r UploadRequest) Validate() error {
	if !ID.MatchString(r.Conversation) || !ID.MatchString(r.ClientID) || !digest.MatchString(r.SHA256) || r.Size < 1 || r.Size > MaxFileBytes || !utf8.ValidString(r.Name) || len(r.Name) > 255 || utf8.RuneCountInString(r.Name) > 160 || strings.TrimSpace(r.Name) == "" || r.Name == "." || r.Name == ".." || strings.ContainsAny(r.Name, "/\\") {
		return ErrInvalid
	}
	for _, c := range r.Name {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return ErrInvalid
		}
	}
	switch r.MIME {
	case "application/octet-stream", "application/pdf", "application/zip", "text/plain", "image/jpeg", "image/png", "image/webp", "video/mp4":
	default:
		return ErrInvalid
	}
	switch r.Kind {
	case "file":
	case "photo":
		if !strings.HasPrefix(r.MIME, "image/") {
			return ErrInvalid
		}
	case "video":
		if r.MIME != "video/mp4" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func newID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("random_unavailable")
	}
	return hex.EncodeToString(b[:])
}
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
