package supportchat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// Dispatch runs inside the caller's authenticated identity transaction. Its owner
// comes from the locked session, never a request field. Role revocation and
// conversation order linearize at their row locks before any message/file effect.
func Dispatch(ctx context.Context, tx *sql.Tx, owner, action string, raw []byte, now time.Time) (any, error) {
	var admin bool
	e := tx.QueryRowContext(ctx, `SELECT enabled FROM chat_admins WHERE owner=$1 FOR SHARE`, owner).Scan(&admin)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	if action == "self" {
		var r struct{}
		if identity.Decode(raw, &r, true) != nil {
			return nil, ErrInvalid
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO chat_conversations(id,owner,updated_at) VALUES($1,$2,$3) ON CONFLICT(owner) DO NOTHING`, newID(), owner, now.Unix())
		if e != nil {
			return nil, e
		}
		var c Conversation
		e = tx.QueryRowContext(ctx, `SELECT c.id,c.owner,c.updated_at,c.next_seq-1,COALESCE(r.last_seq,0) FROM chat_conversations c LEFT JOIN chat_read_cursors r ON r.conversation=c.id AND r.reader=$1 WHERE c.owner=$1`, owner).Scan(&c.ID, &c.Owner, &c.UpdatedAt, &c.LastSeq, &c.ReadSeq)
		return struct {
			Conversation Conversation `json:"conversation"`
			Admin        bool         `json:"admin"`
		}{c, admin}, e
	}
	if action == "inbox" {
		var r struct {
			Before   int64  `json:"before"`
			BeforeID string `json:"beforeId"`
		}
		if identity.Decode(raw, &r, true) != nil || r.Before < 0 || (r.Before != 0 && !ID.MatchString(r.BeforeID)) || (r.Before == 0 && r.BeforeID != "") {
			return nil, ErrInvalid
		}
		if !admin {
			return nil, ErrDenied
		}
		rows, e := tx.QueryContext(ctx, `SELECT c.id,c.owner,c.updated_at,c.next_seq-1,COALESCE(r.last_seq,0) FROM chat_conversations c LEFT JOIN chat_read_cursors r ON r.conversation=c.id AND r.reader=$1 WHERE ($2::bigint=0 OR (c.updated_at,c.id)<($2,$3)) ORDER BY c.updated_at DESC,c.id DESC LIMIT 50`, owner, r.Before, r.BeforeID)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		out := []Conversation{}
		for rows.Next() {
			var c Conversation
			if e = rows.Scan(&c.ID, &c.Owner, &c.UpdatedAt, &c.LastSeq, &c.ReadSeq); e != nil {
				return nil, e
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
	switch action {
	case "messages":
		var r struct {
			Conversation string `json:"conversation"`
			Before       int64  `json:"before"`
			After        int64  `json:"after"`
		}
		if identity.Decode(raw, &r, true) != nil || r.Before < 0 || r.After < 0 || (r.Before > 0 && r.After > 0) {
			return nil, ErrInvalid
		}
		if _, e = access(ctx, tx, owner, admin, r.Conversation); e != nil {
			return nil, e
		}
		order := "DESC"
		if r.After > 0 {
			order = "ASC"
		}
		rows, e := tx.QueryContext(ctx, `SELECT id,conversation,sender,sender_role,client_id,sequence,text,created_at FROM chat_messages WHERE conversation=$1 AND ($2::bigint=0 OR sequence<$2) AND sequence>$3 ORDER BY sequence `+order+` LIMIT 20`, r.Conversation, r.Before, r.After)
		if e != nil {
			return nil, e
		}
		out := []Message{}
		for rows.Next() {
			var m Message
			if e = rows.Scan(&m.ID, &m.Conversation, &m.Sender, &m.SenderRole, &m.ClientID, &m.Sequence, &m.Text, &m.CreatedAt); e != nil {
				rows.Close()
				return nil, e
			}
			out = append(out, m)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		for i := range out {
			out[i].Attachments, e = attachments(ctx, tx, out[i].ID)
			if e != nil {
				return nil, e
			}
		}
		var peerRead int64
		e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(r.last_seq),0) FROM chat_read_cursors r JOIN chat_conversations c ON c.id=r.conversation WHERE c.id=$1 AND (($2::boolean AND r.reader=c.owner) OR (NOT $2 AND r.reader<>c.owner))`, r.Conversation, admin).Scan(&peerRead)
		return struct {
			Messages []Message `json:"messages"`
			PeerRead int64     `json:"peerRead"`
		}{out, peerRead}, e
	case "send":
		var r SendRequest
		if identity.Decode(raw, &r, true) != nil || r.Validate() != nil {
			return nil, ErrInvalid
		}
		next, e := access(ctx, tx, owner, admin, r.Conversation)
		if e != nil {
			return nil, e
		}
		encoded, _ := json.Marshal(r)
		hash := Hash(encoded)
		var prior, priorHash string
		e = tx.QueryRowContext(ctx, `SELECT id,body_hash FROM chat_messages WHERE sender=$1 AND client_id=$2`, owner, r.ClientID).Scan(&prior, &priorHash)
		if e == nil {
			if priorHash != hash {
				return nil, ErrConflict
			}
			return message(ctx, tx, prior)
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
		for _, id := range r.Attachments {
			var c, s string
			var complete bool
			var linked sql.NullString
			var expires int64
			e = tx.QueryRowContext(ctx, `SELECT conversation,sender,complete,message_id,expires_at FROM chat_uploads WHERE id=$1 FOR UPDATE`, id).Scan(&c, &s, &complete, &linked, &expires)
			if errors.Is(e, sql.ErrNoRows) || e == nil && (c != r.Conversation || s != owner || !complete || linked.Valid || expires <= now.Unix()) {
				return nil, ErrNotReady
			}
			if e != nil {
				return nil, e
			}
		}
		role := "user"
		if admin {
			role = "admin"
		}
		id := newID()
		_, e = tx.ExecContext(ctx, `INSERT INTO chat_messages(id,conversation,sender,sender_role,client_id,body_hash,sequence,text,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, r.Conversation, owner, role, r.ClientID, hash, next, r.Text, now.Unix())
		if e != nil {
			return nil, e
		}
		for _, f := range r.Attachments {
			if _, e = tx.ExecContext(ctx, `UPDATE chat_uploads SET message_id=$1 WHERE id=$2`, id, f); e != nil {
				return nil, e
			}
		}
		_, e = tx.ExecContext(ctx, `UPDATE chat_conversations SET next_seq=next_seq+1,updated_at=$2 WHERE id=$1`, r.Conversation, now.Unix())
		if e != nil {
			return nil, e
		}
		return message(ctx, tx, id)
	case "read":
		var r struct {
			Conversation string `json:"conversation"`
			Sequence     int64  `json:"sequence"`
		}
		if identity.Decode(raw, &r, true) != nil || r.Sequence < 0 {
			return nil, ErrInvalid
		}
		next, e := access(ctx, tx, owner, admin, r.Conversation)
		if e != nil {
			return nil, e
		}
		if r.Sequence >= next {
			return nil, ErrInvalid
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO chat_read_cursors(conversation,reader,last_seq) VALUES($1,$2,$3) ON CONFLICT(conversation,reader) DO UPDATE SET last_seq=GREATEST(chat_read_cursors.last_seq,excluded.last_seq)`, r.Conversation, owner, r.Sequence)
		return map[string]bool{"ok": true}, e
	case "uploads/begin":
		var r UploadRequest
		if identity.Decode(raw, &r, true) != nil || r.Validate() != nil {
			return nil, ErrInvalid
		}
		if _, e = access(ctx, tx, owner, admin, r.Conversation); e != nil {
			return nil, e
		}
		var id string
		var old UploadRequest
		e = tx.QueryRowContext(ctx, `SELECT id,conversation,client_id,name,mime,size,sha256,kind FROM chat_uploads WHERE sender=$1 AND client_id=$2`, owner, r.ClientID).Scan(&id, &old.Conversation, &old.ClientID, &old.Name, &old.MIME, &old.Size, &old.SHA256, &old.Kind)
		if e == nil {
			if old != r {
				return nil, ErrConflict
			}
			return uploadStatus(ctx, tx, owner, id, now)
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM chat_uploads WHERE sender=$1 AND message_id IS NULL AND expires_at<=$2`, owner, now.Unix()); e != nil {
			return nil, e
		}
		var count int
		var pending, total int64
		e = tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE message_id IS NULL),COALESCE(sum(size) FILTER(WHERE message_id IS NULL),0),COALESCE(sum(size),0) FROM chat_uploads WHERE sender=$1`, owner).Scan(&count, &pending, &total)
		if e != nil {
			return nil, e
		}
		if count >= 8 || pending+r.Size > 4*MaxFileBytes || total+r.Size > 1024*1024*1024 {
			return nil, ErrQuota
		}
		id = newID()
		_, e = tx.ExecContext(ctx, `INSERT INTO chat_uploads(id,conversation,sender,client_id,name,mime,kind,size,sha256,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, r.Conversation, owner, r.ClientID, r.Name, r.MIME, r.Kind, r.Size, r.SHA256, now.Unix(), now.Add(24*time.Hour).Unix())
		if e != nil {
			return nil, e
		}
		return uploadStatus(ctx, tx, owner, id, now)
	case "uploads/part":
		var r struct {
			Upload string `json:"upload"`
			Part   int    `json:"part"`
			Data   []byte `json:"data"`
			SHA256 string `json:"sha256"`
		}
		if identity.DecodeAttachmentChunk(raw, &r) != nil || !ID.MatchString(r.Upload) || r.Part < 0 || r.Part >= 100 || len(r.Data) == 0 || len(r.Data) > ChunkBytes || !digest.MatchString(r.SHA256) || Hash(r.Data) != r.SHA256 {
			return nil, ErrInvalid
		}
		u, e := permittedUpload(ctx, tx, owner, admin, r.Upload, now)
		if e != nil {
			return nil, e
		}
		if u.complete || u.linked {
			return nil, ErrConflict
		}
		expected := min(int64(ChunkBytes), u.Size-int64(r.Part)*ChunkBytes)
		if int64(len(r.Data)) != expected {
			return nil, ErrInvalid
		}
		var previous string
		e = tx.QueryRowContext(ctx, `SELECT sha256 FROM chat_chunks WHERE upload=$1 AND part=$2`, r.Upload, r.Part).Scan(&previous)
		if e == nil {
			if previous != r.SHA256 {
				return nil, ErrConflict
			}
			return map[string]bool{"ok": true}, nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO chat_chunks(upload,part,data,sha256) VALUES($1,$2,$3,$4)`, r.Upload, r.Part, r.Data, r.SHA256)
		return map[string]bool{"ok": true}, e
	case "uploads/status", "uploads/complete", "uploads/cancel":
		var r struct {
			Upload string `json:"upload"`
		}
		if identity.Decode(raw, &r, true) != nil || !ID.MatchString(r.Upload) {
			return nil, ErrInvalid
		}
		u, e := permittedUpload(ctx, tx, owner, admin, r.Upload, now)
		if e != nil {
			return nil, e
		}
		if action == "uploads/cancel" {
			if u.linked {
				return nil, ErrConflict
			}
			_, e = tx.ExecContext(ctx, `DELETE FROM chat_uploads WHERE id=$1`, r.Upload)
			return map[string]bool{"ok": true}, e
		}
		if action == "uploads/complete" && !u.complete {
			rows, e := tx.QueryContext(ctx, `SELECT part,data,sha256 FROM chat_chunks WHERE upload=$1 ORDER BY part`, r.Upload)
			if e != nil {
				return nil, e
			}
			h := sha256.New()
			var size int64
			part := 0
			valid := true
			for rows.Next() {
				var n int
				var data []byte
				var hash string
				if e = rows.Scan(&n, &data, &hash); e != nil {
					break
				}
				if n != part || hash != Hash(data) || part == 0 && !mediaType(u.MIME, data) {
					valid = false
				}
				part++
				size += int64(len(data))
				_, _ = h.Write(data)
			}
			if e == nil {
				e = rows.Err()
			}
			rows.Close()
			if e != nil {
				return nil, e
			}
			if !valid || size != u.Size || hex.EncodeToString(h.Sum(nil)) != u.SHA256 {
				return nil, ErrNotReady
			}
			if _, e = tx.ExecContext(ctx, `UPDATE chat_uploads SET complete=true WHERE id=$1`, r.Upload); e != nil {
				return nil, e
			}
		}
		return uploadStatus(ctx, tx, owner, r.Upload, now)
	case "download":
		var r struct {
			Attachment string `json:"attachment"`
			Part       int    `json:"part"`
		}
		if identity.Decode(raw, &r, true) != nil || !ID.MatchString(r.Attachment) || r.Part < 0 || r.Part >= 100 {
			return nil, ErrInvalid
		}
		var c string
		e = tx.QueryRowContext(ctx, `SELECT conversation FROM chat_uploads WHERE id=$1 AND complete AND message_id IS NOT NULL`, r.Attachment).Scan(&c)
		if errors.Is(e, sql.ErrNoRows) {
			return nil, ErrDenied
		}
		if e != nil {
			return nil, e
		}
		if _, e = access(ctx, tx, owner, admin, c); e != nil {
			return nil, e
		}
		var data []byte
		var hash string
		e = tx.QueryRowContext(ctx, `SELECT data,sha256 FROM chat_chunks WHERE upload=$1 AND part=$2`, r.Attachment, r.Part).Scan(&data, &hash)
		if errors.Is(e, sql.ErrNoRows) {
			return nil, ErrInvalid
		}
		return struct {
			Data   []byte `json:"data"`
			SHA256 string `json:"sha256"`
		}{data, hash}, e
	default:
		return nil, ErrInvalid
	}
}
func access(ctx context.Context, tx *sql.Tx, owner string, admin bool, id string) (int64, error) {
	if !ID.MatchString(id) {
		return 0, ErrInvalid
	}
	var actual string
	var next int64
	e := tx.QueryRowContext(ctx, `SELECT owner,next_seq FROM chat_conversations WHERE id=$1 FOR UPDATE`, id).Scan(&actual, &next)
	if errors.Is(e, sql.ErrNoRows) || e == nil && actual != owner && !admin {
		return 0, ErrDenied
	}
	return next, e
}
func message(ctx context.Context, tx *sql.Tx, id string) (Message, error) {
	var m Message
	e := tx.QueryRowContext(ctx, `SELECT id,conversation,sender,sender_role,client_id,sequence,text,created_at FROM chat_messages WHERE id=$1`, id).Scan(&m.ID, &m.Conversation, &m.Sender, &m.SenderRole, &m.ClientID, &m.Sequence, &m.Text, &m.CreatedAt)
	if e == nil {
		m.Attachments, e = attachments(ctx, tx, id)
	}
	return m, e
}
func attachments(ctx context.Context, tx *sql.Tx, id string) ([]Attachment, error) {
	rows, e := tx.QueryContext(ctx, `SELECT id,name,mime,size,sha256,kind FROM chat_uploads WHERE message_id=$1 ORDER BY id`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Attachment{}
	for rows.Next() {
		var a Attachment
		if e = rows.Scan(&a.ID, &a.Name, &a.MIME, &a.Size, &a.SHA256, &a.Kind); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type upload struct {
	Attachment
	complete, linked bool
}

func permittedUpload(ctx context.Context, tx *sql.Tx, owner string, admin bool, id string, now time.Time) (upload, error) {
	var c string
	e := tx.QueryRowContext(ctx, `SELECT conversation FROM chat_uploads WHERE id=$1`, id).Scan(&c)
	if errors.Is(e, sql.ErrNoRows) {
		return upload{}, ErrDenied
	}
	if e != nil {
		return upload{}, e
	}
	if _, e = access(ctx, tx, owner, admin, c); e != nil {
		return upload{}, e
	}
	return ownedUpload(ctx, tx, owner, id, now)
}
func ownedUpload(ctx context.Context, tx *sql.Tx, owner, id string, now time.Time) (upload, error) {
	var u upload
	var sender string
	var expires int64
	e := tx.QueryRowContext(ctx, `SELECT id,name,mime,size,sha256,kind,sender,expires_at,complete,message_id IS NOT NULL FROM chat_uploads WHERE id=$1 FOR UPDATE`, id).Scan(&u.ID, &u.Name, &u.MIME, &u.Size, &u.SHA256, &u.Kind, &sender, &expires, &u.complete, &u.linked)
	if errors.Is(e, sql.ErrNoRows) || e == nil && (sender != owner || expires <= now.Unix() && !u.linked) {
		return u, ErrDenied
	}
	return u, e
}
func uploadStatus(ctx context.Context, tx *sql.Tx, owner, id string, now time.Time) (any, error) {
	u, e := ownedUpload(ctx, tx, owner, id, now)
	if e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT part FROM chat_chunks WHERE upload=$1 ORDER BY part`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	parts := []int{}
	for rows.Next() {
		var p int
		if e = rows.Scan(&p); e != nil {
			return nil, e
		}
		parts = append(parts, p)
	}
	return struct {
		Attachment Attachment `json:"attachment"`
		Complete   bool       `json:"complete"`
		Parts      []int      `json:"parts"`
	}{u.Attachment, u.complete, parts}, rows.Err()
}
func mediaType(mime string, b []byte) bool {
	switch mime {
	case "image/jpeg":
		return len(b) >= 3 && bytes.Equal(b[:3], []byte{255, 216, 255})
	case "image/png":
		return bytes.HasPrefix(b, []byte{137, 80, 78, 71, 13, 10, 26, 10})
	case "image/webp":
		return len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP"
	case "video/mp4":
		return len(b) >= 12 && string(b[4:8]) == "ftyp"
	case "application/pdf":
		return bytes.HasPrefix(b, []byte("%PDF-"))
	case "application/zip":
		return bytes.HasPrefix(b, []byte{'P', 'K', 3, 4}) || bytes.HasPrefix(b, []byte{'P', 'K', 5, 6})
	case "text/plain":
		return !bytes.ContainsRune(b, 0) && !strings.HasPrefix(strings.TrimSpace(strings.ToLower(string(b[:min(len(b), 512)]))), "<html")
	case "application/octet-stream":
		return true
	default:
		return false
	}
}
