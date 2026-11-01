CREATE TABLE IF NOT EXISTS chat_conversations (
 id text PRIMARY KEY CHECK(id ~ '^[0-9a-f]{32}$'),
 owner text NOT NULL UNIQUE REFERENCES identity_accounts(owner),
 next_seq bigint NOT NULL DEFAULT 1 CHECK(next_seq>=1), updated_at bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
 id text PRIMARY KEY CHECK(id ~ '^[0-9a-f]{32}$'),
 conversation text NOT NULL REFERENCES chat_conversations(id),
 sender text NOT NULL REFERENCES identity_accounts(owner),
 sender_role text NOT NULL CHECK(sender_role IN ('user','admin')),
 client_id text NOT NULL CHECK(client_id ~ '^[0-9a-f]{32}$'),
 body_hash text NOT NULL CHECK(body_hash ~ '^[0-9a-f]{64}$'),
 sequence bigint NOT NULL CHECK(sequence>=1),
 text text NOT NULL CHECK(octet_length(text)<=16384 AND char_length(text)<=4096),
 created_at bigint NOT NULL, UNIQUE(conversation,sequence), UNIQUE(sender,client_id)
);
CREATE TABLE IF NOT EXISTS chat_uploads (
 id text PRIMARY KEY CHECK(id ~ '^[0-9a-f]{32}$'),
 conversation text NOT NULL REFERENCES chat_conversations(id), sender text NOT NULL REFERENCES identity_accounts(owner),
 client_id text NOT NULL CHECK(client_id ~ '^[0-9a-f]{32}$'),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 255 AND char_length(name)<=160),
 mime text NOT NULL CHECK(mime IN ('application/octet-stream','application/pdf','application/zip','text/plain','image/jpeg','image/png','image/webp','video/mp4')),
 kind text NOT NULL CHECK(kind IN ('file','photo','video')),
 size bigint NOT NULL CHECK(size BETWEEN 1 AND 26214400), sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 created_at bigint NOT NULL, expires_at bigint NOT NULL, complete boolean NOT NULL DEFAULT false,
 message_id text REFERENCES chat_messages(id) ON DELETE CASCADE, UNIQUE(sender,client_id)
);
CREATE TABLE IF NOT EXISTS chat_chunks (
 upload text NOT NULL REFERENCES chat_uploads(id) ON DELETE CASCADE,
 part integer NOT NULL CHECK(part BETWEEN 0 AND 99),
 data bytea NOT NULL CHECK(octet_length(data) BETWEEN 1 AND 262144),
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'), PRIMARY KEY(upload,part)
);
CREATE TABLE IF NOT EXISTS chat_read_cursors (
 conversation text NOT NULL REFERENCES chat_conversations(id), reader text NOT NULL REFERENCES identity_accounts(owner),
 last_seq bigint NOT NULL CHECK(last_seq>=0), PRIMARY KEY(conversation,reader)
);
CREATE TABLE IF NOT EXISTS chat_admins (
 owner text PRIMARY KEY REFERENCES identity_accounts(owner), enabled boolean NOT NULL,
 lock_guard integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS chat_inbox ON chat_conversations(updated_at DESC,id);
CREATE INDEX IF NOT EXISTS chat_upload_expiry ON chat_uploads(expires_at) WHERE message_id IS NULL;
CREATE INDEX IF NOT EXISTS chat_upload_sender ON chat_uploads(sender);
CREATE INDEX IF NOT EXISTS chat_attachments ON chat_uploads(message_id);
