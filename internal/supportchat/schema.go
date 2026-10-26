package supportchat

import _ "embed"

// Schema is applied by the migration owner; the API cannot migrate or grant roles.
//
//go:embed schema.sql
var Schema string

const Roles = `
GRANT SELECT,INSERT,UPDATE,DELETE ON chat_conversations,chat_messages,chat_uploads,chat_chunks,chat_read_cursors TO syn443_identity_api;
GRANT SELECT,UPDATE(lock_guard) ON chat_admins TO syn443_identity_api;
`
