# SQL support chat

The device API now supports one conversation per enrolled user account. A live
owner-issued SQL grant enables an administrator to read the inbox and reply from
Android or the separate `support-chat-web` frontend service. Device registration
alone never grants this role. Every content request checks current account,
device/session or web token, DPoP and conversation authority in a transaction.

PostgreSQL holds conversations, messages, read cursors, upload reservations and
all attachment bytes. No public object URL or external file store is used.
Messages allow 4,096 Unicode code points / 16,384 UTF-8 bytes and four attachments.
Each file is at most 25 MiB (26,214,400 bytes), split into 256 KiB SQL bytea parts.
The API validates part and whole-file SHA-256, MIME signatures, quotas, immutable
client IDs and publication atomicity. Expired unlinked uploads are deleted after
24 hours by the bounded owner cleanup command. The full retention editor is not
implemented. SQL backup/access controls must cover chat BLOBs as sensitive data.

`contracts/v1/chat-openapi.json` defines device and administrator routes. The
device routes use existing DPoP-bound device sessions. Administrator routes use
a separate Keycloak client/audience plus `chat_admins.enabled`; API runtime roles
cannot create or enable their own administrative grants. Publisher roles cannot
read chat data. An existing account can be granted/revoked by the database owner
with `enrollment-admin chat-admin` and an owner-only JSON grant file supplied in
`SYN443_CHAT_ADMIN_GRANT` (`issuer`, `subject`, `enabled`). Never put that file in
source control. Run existing schema migration before enabling chat.

Enrollment config adds `chatEnabled`, `chatWebOrigin`, `chatWebClientId` and
`chatWebAudience`. Omit all three web fields when only Android is enabled.
`enrollment-admin chat-cleanup` removes at most 128 expired orphan uploads per
invocation. Scheduling and production rollout are operator actions.

The separate frontend/BFF executable reads an owner-only config from
`SYN443_CHAT_WEB_CONFIG`, with `listen`, `origin`, `apiOrigin`, `issuer`, `clientId`,
`audience`, `certificate`, `certificateKey`, and `fixtureHttp`. Production origins
must be HTTPS; the listener is loopback-bound, with normal certificate validation
for outbound requests. The explicit fixture flag permits loopback HTTP only.
Example public placeholders (certificate paths must be supplied at deployment):

```json
{"listen":"127.0.0.1:17849","origin":"https://support.example.invalid","apiOrigin":"https://api.example.invalid","issuer":"https://id.example.invalid/realms/syn443-test","clientId":"syn443-support-web","audience":"syn443-support-api","certificate":"/run/tls/cert.pem","certificateKey":"/run/tls/key.pem","fixtureHttp":false}
```

Register exactly `https://support.example.invalid/callback` in the separate
Keycloak public client, with S256 PKCE, DPoP-bound access tokens, a maximum
600-second access-token lifetime and the dedicated API audience mapper. No
wildcard redirect or password grant is required. OAuth code exchange verifies the
signed access-token identity against issuer, audience, client and proof key; an
unverified ID token is never used. The frontend holds tokens/keys only in bounded
one-hour RAM sessions (32 sessions and 32 pending logins). Restart requires login
again and does not lose SQL history. Browser JavaScript receives no OAuth tokens.
Cookies use HttpOnly, Secure, host-only scope and SameSite=Lax. State/cookie and
PKCE bind the callback; all browser mutations require the exact Origin and CSRF
header. CSP prevents inline scripts, frames and external connections.

SQL tests cover account/device ownership, live administrator withdrawal including
pending uploads, concurrent idempotent sends/replay, a complete 25 MiB transfer,
quotas/expiry/MIME/hash and separate web authority. HTTP tests cover browser-bound
OAuth callbacks, proof binding, refresh, nonce, session expiry/logout, CSRF,
request bounds and capacity. Independent chat SQL and authenticated HTTP coverage
gates are part of the existing enrollment Actions job.

This is a draft implementation. Browser E2E, Android/web exchange, actual video
compression and physical acceptance are still being completed. It is not a
production deployment or completion of the full control-panel milestone.
