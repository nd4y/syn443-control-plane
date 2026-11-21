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
`chatWebAudience`, with an optional `chatWebIssuer`. Omit all web fields when
only Android is enabled. The optional issuer pins a separate administrator realm;
when absent the existing enrollment issuer is used. Each deployment accepts one
pinned web issuer, its separate client/audience and a live SQL grant keyed by both
issuer and subject. A same-named device account or a device session grants no web
authority. Only the explicit fixture flag allows loopback HTTP. Issuer discovery
and JWKS use the same pinned provider and bounded cache as device authentication;
there is no fallback to another realm after a failed token.
`enrollment-admin chat-cleanup` drains expired orphan uploads in committed
batches of up to 128. One invocation uses one expiry cutoff. It skips rows
locked by a sender and checks eligibility again before deletion. Linked
attachment chunks remain available for download. A command that reaches its
deadline reports an error and can be retried. The next invocation also
reconsiders previously locked rows.

The console BFF may explicitly set `chatApiOrigin` when the control and chat APIs
have different HTTPS origins. Chat DPoP proofs bind the exact chat origin, while
control proofs keep their original target. Nonces are cached separately, so
alternating chat/control calls neither borrow a nonce nor cause repeated
challenges. In console mode chat forwarding stays disabled unless this origin
is configured. It grants no administrator authority. The PatternFly console adds
a support workspace with its own conversation list, text/file controls, explicit
retry and an empty state. It shares the standalone transfer controller; upload
identities, chunk hashes, final download verification and immutable send retries
are preserved. Workspace hiding cancels owned requests and polling; logout clears
the chat state and revokes prepared download URLs. Failure polling backs off to
60/120/240/300 seconds, with one owned attempt and a manual refresh floor.
Exact-head browser and live acceptance remain separate gates.

An owner can provision an account used only for web support through
`enrollment-admin chat-web-admin`, using the owner-only
`SYN443_CHAT_WEB_ADMIN_GRANT` file. It contains the pinned `issuer`, `subject`,
explicit `enabled`, a future `until` no more than30 days away, and
`expectedGrantHash` (empty for creation). The command returns `grantHash`; a
changed grant must name the previous hash. Repeating an already committed grant
is idempotent. A stale grant cannot restore withdrawn authority or overwrite an
existing VPN account. Account, chat role and owner audit commit atomically.
The new account has `device_limit=0`; real enrollment is denied even with a valid
OIDC token. Normal device grants still require1..16. Run the owner-only migration
before using this command on an older installation. Runtime roles cannot create
these accounts, enable administrator roles or edit their audit. Existing VPN
accounts can instead receive the separate explicit `chat-admin` role, retaining
their device limit and entitlements. No live grant is enabled by source changes.

The separate frontend/BFF executable reads an owner-only config from
`SYN443_CHAT_WEB_CONFIG`, with `listen`, `origin`, `apiOrigin`, `issuer`, `clientId`,
`audience`, `certificate`, `certificateKey`, and `fixtureHttp`, with optional
`chatApiOrigin` for the console. Production origins
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

Configuration and signed-token tests cover both the default and explicit web
issuer, fixture-only HTTP, unsafe/partial/duplicate fields, foreign signatures,
issuer/client/audience rejection and bounded discovery. A PostgreSQL HTTP case
checks that equal subjects across two issuers cannot share administrator rights,
and that withdrawal leaves the ordinary device conversation intact.

SQL tests cover account/device ownership, live administrator withdrawal including
pending uploads, concurrent idempotent sends/replay, a complete 25 MiB transfer,
quotas/expiry/MIME/hash and separate web authority. HTTP tests cover browser-bound
OAuth callbacks, proof binding, refresh, nonce, session expiry/logout, CSRF,
request bounds and capacity. Independent chat SQL and authenticated HTTP coverage
gates are part of the existing enrollment Actions job.

Actions checks include real PostgreSQL process/role tests over HTTP and pinned
HTTPS, real temporary Keycloak web-client conformance, and five browser cases.
Browser cases validate actual 25 MiB download bytes, upload bounds, role withdrawal
and clearing an authorized save link on logout. A verified Blob link is explicit
and expires after 120 seconds. Physical Edge download persistence is not confirmed
by the automation tool; Android SAF download was checked against the source hash.

The inbox shows 50 conversations per page. The next page uses the last
conversation's update time and ID, including when several updates share a
timestamp. Administrators can return to the first page from any depth.
The conversation view follows new arrivals while keeping up to 200 messages.
Its history controls navigate older and newer pages of 20 and can jump back
to the newest messages. Polling an archived page retains the current position
and leaves the read cursor alone. These controls are available in both web views.

Selecting another conversation clears the previous history and revokes its
prepared file link before the first request for the new conversation. This
also applies when the new history is slow or unavailable. Leaving the support
view during file verification invalidates the pending save link.

A disposable deployment of the Actions binaries preserved SQL history and file
bytes across runtime replacement. Private USB Xperia checks exercised ordinary
user and administrator replies, live role withdrawal, complete 25 MiB files and
actual H264/AAC 720p video produced on the phone. Only synthetic test content was
used; device data and raw logs are not public artifacts.

This is a draft implementation. Permanent production deployment, the full
retention editor and the complete control-panel milestone remain separate. LTE,
natural Doze, unplugged energy and long endurance are not accepted by these tests.
