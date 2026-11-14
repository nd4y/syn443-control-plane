# Authorized device discovery

The console loads `configuration.devices.list` after sign-in and provides an
explicit refresh and next-page action. Clicking a device opens the existing
configuration card without copying an identifier. Manual lookup remains available
when discovery is unavailable. No mutation, policy publication or VPN connection
is triggered by listing or selecting a device.

The action accepts only an optional `after` device identifier. Each page contains
at most 32 devices in bytewise identifier order and an exclusive cursor. There
is no global device count. The ordinary, separate control audience and DPoP
verification remain mandatory. Metadata reads do not require another MFA prompt.
Every returned device must be active and approved, belong to an enabled,
unexpired account and have a live `configuration.drafts.read` device grant for
the actor, using the same explicit/wildcard ACL semantics as the existing card.
Discovery does not grant access to any configuration body or inherited layer.

Only the identifier, desired and issued revision, and bounded activation receipt
metadata are returned. The UI distinguishes an unissued policy, an awaited
receipt, a receipt for the issued policy and a historical receipt. A receipt is
never represented as proof of current online connectivity. Report timestamps
refer to server receipt time. The endpoint omits owners, keys, addresses,
configuration bodies, tokens and provider credentials.

The SQL transaction locks the selected grant, device and account rows and checks
monotonic authority and account/grant expiry after any lock wait. It has a five
second context deadline. The read is audited before commit. Missing audit
authority fails closed. No schema or runtime-role expansion is required.

The browser validates the complete closed page before rendering. Unexpected
members, duplicate/unsorted identifiers, oversized pages, incorrect cursors and
unsafe revisions discard the page. Session expiry, role withdrawal and logout
erase the entire list and current card; errors never retain a stale list.
Device metadata stays in tab memory. The PatternFly table uses a keyboard
accessible scroll region on narrow screens.

GitHub Actions must run the schema and BFF allowlist checks, actual PostgreSQL
ACL/isolation/pagination/report/audit/expiry-under-lock cases, and four mandatory
Chromium discovery scenarios. Current acceptance is pending that exact build.
This contributes to web administration. Friendly names, user management, native
administrative screens, current online heartbeats and the full M2/M3 milestone
remain separate requirements.
