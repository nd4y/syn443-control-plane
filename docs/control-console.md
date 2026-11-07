# Control console - source metadata and private drafts

## Android navigation

After applying the catalog schema and roles, set `controlPanelDiscovery` in the
enrollment API configuration to enable `GET /v1/device/control-panel`. The
signed bootstrap must also contain the trusted control panel HTTPS origin.
Grant `control.open` on `control/panel` to the intended owner identity. That
grant enables navigation only. Keep action-specific ACLs and the separate
Keycloak control audience for the actual browser session and requests.

The endpoint requires a live device session and its DPoP key, and returns only
an expiry capped at two minutes, the account/session deadline and the grant.
An owner without the grant receives zero. The enrollment role can execute
the expiry lookup but cannot read or edit the catalog ACL table.

## Source management extension (acceptance pending)

The new source form creates/edits server/manual/Remnawave source definitions with
expected revision, immutable owner/ID for existing records, expiry, refresh/stale
limits and supported network modes. Secret handling is explicit keep/replace/
delete. Replace accepts only a newly entered bounded JSON document; get/list do
not return the previous secret, and a successful save clears new secret text.
Literal replacement JSON retains duplicate members for server-side rejection.
The existing SQL ACL, freshness/MFA and secret validation remain authoritative.

The fixed-path control BFF admits scoped `source.put`, `source.sync`,
`job.get` and `job.list`. Support-chat sessions cannot reach control actions.
Refresh queues a SQL job and the
screen reads its state. Unacknowledged mutations retry the identical body/request
identity; fields stay locked until the result or a fresh server read is chosen.
Permission/session withdrawal and logout erase both draft and new source-secret
memory. The console keeps the temporary edit in the current tab. Device fetch
and full resource/user/group administration remain unfinished.

For a saved manual source, the console submits a file up to 10 MiB to
`/control/source/import`. That BFF endpoint accepts only `source.import` and
forwards the original proof-bound request to the existing source job API.
It admits one import at a time under the standard session and CSRF checks.
Allow the base64 envelope up to 14 MiB plus 64 KiB at the ingress for this path.
Other control requests retain their ordinary limit. The source worker parses
the file, applies normal quarantine and erases raw input on terminal outcomes.
The file selector clears after the body is prepared. An uncertain reply keeps
the same pending operation in tab memory for an explicit retry.

The source recipient editor uses the selected source revision and the loaded
share revision. It shows an editable list of user, device or group identifiers,
requires confirmation and retries the exact operation if a reply is lost.
The control API independently verifies fresh MFA, source share and recipient
receive rights. Source recipient changes are separate from publishing device
policies. The signer still requires verified membership before using group
grants. The page clears the list on source change or session withdrawal.

Three new required browser cases cover save/read-without-secrets/sync job,
lost-acknowledgment idempotency and denial erasure. The browser gate now requires
all twelve named outcomes with no skips; compiled/browser acceptance is pending
the next Actions run. This does not close the full administrative milestone.

This is the initial administrative web interface. It lists authorized source and
profile metadata and opens/saves an administrator's actor-private network drafts.
The default target kind is device. Template/group/user targets are explicit;
changing an existing draft's scope requires a new draft. Source credentials are
not returned or rendered. The editor sends portable source/profile references,
DNS/routing and activation plans; the server applies the same closed schema and
SQL object ACL as direct control API calls. Saving never publishes a policy.

Run the existing `support-chat-web` BFF as a **separate process**, with its private
`SYN443_CHAT_WEB_CONFIG` setting `controlConsole: true`. Configure its API origin
to the control API, its own Keycloak client and the pinned control API audience.
The authorization request asks for `openid syn443.control`; configure that client
and scope in the isolated/production realm deliberately. Use its own trusted
HTTPS origin/certificate and exact `/callback` redirect URI. Keep configuration,
provider URLs, audience-specific access and refresh tokens outside this repository.
No source or signing secrets are required by the BFF.

Control mode uses a separate HttpOnly/Secure/SameSite cookie and refuses support
chat routes. Support mode cannot proxy control actions. The BFF validates the
closed outer envelope and fixed implemented-action allowlist, signs the original
body for the one control URI with its session's DPoP key and handles bounded nonce
retry/refresh. Control scope is verified at login and refresh; live SQL permissions
are still checked by the control API on every operation. Browser code never gets
tokens or a private key. CSRF/origin checks, restrictive CSP and no-store/no-referrer
remain in effect. There is no arbitrary URL/action forwarding.

The dark layout supports narrow phone screens. UI data uses text nodes, no HTML
injection. Drafts live in tab memory until saved; there is no localStorage,
sessionStorage, telemetry or browser console logging of configuration. Lost save
replies retain exactly the same request ID/body for an explicit retry. A known
invalid request lets the administrator edit again. Conflict/readback never silently
resubmits a different edit under that operation. Logout or access/session denial
clears the visible configuration and pending body.

Actions runs Go OAuth/DPoP/cookie/scope/path/CSRF/size/nonce checks, existing actual
SQL draft tests, and Chromium source metadata/XSS, draft save/readback, lost reply,
invalid plan, role withdrawal/logout/expiry and phone-width/dark-theme cases.
All nine existing and new browser cases must appear and pass without skips.
The initial console passed all eight mandatory jobs at10da9cb6d384c641fea514de199ed9457cee6f5a, [Actions41447469608](https://github.com/nd4y/syn443-control-plane/actions/runs/41447469608), including all nine required browser outcomes without skips.

Independent signed preview/approval/publication, assignments and users/groups,
source/resource mutations, three-way conflict editing, full application settings,
native administrator access and real Keycloak/browser acceptance remain required
M2/M3 work. The support chat remains a separate supported interface. This console
does not label saved drafts or synthetic browser tests as an accepted publication.
