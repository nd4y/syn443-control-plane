# Durable managed-overlay broker (runtime integration in progress)

`internal/enrollment/broker.go` adds a publisher-reserved SQL journal and a
separately restricted `syn443_overlay_worker` role. It is not enabled by the
existing enrollment runtime configuration. No live NetBird account is changed by tests.
M2/M3 remain incomplete until resource/policy/scheduler/API/UI/device integration
and the complete acceptance contract pass.

The SQL broker, role isolation, independently addressed wrapping and opt-in API
pending/withdrawal paths passed all eight mandatory jobs at
`8bcde91e02f2351283209a8084ea9a8dbaef7908`,
[Actions41472655185](https://github.com/nd4y/syn443-control-plane/actions/runs/41472655185),
including the separate80% broker coverage gate. This is component acceptance;
the newer worker bootstrap and complete resource/policy/UI wiring remain pending.

The publisher locks the actual SQL account/device, derives the owner tag and
checks an independent approval/resource fence before reserving an immutable
device/key/namespace/resource/account/group/reference/version/deadline scope.
Scopes and returned setup material use distinct authenticated encryption AADs.
Duplicate reservations keep the original opaque operation; changed input conflicts.
At most16 unfinished records are admitted per device. The API cannot reserve,
read a provider secret, mark work complete or grant publication authority.

The provider worker cannot read identity devices/sessions, insert requests, change
scope/retirement intent or sign policy. It claims a45-second SQL lease with
`SKIP LOCKED`, resolves the pinned resource/account and commits `dispatched` before
issuing exactly one POST. A resource outage before dispatch retains retry authority.
A process crash or lost POST reply only permits exact-operation reconciliation;
missing/multiple matches never mean create again. Unresolved creation becomes
blocked after26 hours. Late replies cannot overwrite an expired/replaced lease
and do not independently revoke another worker's current provider key.

Credential cleanup and peer retirement are separate. At the short SYN443
deadline or confirmed use, the worker disables the one-off provider key, retaining
its usage counter. It commits unused or registered evidence before deleting the
provider key record, so a lost DELETE reply remains safely retryable. Used keys
require an account/resource-bound `peer.setupkey.add` receipt and current peer
creation identity; missing evidence blocks cleanup rather than guessing a peer.
The authenticated encrypted receipt is immutable once recorded. Established peer
retirement uses that receipt after audit retention, rechecking account and current
creation time before deletion. Expiring an enrollment key never retires the peer.

The independent publisher wraps issued values into addressed ES256 credentials
only after verifying the current signed policy, actual live account/device/JKT,
original grant and exact namespace/reference/epoch plus initial/final approval
fences. It preserves the original credential deadline. SQL ready state cannot
replace policy/signature/approval authority. A short polling loop must be wired
independently of the long policy refresh interval.

SQL tests use a real disposable PostgreSQL with owner/API/publisher/provider-worker
roles, covering dispatch commit before HTTP, response loss, crash before HTTP,
expiry, ownership, duplicate/conflicting reservations, quota, resource outage,
late lease callbacks, independent addressed installation, retained peer mapping
and retirement after audit retention. The broker has a separate required80%
coverage gate. Compiled tests run only in GitHub Actions.

Still required: accepted configured resource resolver/worker binary, approved portable
overlay materialization, independently scheduled
wrapping/retirement, bounded inventory/retention and controlled safe renewal.
Actual Cloud, root/capability upgrades, complete web/native administration and
final restored USB Xperia Wi-Fi acceptance remain open. LTE is not tested.

The new opt-in API path recognizes pending metadata only after current signed
policy and session validation. Absent/foreign/unconfigured grants remain denied;
owned live pending grants return202 with a2-second retry hint. An owned expired,
retired or otherwise unavailable enrollment value returns a credential conflict,
preserving the separately valid base policy. No pending response creates delivery
or consumption evidence. API column privileges omit encrypted scopes, provider
IDs/values and peer receipts. Actual account/device withdrawal is propagated by
the publisher to immutable retirement intent; changing an ordinary config hash
alone does not retire an established peer. Runtime scheduling/configuration and
acceptance of these new paths remain pending.

## Isolated provider process (acceptance pending)

`overlay-worker` reads the0600 owner file named by
`SYN443_OVERLAY_BROKER_CONFIG`: database/encryption key and at most16 pinned
resource revisions with API origin, account, management origin, logical network,
approved groups, root CA/network grants and management token. This is private
server bootstrap input; it is never a device body or a public sample containing
real values. Archived revisions must remain available until cleanup completes.
The SQL catalog-backed resource editor/rotation/retention remains required.

The resolver checks exact resource/revision/account/network/management origin and
group subset before constructing a normal TLS-validated adapter. It copies the
owner input, refuses redirects/environmental proxies through the adapter and
closes each admitted client. Its diagnostics redact the entire configuration.
The worker uses its own monotonic SQL scheduling clock, a40-second operation
deadline and a2-second polling interval; it cannot modify the identity clock.
SIGTERM cancels current work without forgetting durable dispatch. Actions builds
and scans the executable with the other runtime artifacts and a checksum manifest.
TLS resolver, malformed bootstrap, wrong scope and SQL-clock tests plus a separate
80% bootstrap coverage gate are required before accepting this new process.

The isolated worker passed all eight mandatory jobs at
`80a982dd628adabea519b4d050c8b2a9aebebbe7`,
[Actions41476009154](https://github.com/nd4y/syn443-control-plane/actions/runs/41476009154).

## Automatic reference materialization (acceptance pending)

The independent publisher can opt in using `overlayBrokerEnabled`, a service ID
and the0600 metadata file `SYN443_OVERLAY_POLICY_RESOURCES`. This file contains
resource/revision/account/management origin/network/group metadata, with no PAT;
unknown token fields are rejected. Each owner-authorized grant also explicitly
lists `overlayGroups` per resource. An app configuration referencing a resource
does not itself grant that resource or broaden the allowed auto-groups.

`BrokerPolicies` replaces caller setup-reference/version fields with a persisted
per-namespace head. Head identity is immutable; the reference can advance only
one version at a time. Policy signature, head CAS and broker reservation commit
in the same account/device-fenced transaction. Failed publication must not leave
a head or provider request. Ordinary refresh keeps the same reference and cannot
extend the original setup deadline. Only a confirmed unused/cleared key after its
deadline permits a new reference; registered and uncertain results preserve the
head. Per-identity auto-group changes are rejected rather than silently reenrolling.

The publisher's2-second loop independently schedules safe renewal, propagates
withdrawal and wraps ready addressed values. It does not wait for the long policy
refresh interval and has no management PAT. The API recognizes reserved pending
metadata only when explicitly enabled; default behavior remains unchanged.
Plain authorized devices do not require overlay capability or allocate a head.

The new source/SQL tests and an independent80% materializer coverage gate are
pending Actions acceptance. This bootstrap integration does not implement the
SQL resource editor, independent preview/MFA approval, portable overlay/layer UI,
obsolete namespace retirement after rollback leases, actual Cloud or final Xperia
acceptance. Those remain required by the full M2/M3 contract.

The initial materializer run compiled and passed its Go/SQL behavior checks at
`fc599079f797c90f3472c9a627508e96d2815cbe`, but
[Actions41483101909](https://github.com/nd4y/syn443-control-plane/actions/runs/41483101909)
failed its79% materializer coverage against the required80%. It is not accepted.
Additional malformed document/capability cases retain that gate and reject empty
or oversized outbound lists before reservation. A new disposable process fixture
also runs separate actual API, publisher and provider-worker executables with
independent SQL roles and TLS management service: pending grant, exactly one POST,
short-poll addressed delivery and no secret in process diagnostics. This is an
isolated provider fixture; it does not prove live Cloud registration or SDK traffic.

At`c61ed670db03400662fa4520ab0e9b07c3464c1e` the actual three-process fixture
passed, but the complete run failed a new positive materializer fixture that
omitted its activation gate. The next source keeps production validation intact
and supplies the complete test policy. That run remains unaccepted.

## Obsolete namespace and rollback lease (acceptance pending)

Each reference head tracks the maximum offline permit ever signed for that
namespace. Ordinary publication extends this bound without rotating its reference.
A new committed configuration that omits the namespace marks it obsolete, while
the peer remains available for a permitted previous-config rollback. Readding
that same namespace before retirement cancels obsolescence and extends its permit.
The publisher schedules owned provider retirement only after an obsolete head's
last permit expires. A still-assigned namespace is not retired merely because
policy refresh is temporarily unavailable. Actual device/account withdrawal
continues through the separate immediate cleanup intent.

Retired heads cannot return to active state under the same identity epoch. A new
explicit identity epoch is required; a routine refresh cannot silently reenroll a
known revoked peer. SQL guards prevent decreasing the last permit or clearing
retired state. Tests exercise a refreshed rollback lease, removal, the final
permitted millisecond, retirement and denial of implicit reactivation. The new
lease columns/fence/scheduler behavior awaits mandatory Actions acceptance.

The automatic materializer, actual three-process delivery and rollback-lease
retirement passed all eight mandatory jobs at
`d556a41cc7eb6f39b9272b2ef39d6f7e859c16ee`,
[Actions41487142571](https://github.com/nd4y/syn443-control-plane/actions/runs/41487142571).
This accepts isolated source/SQL/process behavior, not live Cloud or full M2/M3.
The new startup guards additionally reject an API role with setup-secret read
rights or a provider-worker role with reference-head mutation rights. Their new
real-SQL privilege-contamination test awaits the next Actions run.

## Credential-only withdrawal (acceptance pending)

A changed live owner grant now monotonically withdraws pending setup authority
without retiring an established peer. The publisher records a separate SQL flag;
the API cannot change it and the provider worker cannot reset it. A queued job
never dispatches after withdrawal. A late creation callback cannot retain or
deliver its setup value, including an already wrapped addressed copy. Cleanup
disables the key before checking its monotonic use count. If registration raced
withdrawal, ownership evidence is retained and the peer survives. Missing audit
evidence blocks destructive cleanup. Erasure acknowledgements remain possible.

Only a durable confirmed-unused cleared result permits a new reference, including
when withdrawal happened before the original short deadline. Permission refresh
and credential cleanup do not authorize peer deletion or silent re-enrollment of
a known registered identity. Actual account/device withdrawal and expired obsolete
namespace retirement remain separate. Actions add queued, late callback, wrapped
fetch/erasure, live-grant change, registration race, missing ownership and SQL-role
checks. Live Cloud and final physical acceptance remain open.
