# Control catalog service

The `control-api` and `source-worker` executables use separate restricted SQL
roles and owner-protected configuration files. Neither receives a signing key,
device-session grants, schema ownership or permission to create administrative
ACL. Run owner migrations/initial grants separately. The source worker only
loads and normalizes data; a successful source job is not a policy publication.

The control audience is `syn443-control-api`, with the explicitly pinned
`syn443-control-web` and/or `syn443-control-mobile` public clients. Device/chat
tokens cannot substitute for it. The API requires signed scope `syn443.control`,
key/token/body/origin-bound DPoP, a durable unique proof identifier and live SQL
object authority. Initial ACL actor IDs are the SHA256/base64url identity hash of
`issuer + NUL + subject`; display names/email/provider user IDs are not identity.
Sensitive mutations additionally require a signed, pinned IdP ACR plus OTP or
security-key AMR and authentication within ten minutes. Token refresh alone does
not extend that assurance window. IdP configuration must actually issue these
claims after strong authentication; the client cannot assert them.

The [closed API contract](../contracts/v1/control-openapi.json) defines supported
catalog actions. Unknown/missing/case-variant members, URL queries, cross-origin
browser requests, replayed proofs and stale revisions are rejected. Lost replies
retry the same operation ID and body with a new proof. Inventory exposes IDs,
names, types, quota/expiry and state, never outbound credentials. Source import
has a separate10MiB decoded budget; ordinary identity/admin DTO limits stay small.

The source worker has40 seconds per claimed job inside its60-second lease,
bounded HTTP time/size/redirect/DNS egress and no provider writes. Resource/source
revision, active head, lease and cancellation are rechecked at commit. HTTP
authentication failures preserve only the existing bounded valid snapshot;
explicit upstream user revocation/expiry removes eligibility.
The durable access denial is separate from refresh state: rename, credential
rotation or a later network/authentication failure cannot revive a revoked cache.

Conditional HTTP validators are encrypted for the active snapshot and source
revision. A quarantined candidate cannot attach its validators to the previous
working snapshot. Manual promotion and legacy validators force one full fetch.

The optional version 2 device endpoints carry the active validators in a lease.
The device signs a bounded binary result containing status, allowed metadata and
the provider body only on success. The worker accepts 304 only against the
leased working snapshot and updates quota without transferring profiles again.
Provider error responses carry a status only. The original endpoints still
accept and return the previous wire format.

A portable network plan can set `network.routeChecks` with a separate list of
TCP, TLS, HTTPS 204 or SSH banner checks for each configured outbound. Up to
16 outbounds and four checks per outbound are accepted. Invalid or unsupported
targets and incompatible paths are rejected in preview. Required checks
participate in activation on a client advertising `route.health.v1`. The
publisher rejects plans with these checks for clients that lack that capability.

The opt-in `network.routeFailover` pilot applies to one named internal
destination rule on Wi-Fi. It requires a noninterrupting selector with
two to eight concrete proxy paths and identical signed probes for the
selector and its members. The selector cannot also be the default route,
a detour for another outbound, or a DNS path. It is only issued to a
client advertising `route.failover.v1`.
Only a newly accepted verified snapshot can restore it. Cache TTL/provider expiry
remain visible even when the most recent refresh failed. Source recipient
changes require both share and receive authority; device-fetched data is personal.
Large removals are quarantined until an exact hash/head/revision-bound decision.
Review cannot approve expired/quota-exhausted access or dangling profile references.

Device fetch sources carry an immutable `fetchDeviceId` in addition to the owner.
The API requires scope over both objects when saving the source. The compiler
rejects every other device, including another device of the same owner. Binding
an older unaddressed source drops its active snapshot pointer.

The SQL catalog can lease one pending fetch to the addressed device and accept
its bounded, encrypted input. The regular worker starts normalization only after
upload. The lease, source revision and snapshot head fence expired work and
lost responses. The device API accepts proof-bound claim and result requests
only from a live session for that owner and device. Enable `deviceFetchEnabled`
on the catalog API and worker and configure `SYN443_DEVICE_FETCH_KEY_FILE` on
enrollment API with the owner-only catalog encryption key file. It is distinct
from the identity encryption key. Apply the scoped view grants before enabling.

This runtime path schedules sources permitted in the generic Wi-Fi context.
The Android supervisor fetches on validated physical Wi-Fi while the VPN is On.
Conditional provider refresh, separate home/cellular classification and actual
provider/device acceptance remain open. A failed fetch leaves the existing
authorized snapshot subject to its original expiry.

Runtime files use `SYN443_CONTROL_CONFIG` / `SYN443_SOURCE_CONFIG`. Their schema is
the closed `catalog.RuntimeConfig`; verified remote PostgreSQL TLS is mandatory.
API listeners are loopback-bound and serve HTTPS behind an owner-configured ingress.
Fixture HTTP and literal-loopback provider access are separate owner-only process
settings, absent from all resource/source mutation DTOs. All binaries are built
and scanned in GitHub Actions. Actual service deployment and real users are not CI.

This is the catalog service stage of M2/M3. Dynamic compilation/signing, the full
web/native administrative UI, managed invitations/overlay and final physical
acceptance remain required. See [the completion map](m2-m3-completion.md).

## Signer selection boundary

`PrepareSelection` selects only requested normalized profiles for an independently
verified user/device target and one permitted network mode. Personal device-fetch
sources never become shared data. Only explicit user/device grants are consumed
at this stage; a supplied group name is not membership evidence. The returned
server-private data omits provider API credentials and subscription URLs. Stable
profile IDs are independently recomputed from each source salt and selected
outbound, in addition to schema, ciphertext and snapshot-integrity checks.

The dependency ticket binds source/head/hash/share/resource revisions and clamps
the publication lease to current source freshness, validity and quota expiry.
A signer must call `Lock` in its final SQL transaction. Revocation, new heads,
sharing changes, provider disable/rotation and deadline expiration then prevent
publication, while an authorized last-known-good snapshot survives a transient
refresh failure. This component is not yet wired into configuration publication.
No device/API caller may supply its own owner or inferred group membership.

The optional identity publisher role can read only compiler-required columns;
fetch URLs, provider tokens, source jobs and ACLs remain denied. A dedicated
non-authoritative integer column permits PostgreSQL SHARE row locks without
UPDATE rights on any real source/resource setting. The source worker and control
roles retain their existing boundaries. Actions tests exercise the restricted
role, actual SQL races/cancellation, expiry/quota, corruption and memory bounds.

## Private network drafts (acceptance pending)

configuration.draft.get and configuration.draft.put handle only the current
verified administrator's own proposal namespace. Each explicit target also needs
live configuration.drafts.read/write ACL. The response body is private authorized
editing data, not inventory/telemetry; profile credentials remain source references.
Saved proposals use encrypted SQL, CAS, actor/ID/revision AAD and stable-operation
receipts. SavedAt is server-owned (zero in a put request). The portable plan is
bounded to256KiB and its put envelope to270336 bytes. Unknown/native fields and
numeric/null substitutions cannot become active settings. There is no side effect
on active configuration, source assignments, signing or provisioning.

Draft save does not require fresh MFA because it has no publication authority.
Independent preview/approval/publication still requires its own current strong
assurance and immutable target/base/dependency/impact fences. Discard/retention,
inventory, complete supported settings and web/mobile editors remain open.

The initial [control console](control-console.md) now consumes source/profile metadata
and actor-private draft get/put through a separately scoped OAuth/DPoP BFF.
Its exact Actions acceptance is pending; publication and the full panel remain open.

## Terminal source input erasure (new source, acceptance pending)

Raw manual/device import bodies are temporary encrypted job input. A SQL trigger
erases that input and the execution lease when a job succeeds, fails permanently,
is cancelled or reaches its deadline/retry limit. Terminal phases cannot be
reopened in place. Operation identity, keyed body hash, outcome and audit remain
available for idempotent replay; an administrative retry must create a new job.
Transient queued retries retain the encrypted input and existing fencing rules.

Each ordinary claim also scrubs at most32 terminal input records left by older
workers, using an indexed predicate and row locks with SKIP LOCKED. It does not
delete snapshots, receipts or audit, change a live job or acquire additional SQL
privileges. PostgreSQL tests exercise each terminal path, replay, late leases,
attempted reintroduction, retry preservation and bounded legacy cleanup.
Broader snapshot/history/outbox retention remains a separate open requirement.

Deadline and exhausted-retry cleanup also runs in batches of at most 32 jobs
and skips rows locked by concurrent work. The worker can claim eligible work
in the same transaction. The periodic schedule adds a stable per-source offset
of up to 10 percent to the configured interval and never schedules past source
expiry. Transient retries add up to 20 percent to the existing exponential delay.
Offsets do not move a provider request earlier.

The control console reads the selected source's job history with `job.list`.
Each page contains up to 20 jobs in reverse creation order with a stable cursor.
The request requires the existing control session, body-bound proof and live
source-owner read permission. Cursor lookups are scoped to the same source.
Queue phase, attempt count, reason and the earliest retry are visible. The
response omits request bodies, provider credentials and worker lease secrets.
The console clears the visible history when the source or session changes.

## Reserve probe cooldown

For a signed internal Wi-Fi failover plan, the operator can enable
`network.routeFailover.probeCooldown` in a draft. With no rollout share,
the preview requires every selected recipient to have negotiated
`route.reserve-cooldown.v1`.
Existing approval, source checks and independent publication still apply.
The publisher signs the capability alongside the unchanged proxy graph,
with a device-key-bound policy. Shared account grant templates cannot
opt into the rollout. Turning off the option leaves the legacy behavior
in the next reviewed policy revision.

Saving the option in a private draft does not activate it. To publish to a
fraction of an approved group, set `probeCooldownRollout` to a stable
lowercase ID and a share in basis points (0 to 10,000). The publisher
hashes that ID with the enrolled device ID. Raising the share with the
same ID preserves existing members. Devices without support and devices
outside the share receive the legacy behavior with the same proxy graph.
A new approved publication with share 0 stops this rollout. No hashes or
recipient IDs are added to policy diagnostics. Independent decision
bundles, measurement gates and automated progression remain separate.

## Conservative failover algorithm

For an internal Wi-Fi selector, set `decisionRevision: "m4-confirmed-v1"`
to require three independent failure confirmations and 60 seconds between
switches. Omit it for the baseline (two confirmations, 30 seconds).
`decisionRollout: {"id":"synthetic-algorithm","basisPoints":2500}` selects 25%
of compatible devices already approved for the plan. An unchanged ID keeps
the cohort stable as the percentage grows. Set zero basis points to return
the cohort to baseline. The selection is independent of the reserve probe
cooldown cohort and changes neither routes nor access. With no percentage,
every targeted device must advertise `route.decision.v1` before publication.
