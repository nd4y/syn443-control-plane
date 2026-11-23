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

For a known allowance, `source.snapshot` includes `trafficBytes.used` and
`trafficBytes.limit` as unsigned decimal strings. The largest counter is
`18446744073709551615`. A zero limit denotes an unlimited allowance. The
existing numeric fields in `snapshot.quota` are retained for compatible clients.
The console uses `snapshot.quota.observedAt` for the time the provider reported
the counters. A later subscription fetch can update `snapshot.observedAt`
without refreshing those counters. An unknown quota omits `trafficBytes`.

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

## Signed failover thresholds

In the configuration draft, choose **Консервативный** under **Алгоритм переключения** for an internal Wi-Fi selector. Enter a positive program revision, choose 3 to 6 independent failed checks, and choose a minimum interval of 60000 to 300000 milliseconds between switches. Click **Применить пороги к черновику**, save the draft, then publish it to the intended devices. A switch also needs a fresh successful check of an authorized alternative.

For example, a program at revision 7 with four confirmations and a two-minute interval uses the following fields in the existing failover plan.

```json
{
  "decisionRevision": "m4-confirmed-v1",
  "decisionProgram": {
    "revision": 7,
    "confirmations": 4,
    "minSwitchIntervalMs": 120000
  },
  "decisionRollout": {
    "id": "example-pilot",
    "basisPoints": 2500
  }
}
```

The publisher selects eligible devices using the existing cohort assignment. Devices in treatment must advertise both `decision.bundle.v1` and `route.decision.v1`. With a percentage rollout, incompatible devices retain the baseline. An explicit assignment without a percentage requires both capabilities. The issuer signs the program against the enrolled device key, configuration hash and lease expiry, then includes it in that device's policy.

To restore the conservative defaults of three confirmations and 60 seconds, clear the program revision, apply the thresholds to the draft and publish a new policy. To send the percentage cohort back to the baseline algorithm, set its treatment share to zero and publish.

## Permanent control group

For example, `{"id":"synthetic-algorithm","basisPoints":5000,"controlBasisPoints":1000}`
reserves 10% of eligible devices on the baseline and selects half of the remainder
for treatment. At 100% treatment those same control devices still receive the baseline.
Existing plans without a control share retain their original assignments.
The authenticated device ID determines membership. Keep the rollout ID and reserved
share fixed while increasing or decreasing treatment. Changing either reassigns
some devices. Decision and cooldown rollouts can share a control group by using
the same ID and reserved share. Their treatment assignments remain independent.
A zero treatment share stops the rollout for the next approved policy.

### Pause a rollout

Select the pause control in the route draft for the algorithm or the reserve
probe setting, then apply it to the draft. The group preview accounts for the
pause before publication. A paused rollout sends the baseline configuration to
devices outside the permanent control group. The group ID and both percentages
stay in the draft. Clear the pause and publish a new approved revision to
resume using the same predefined groups. Devices apply the change when they
receive the approved policy. Existing publication and authorization checks
apply to both operations.

In the route draft editor, enter the rollout percentages and a device ID, then
choose **Проверить группу**. Each configured feature reports its own treatment,
permanent control or unselected baseline assignment. The preview accepts
unsaved percentages and uses the publication allocator. An ID can be checked
before enrollment. The device card shows the policy actually issued after
eligibility and capability checks.

## Replay the freshness of route evidence

Open the simulation in the drafts section before publishing. The baseline uses
the evidence TTL from each frame. The trial changes only that TTL, in
milliseconds. Both passes use the common route selection algorithm on exactly
the same measurements. The report counts identical routes, changed routes,
loss of a route, gain of a route, and frames with no route in either pass.
Expand a traffic class to see its outcomes and why the trial rejected candidates.
Outcomes count frames. Reasons count candidates, so one lost internal route
can have several rejected alternatives. Neither route identifiers nor raw
observations appear in the comparison. Requests from older clients keep the
original six aggregate counts.
A longer TTL can select older measurements; a gained route is a simulation
outcome and does not establish current reachability.

Run the bundled public contract scenarios or supply a JSON array of aggregate
decision requests matching `contracts/v1/decision-request.schema.json`.
To make a small synthetic trace, take the `input` objects of two cases in
`contracts/v1/decision-vectors.json` and put them in one array. Up to 64
frames and 64 candidates per frame are accepted. The file limit is 255 KiB.
The console returns aggregate counts, performs no live probes or writes, and
discards comparisons when the operator changes the inputs. This replay covers
snapshot ranking; on-device shadow observation and automatic rollout gates
remain separate requirements.

## Home Wi-Fi proof for adaptive routes

An adaptive network draft can assign one TLS service in `network.homeProof`.
Supply its DNS certificate name in `hostname`, its private IP literal in
`address`, the TCP `port`, and the SHA-256 digest of the leaf certificate's
SubjectPublicKeyInfo in unpadded base64url as `spkiSha256`. Choose a service
reachable over the intended home network. Use a private IPv4 or IPv6 ULA
address; the name is for SNI and certificate verification. The client needs
no DNS lookup of that name. Retain ordinary TLS certificate and hostname
verification when deploying or rotating the key.

Publication requires the authenticated target to advertise
`network.home-proof.v1` along with adaptive routing. This declaration scopes
a handshake to the named service. It grants no direct application traffic,
trust exception, location permission or access to additional endpoints.
An unreachable or changed service leaves the client on its ordinary Wi-Fi
policy. Previously enrolled clients retain their earlier configuration.

## Replacing a subscription profile in use

Open a source in the console to see all its profile IDs used by published routes, displayed in groups of 32. Use **Обновить зависимости** to refresh the list while editing. A pending historical check is shown separately from an empty result.

When a feed drops a profile in a published configuration, the worker quarantines
the candidate. Manual approval checks the same current references. Publish a
replacement route for each affected recipient, then review the candidate again.
The check includes static aliases and adaptive candidates from the effective
configuration. A preview or an unsuccessful publication leaves the references
on the current revision.

After upgrading the catalog and configuration schemas, the configuration worker
indexes one historical head on each idle iteration. It opens the stored proposal
and verifies the original signed preview. While a head awaits recovery, removals
from an active feed stay in quarantine. Additions can still be evaluated.
A failed historical verification leaves the removal fence in place and delays
that head's next attempt for 15 minutes. Reindexing preserves the device key,
configuration revision, approval time and offline lease.

## Device subscription retry history

Open the subscription source and select its job history. A device job reports
download attempts on the phone and parsing attempts on the server separately.
A phone can resume its current lease. The next time shown for a *new* download
respects that lease, the eight-attempt limit, the job deadline and source expiry.
Once the phone uploads the response, the history shows the server processing
stage and its own retry budget.

### Explain a connection with an unavailable hostname

In the draft route preview, enter the destination IP. If the connection was made
to a literal IP, leave the address context at its default. If DNS was encrypted
or only an IP was observed, choose the option for an unavailable domain. The
preview then stops at an earlier domain-dependent rule whose outcome could
change the route. A matching CIDR can still confirm that rule, and a conflicting
application, port or transport can rule it out. The same reasoning applies to
IPv4 and IPv6. An IP shared by several hostnames supplies no domain evidence.

The preview uses only the facts entered for this query. It performs no lookup
and retains no destination history. DNS is reported as unknown when the hostname
is unavailable. The DNS step is inapplicable to a connection made to a literal
IP. OWN-04 remains partial pending equivalent evidence across live packet
classification and portable rule sets.
