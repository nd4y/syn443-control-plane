# Implementation and acceptance snapshot

The [bounded check-profile v2 component](route-check-profiles-v2.md) adds source
support for all/any/quorum and sequential stages while preserving legacy checks,
mandatory transport/exit gates and local proof/resource limits. Android advertises
the optional capability on new enrollment and can request it after an upgrade.
Assigning a profile requires a device with the approved capability. CHK-04 and
AC58 still require broader expression support and checks on an enrolled handset.
[Android capability negotiation](https://github.com/nd4y/syn443-android/pull/135)

Snapshot updated on 2026-11-22. Specification 0.9 contains 292 requirements and 98 acceptance
scenarios. Those numbers describe scope, not completed work or test counts.
This document supersedes repository-wide readiness claims in historical stage notes.

## Personal policies (AC01)

Two independent test users signed in through Keycloak using authorization code flow with PKCE. They enrolled three devices and received distinct signed policies. Each device retrieved its own policy. The API rejected all six combinations that presented one device's token with another device's proof. This verifies the Control Plane scenario in hosted integration. Opening the pilot device from the deployed console uses a separate account and deployment. [Integration test](../integration/keycloak/personal_issuance_test.go) · [Protected run](https://github.com/nd4y/syn443-control-plane/actions/runs/45016543420)

## Failed subscription refresh (AC03)

In the PostgreSQL integration test, an HTTPS provider returned an empty body, a malformed URI and an HTML document on consecutive refreshes. Each time the worker retained the last usable source snapshot and advanced a second provider independently. The publisher then issued a signed policy containing the retained profiles. In the mobile console, the source card offers review only for a distinct parsed candidate. It also reports a failed first download when there are no published profiles. [Worker and publisher test](../internal/deviceprovisioning/mixed_sources_postgres_test.go) · [Mobile console tests](../web-tests/source-review.spec.js) · [Protected run](https://github.com/nd4y/syn443-control-plane/actions/runs/45021785780)

## Subscription chain replacement (AC04)

The Control Plane verifies AC04 through the subscription worker, persisted source snapshots and the configuration publisher. When the first hop disappears from a six-profile feed, the previous snapshot remains active. Manual approval of the candidate conflicts while the published chain still uses the missing profile. After the administrator publishes a replacement, the same candidate can be promoted and the retained exit stays available. Four PostgreSQL cases passed on the reviewed source and again on protected main. [Integration fixture](../internal/deviceprovisioning/profile_dependencies_postgres_test.go) · [Source run](https://github.com/nd4y/syn443-control-plane/actions/runs/45008915397) · [Protected run](https://github.com/nd4y/syn443-control-plane/actions/runs/45011456943)

## Telemetry delivery after a lost acknowledgement (AC18)

The enrollment API accepted a newer batch before two older observations and deduplicated every replay. The standalone listener and its release container also committed an upload whose sender never read the response. After a restart and a newer upload, retrying the original batch returned the same ordered IDs. PostgreSQL retained the original observation times, versions and first server receipt. Seven integration cases passed on protected main. The Android delivery schedule and field deployment are tracked independently. [Database coverage](../internal/enrollment/telemetry_postgres_test.go) · [Listener and release container](../internal/enrollment/standalone_ingest_postgres_test.go) · [Protected run](https://github.com/nd4y/syn443-control-plane/actions/runs/45035206153)

## Resource-scoped external IDs (AC41)

Two synthetic API resources used the same external user ID. PostgreSQL retained distinct owner bindings, encrypted credentials, source assignments and health state. Changing which resource was active preserved both records. A second simultaneous activation was rejected. Three catalog cases passed on the reviewed and merged revisions. [Resource integration tests](../internal/catalog/resource_postgres_test.go) · [Protected run](https://github.com/nd4y/syn443-control-plane/actions/runs/45039968921)

## Enrollment and overlay evidence

The invitation link parser authenticates the service descriptor before discovery. The PostgreSQL tests follow an approved claim through publication into an ordinary device session. They also exercise an unavailable invitation database, prevent reassignment of an existing key and check that a revoked approval cannot complete publication. These tests cover the server portion of BOOT-02 and BOOT-03. Resolving the identity provider, reaching the enrollment API on a restricted network and fetching a usable first policy require separate network acceptance. [Invitation tests](../internal/invitation/boundaries_postgres_test.go) · [Publication tests](../internal/deviceprovisioning/invitations_postgres_test.go)

The NetBird broker issues credentials for a specific overlay and provider resource. Its management API updates and queries provider-side objects. Android separately verifies the embedded engine, route and traffic path. OVL-02 remains partial pending full lifecycle and device diagnostics acceptance. [Managed overlay](managed-overlay.md) · [Provider tests](../internal/netbirdapi/peers_test.go)

The Android register pins version 135. GitHub Actions passed 553 JVM tests and 641 tests on each of API 29, 35 and 37. The signed upgrade fixture exercised version 135 to 136. Six measured recoveries after an ingress or egress proxy failure ranged from 8.946 to 10.964 seconds. The normal release APK and the system package installer cancellation were verified separately. [Protected Android run](https://github.com/nd4y/syn443-android/actions/runs/45037062087)

The last verified physical installation was version 133. The source run passed 553 JVM tests and 622 cases on each of API 29, 35 and 37. It installed a signed higher-version fixture with ADB, checked the existing enrollment and sent real traffic through the restored VPN. An in-place update to version 133 preserved the enrolled pilot handset's identity. Four on-device package and DNS diagnostic checks passed. The device subsequently requested a fresh account login. Authenticated VPN recovery on this installation remains open. [Android source build and test evidence](https://github.com/nd4y/syn443-android/actions/runs/44990432637)

A separate Android 15 hosted emulator opened the signed update through DocumentsUI, cancelled in the system package installer and verified that the enrolled policy still worked. The check completed in the APK job. [System installer check](https://github.com/nd4y/syn443-android/actions/runs/44998526541/job/137139114860)

## Publication history and provider operations

The publication worker commits a revision and its content hash atomically. Authorized history reads identify a prior revision even after another edit takes effect. The inventory relates the issued policy to the exact desired revision. A separate authenticated device report supplies the activation or rollback observation. The register records partial coverage of EDIT-08, EDIT-09 and AC32. End-to-end mobile publication with its author, initiating device, comment and subsequent recovery from a lost response still requires acceptance. [SQL publication tests](../internal/deviceprovisioning/layer_publisher_postgres_test.go) · [Inventory and history](../internal/deviceprovisioning/layer_inventory_postgres_test.go) · [Activation reports](../internal/enrollment/activation_status_postgres_test.go)

The Remnawave adapter reads an assigned subscription. The NetBird adapter manages enrollment and revocation of objects whose ownership it can verify. Reserved x-ui, 3x-ui, Tailscale and ZeroTier resources stay inactive and cannot schedule provider work. The authenticated console rejects unsupported provider writes before contacting an upstream service. These checks provide server evidence for SRV-02, SRV-04 and AC42. Android capability display and unsupported chain selection have separate acceptance criteria. [Remnawave contract](../internal/remnawave/client_test.go) · [NetBird ownership](../internal/netbirdapi/peers_test.go) · [Reserved resources](../internal/catalog/resource_postgres_test.go) · [Console HTTP boundary](../internal/chatweb/control_test.go)

## Previously recorded control-plane checks




The accepted operation-reconciliation source adds an immutable SQL ledger, same-transaction native-effect guards and a fixed authenticated endpoint; see [the contract and limits](operation-outcome-reconciliation.md). Its28 new actual PostgreSQL/HTTP outcomes (23 provisioning,5 catalogue) and6 evidence-validator unit cases passed Actions43973718639 and resulting main43975423153. The separate safe Go-wire producer passed19 roots in43988560182 and resulting main43991701436; its public artifact contains only a bounded report, never signed specimens. No migration, live service activation, client reconciliation or restore/import acceptance is claimed. Shared IP/DPoP admission can still transiently throttle recovery.

The [service protocol eligibility source](operation-outcome-reconciliation.md#service-protocol-eligibility---source-and-main-accepted) adds only `configuration.protocol.get` with an empty payload and a closed two-field reply. Its optional owner declaration defaults to version1; explicit2 is a coordinated schema/consumer declaration, not proof of deployment or an authorization grant. Fourteen new outcomes (7 normal,4 provisioning PostgreSQL,3 catalogue HTTP/PostgreSQL) and6 validator unit cases passed Actions44006215112; resulting main44009146272 passed all8 mandatory jobs with the same source tree. No signed administrative metadata/bootstrap/device-key/session binding or old pending bytes/version is changed. No live enablement or full M3 acceptance is claimed.

## Current accepted checkpoint

### Home-network policy, operator console and Android v120

An administrator can assign a TLS endpoint to a specific device's adaptive policy and edit or remove it from the console draft on a phone. Three named Go cases verify policy decoding, compilation and the target's separate capability. The two phone-sized browser cases preserve neighboring settings, reject invalid input and clear unfinished edits when changing target. The server policy passed the protected run. The console form passed its pull-request run. [Policy CI](https://github.com/nd4y/syn443-control-plane/actions/runs/44943758656) · [Console CI](https://github.com/nd4y/syn443-control-plane/actions/runs/44944162657)

The Android v120 integration passed 539 JVM cases and 592 instrumented cases on each of API 29, 35 and 37 before merge. Coverage includes editor capacity, per-route checks, retry expiry and preservation of chat drafts. Deployment, the physical handset's current VPN state and home/guest TLS verification have separate acceptance checks. [Android CI](https://github.com/nd4y/syn443-android/actions/runs/44937487103)

### Wi-Fi recovery and Control Plane rollout - 2026-11-21

On the same enrolled ARM64 phone, v107 established a fresh HTTPS connection
through its VPN and returned 204. Five subsequent Wi-Fi losses and recoveries
kept the user's VPN intent. Each recovery advanced the network epoch. The first
default-family and explicit IPv4 requests returned 204 in all five cycles.
Time from restoring Wi-Fi to Online was 4.09-11.17 seconds. A separate check
in every cycle confirmed that the requesting UID and destination used the
app-owned TUN. The phone finished on its original Wi-Fi with the VPN off.

A separate test triggered a native engine crash and disabled Wi-Fi during
recovery. Android recorded one native SIGABRT in that interval. The client
reported NoNetwork, retained the same intent generation and established a new
engine. It returned to Online 15.06 seconds after the fault. A fresh HTTPS
request through the replacement TUN returned 204.

The test network had no global IPv6 address or IPv6 default route. IPv6-only
connections failed both with the VPN off and during these recoveries. Internet
egress over IPv6 still needs a capable network. A single HTTPS failure just
after an earlier v105 handover was not reproduced. Its cause is open.
The live assignment for these measurements contained one direct route. Device
tests of reserve failover and decision comparison used separate fixtures.
[Android failover](https://github.com/nd4y/syn443-android/pull/111) and
[on-device decision comparison](https://github.com/nd4y/syn443-android/pull/112).

On the same phone, the packaged VLESS XHTTP client exchanged a payload with
an independent, loopback TLS/HTTP2 server in stream-one mode. The server
observed the correct VLESS destination and served its banner. A mismatched TLS
name was rejected before another HTTP request or target connection. Two more
packaged tests exercised HTTP CONNECT through a VLESS exit and a refused
entry. These fixtures used ephemeral test credentials. A provisioned external
provider path still has its own acceptance gate.
[Android XHTTP test](https://github.com/nd4y/syn443-android/pull/113).

| Control Plane change in main | Evidence |
| --- | --- |
| Keep a stable control group during a staged policy rollout | An authorized publisher prepared policies for devices on both sides of the cohort boundary. The mobile editor preserved the control percentage. [PR 93](https://github.com/nd4y/syn443-control-plane/pull/93) |
| Compare routing decisions against the same recorded observations | The web console runs the same ranking function with two evidence lifetimes and reports which decisions change. The replay sends no probes and publishes no policy. [PR 94](https://github.com/nd4y/syn443-control-plane/pull/94) |
| Check provider-worker readiness before taking a job | The executable verified role and catalog configuration against PostgreSQL, left queued work available and made no provider request. Starting the normal worker then processed the job once. [PR 95](https://github.com/nd4y/syn443-control-plane/pull/95) |

The production pilot's web deployment, activation of the provider worker and
external provider egress each have a separate acceptance gate.

### Android v104 on Wi-Fi - 2026-11-21

The first controller status read after an Android reboot used to report recovery
even when the VPN service had already restored traffic. On the updated ARM64
handset, a fresh HTTPS request returned 204 through the app-owned TUN after a real
OS reboot, before the first controller query. Subsequent status queries reported
Online and preserved the connection generation. [Android change and Actions checks](https://github.com/nd4y/syn443-android/pull/108)

| Physical check | Observed result |
| --- | --- |
| Move between two saved Wi-Fi networks, then return | Fresh tunneled HTTPS 204 after 13.88 s and 12.44 s, respectively |
| Terminate the native VPN process | New process and fresh tunneled HTTPS 204 after 37.36 s |
| Keep the screen off on Wi-Fi and USB power | 13 of 13 fresh HTTPS checks passed over 3,603.72 s, with the same engine process, connection generation and network epoch at every sample |
| Exercise the packaged transport | Four handset tests passed, including HTTP CONNECT through a VLESS exit on loopback, refused-entry handling and real Wi-Fi HTTPS GET/HEAD |

The original enrollment was retained. The handset finished on its original Wi-Fi
with the VPN off. Cellular access, unplugged battery life and a full day of
operation require separate measurements.

### Wi-Fi handover and support chat - 2026-11-21

On an enrolled ARM64 phone running v99, the VPN stayed on as the phone moved
between two saved Wi-Fi networks and returned to the first. On each of the
three connections a fresh HTTPS request returned 204. Android reported that
the actual remote address was covered by the application's TUN and that the
requesting UID used the VPN. Each handover changed the network epoch and
preserved the VPN intent generation. The phone finished on its original Wi-Fi
with the VPN off. Cellular and battery-powered endurance remain open.

A separate physical check found that the issuer could be reachable from one
Wi-Fi while public HTTPS through the VPN worked on both. Testing the public
discovery URL with the VPN off isolated the difference to the address returned
by the second network's resolver. Resolving the same approved hostname to its
published address returned HTTP 200 through ordinary certificate validation.
The acceptance test therefore measures authentication and VPN egress separately.

| Control Plane check in main | Observed result |
| --- | --- |
| Change support conversation while a history or attachment request is pending | Both web views clear the previous user's content. A late result cannot restore it. [PR 77 and browser checks](https://github.com/nd4y/syn443-control-plane/actions/runs/44840560646) |
| Read an inbox and history beyond 200 entries | Both views paged 212 conversations and 242 messages. Viewing an older page preserved its position and left new arrivals unread. [PR 78 and 84 browser cases](https://github.com/nd4y/syn443-control-plane/actions/runs/44843769521) |
| Resume a 25 MiB upload from a PostgreSQL backup | A separate restored database retained exactly 50 of 100 chunks. The authorized user completed the upload and downloaded matching bytes. Another account was denied. [PR 79 and PostgreSQL checks](https://github.com/nd4y/syn443-control-plane/actions/runs/44846515509) |

These three GitHub Actions runs validate the corresponding merged source.
The pilot web release and restoration of a deployed database have separate
acceptance checks.

### Physical Wi-Fi recovery and support - 2026-11-20

A pilot user signed back in through the system browser on Android v98. The
app verified the assigned policy and retained the device ID and key. After
installation of v99 over v98, the same policy authorized VPN use. The app
UID, policy revision, telemetry consent and radio settings matched their
pre-upgrade values. [Android PR101](https://github.com/nd4y/syn443-android/pull/101)

| Physical check on the USB-connected phone | Observed result |
| --- | --- |
| Disable Wi-Fi, observe network loss, then re-enable Wi-Fi in airplane mode | Both cycles recovered. A fresh HTTPS request through the app-owned VPN returned 204 after 16.25 s and 16.24 s. |
| End the app's native engine process while the VPN is on | A new process took over. HTTPS through the VPN returned 204 after 9.02 s. |
| End the UI process while the VPN is on | The native process and connection generation stayed the same. A new HTTPS request succeeded, and the UI reopened. |
| End the VPN controller process | Android started a new controller before the test queried the app. The engine was replaced, the connection generation stayed the same and HTTPS succeeded after 9.91 s. |
| Open support chat and export a local diagnostics ZIP | The user saw the connected conversation and an enabled composer. The Android document picker saved the ZIP. Its manifest listed all nine components and the available component hashes matched their contents. |

The traffic checks matched the request's resolved destination against the
VPN routes and checked that the requesting UID belonged to the app-owned
VPN. Timings include the verification request. The assigned policy used one
direct outbound. The test concluded with VPN off and Wi-Fi on, as found.
Cellular, autonomous battery life and current managed NetBird/VLESS assignments
require separate physical checks. The chat check covered opening the conversation.

On November 21 an administrator signed in to the pilot console through Keycloak,
selected the existing phone from the device list and opened its issued settings.
The signed configuration selected a direct outbound and the `m1-local-v1`
algorithm. The console marked the last runtime report as stale. USB readback
confirmed the installed v99 package and its existing registration. This check
covered read access to the device and its configuration. Administrative edits
and publication from the phone remain separate checks.

The server tests covered a concurrent chat send during orphan cleanup, a
backlog spanning multiple cleanup transactions and a retry after the queue
drained. PostgreSQL retained the attachment bytes after the send committed.
Separate process tests checked that API readiness follows database
availability. These changes reached the main branch. Their pilot rollout
remains open. [Chat cleanup](https://github.com/nd4y/syn443-control-plane/pull/70)
and [backlog tests](https://github.com/nd4y/syn443-control-plane/pull/72).
[API readiness tests](https://github.com/nd4y/syn443-control-plane/pull/71).

### Observability source and integration - 2026-11-18

| Component | Verified evidence |
| --- | --- |
| Android NetBird report | [PR97](https://github.com/nd4y/syn443-android/pull/97) and the [matching main tree's CI](https://github.com/nd4y/syn443-android/actions/runs/44180494937). The report pages bounded retained peer evidence and distinguishes direct, VLESS and unknown transport. |
| Android offline diagnostic ZIP | [PR99 CI](https://github.com/nd4y/syn443-android/actions/runs/44259756350) passed 522 JVM cases and 524 outcomes on each of API 29, 35 and 37, including a Provider/CLI collect, export and cancel check. The identical source tree passed [main CI](https://github.com/nd4y/syn443-android/actions/runs/44268019344). |
| Android encrypted local journal | [PR100 CI](https://github.com/nd4y/syn443-android/actions/runs/44268949079) passed 534 JVM cases and 536 outcomes on each emulator API, including 12 new JVM and 12 new device-side journal cases. The source merged into [main with its own CI run](https://github.com/nd4y/syn443-android/actions/runs/44276979024). |
| Control Plane telemetry administration | [PR65](https://github.com/nd4y/syn443-control-plane/pull/65) restored both UTC-hour CLI entry points. [PR66](https://github.com/nd4y/syn443-control-plane/pull/66) added the dedicated retention worker and isolated PostgreSQL tests. Their exact source trees passed eight jobs each on [PR65 main](https://github.com/nd4y/syn443-control-plane/actions/runs/44258666408) and [PR66 main](https://github.com/nd4y/syn443-control-plane/actions/runs/44264413839). |

The local ZIP has a manifest with hashes, explicit omissions and a preview.
Collection reads existing evidence without starting probes or changing VPN
state. The journal adds typed lifecycle and engine evidence with a 64 MiB
storage cap and up to seven days of readable history in the same boot. The
November 20 checkpoint above records the later physical Wi-Fi, identity
preservation and export checks. Full effective configuration, redacted native stacks, remote
support upload and download auditing remain open. The aggregation worker scans
settled UTC hours and resumes missed work after restart. Isolated PostgreSQL
tests exercise the executable with the restricted analysis role and verify its
commits through the reporting role. Pilot deployment, retention of backup copies
and per-device erasure remain open. [Aggregation worker](https://github.com/nd4y/syn443-control-plane/pull/74)

### Prior physical and deployment evidence

The [2026-11-17 checkpoint](non-lte-acceptance-20261117.md) records the accepted
v89 source/main, its68 scoped physical USB/Wi-Fi outcomes and the deployed
session-refresh boundary correction. Real native administrator SSO/editing/
publication and full adaptive routing remain open. The earlier
[v79 USB/Wi-Fi checkpoint](non-lte-acceptance-20261116.md) retains its historical
scope. The
[v77 chat/source checkpoint](chat-acceptance-20261115.md) retains its earlier scope.

See the [2026-11-15 source, CI and USB/Wi-Fi checkpoint](non-lte-acceptance-20261115.md)
for the earlier Android v73 and Control Plane snapshots, delivery provenance,
physical recovery, live console readback and remaining scope. This refresh does
not promote a broad requirement from a component test or merge status.
The [v75 runtime checkpoint](runtime-acceptance-20261115.md) supersedes its
runtime delivery and integration status without closing the remaining milestones.

## Historical foundation integration - 2026-11-01

The following table and counts document the earlier accepted foundation.
Current source and acceptance are pinned in the checkpoint above.



| Component | Accepted implementation | Integration into main |
| --- | --- | --- |
| Android | `e2291a71fa8491497f342fe26fbdf36788e2b59a`; [Actions41284851623](https://github.com/nd4y/syn443-android/actions/runs/41284851623) | [PR25](https://github.com/nd4y/syn443-android/pull/25), merge57038f4249b71766f5146af0d3298210192afab5 |
| Control plane | `c1fae966a2a0030a2d6e949b35716d767ea79e4c`; [Actions40510900456](https://github.com/nd4y/syn443-control-plane/actions/runs/40510900456) | [PR11](https://github.com/nd4y/syn443-control-plane/pull/11), merge3d7763ac39f445d52e8ae32c102143fae2d88d2e |

Each integration preserved the exact accepted source tree and commit ancestry.
Superseded stack PRs are closed with integration links; this does not turn a
historical failed/intermediate CI run into a passed run. Unverified side branches
and dependency updates are separate. Subsequent main/PR CI validates integration
and documentation commits independently. A merge is not a production deployment.

The accepted Android snapshot passed159 JVM methods and138 mandatory outcomes on
each API29/35/37, with zero skips/errors/failures. It retained the previous122 cases.
The exact Actions APK v26/0.7.0 also passed57 physical UI/storage/media/Keystore
checks on USB Xperia. Real public HTTPS, NetBird/internal SSH, independent optional
failure, visible route outcomes, Wi-Fi loss/return with fresh evidence, controller
death, reboot Off/On, update Off, Force stop/update/foreground and actual Android
Always-on/lockdown were checked. Newer Stop wins; a saved engineActive checkpoint
cannot claim a currently owned process. Configuration, two SDK identity fields
and original system/mobile-data settings were preserved/restored; main APK was
retained, test APK removed, Wi-Fi validated and VPN Off at final device readback.
Full status readiness after Wi-Fi return took73.12s including the probe interval;
this is not packet-outage latency. Device records/screenshots/configuration stay
private. This historical receipt covers the version installed at that test.

Control-plane acceptance includes Go/race, PostgreSQL process/role/transaction,
temporary Keycloak and browser support-chat checks. Prior isolated synthetic
deployment/phone evidence covers SQL history and complete25MiB files, user/admin
reply, role withdrawal and device image/video compression. Production deployment
and physical browser download persistence are not implied by browser CI.

## Milestone boundaries

| Milestone | Implemented scope | Remaining gate |
| --- | --- | --- |
| M0 | Shared bounded Go/Kotlin reference ranking, coordinator and contracts | Foundation only; not full route exploration |
| M1 | Real TUN/native host, durable intent, bounded recovery, direct/two-hop/NetBird paths, per-outbound evidence and reproducible Android lifecycle | LTE/restricted LTE, natural Doze, unplugged battery and endurance; full OS/routing predicate matrix |
| M2 | Keycloak/OIDC/PKCE/DPoP pilot, Keystore identities, SQL device sessions, signed assignments, refresh/cache/lease/revoke, transactional activation and rollback | Release invitations/QR/manual binding and live acceptance for full enrollment, managed overlays and root rotation |
| M3 | Embedded engines, a scoped Remnawave API resource, subscription normalization and addressed Wi-Fi fetch, separate API/worker/web processes | Live provider and complete protocol acceptance, native mobile edit/publish, all managed settings and administration workflows |
| M4 | Reference comparator, bounded graph planner, managed target checks, partial diagnostics, internal Wi-Fi failover candidate, [bounded technical telemetry ingestion](telemetry-ingest.md) and basic SQL support chat | Runtime graph exploration/quarantine across all four modes, cohort policy rollout, full telemetry/incident pipeline and retention controls |
| M5 | Reproducible CI and scoped physical evidence | Complete version1.0 security/reliability/update/migration/restore and production acceptance |

HTTP/SOCKS/VLESS/SSH/selector/url-test and NetBird are accepted configuration
types in the embedded adapter. Full physical protocol/transport/chain acceptance,
including XHTTP and restrictive-cellular emergency VLESS paths, is still separate.
NetBird direct mode attempts P2P before relay fallback; VLESS mode has a dedicated
detour with no hidden direct fallback. Direct home access was physically checked;
that is not restricted-LTE acceptance or managed overlay enrollment acceptance.

Android accepts signed route checks and managed NetBird assignments when the
device has the corresponding capabilities. New enrollment advertises
`route.health.v1` and `overlay.credentials.v1`. A managed NetBird publication
requires a permitted provider resource, the broker and an addressed grant.
The November 21 pilot card contained only a direct outbound. The earlier
managed Cloud enrollment and private-peer checks are documented in the
[Android acceptance record](https://github.com/nd4y/syn443-android/blob/4dfffe92c6dbf86f4be9b7b86c3473362f30d2d1/docs/managed-overlay.md#diagnostic-readiness-after-network-changes).
Multiple Remnawave resources, x-ui/3x-ui and Tailscale/ZeroTier remain extension
contracts by design, not implemented version1.0 requirements.

## Evidence index and register semantics

The registers track product requirements, including cross-component contributions.
Evidence may point to this pinned cross-repository inventory when implementation
lives in the other component. Local evidence links are also retained. No register
text, ID, acceptance row or normative specification hash is changed by this update.

- `planned`: no accepted implementation contribution recorded for that row.
- `partial`: concrete code/tests cover a subset; the full requirement is open.
- `implemented`: all clauses are implemented, but required acceptance is incomplete.
- `verified`: every clause and its required acceptance are proved for the declared scope.

Test counts, line coverage and existing file paths alone never promote a broad
requirement. New partial rows contain implementationScope and remainingScope.
Existing partial evidence remains historical unless a new snapshot says otherwise.
No full M1-M5 or production-readiness claim is made by these statuses.

| Requirements | Concrete contribution | Unaccepted remainder |
| --- | --- | --- |
| ARC-02/03/04/07, REC-01..06, ENG-01/02/08, AC82..90 | Durable controller, Stop/generation fences, bounded crash/hang recovery, actual per-outbound target evidence and USB Wi-Fi/OS cases | Full cross-mode/admission/budget matrix, LTE, natural Doze, energy/endurance and every OS/routing predicate |
| MOD-01..10, ENG-05 | Isolated host/TUN adapter, source/patch/toolchain locks, built-in modules, native alignment and ordinary/race tests | Complete capability/version matrix, signed release inventory/SBOM, all update/retirement acceptance |
| NB-01/02/05/06/07 | Direct-first/deferred SDK, strict VLESS detour, local identity, bounded cached roster/diagnostics and home traffic proof | Managed account credential retirement, backend peer lifecycle, DNS/route conflict and full handover matrix |
| CHK-01..12, CHECK requirements | Bounded TCP/SSH/TLS/strictHTTPS all-of checks through selected outbound with fresh scoped samples and check/cancel/status | Full rule/class/template plan model, any/quorum/stages, exit attribution, scheduling/dedup and visual profile editor |
| LOG-01..06, ADB-01..04 | Bounded lifecycle/exit/resource snapshots, debug own-UID/shell controls, an offline diagnostic ZIP and a typed encrypted controller journal | Full channels, debug windows and retention policy, effective configuration and redacted native stacks, supported remote transfer, release opt-in, server audit and physical export |
| AUTH/PROV/SEC partial rows | Pilot protocol/Keystore/journals, signed device-key policy and SQL authorization/publication | Full release onboarding, invitation trust, rotation, managed overlays and operational acceptance |
| CHAT partial rows | SQL message/file integrity and atomicity, Android user/admin and web chat, compression/retry/withdrawal | Complete retention/quota administration, production operations and restricted-network acceptance |

Source/test inventories for review:
- [Android controller and UI](https://github.com/nd4y/syn443-android/tree/e2291a71fa8491497f342fe26fbdf36788e2b59a/app/src/main/kotlin/io/syn443/android/vpn)
- [Android acceptance drivers](https://github.com/nd4y/syn443-android/tree/e2291a71fa8491497f342fe26fbdf36788e2b59a/tools)
- [Native engine adapters and tests](https://github.com/nd4y/syn443-android/tree/e2291a71fa8491497f342fe26fbdf36788e2b59a/native)
- [Enrollment/SQL/worker/chat code](https://github.com/nd4y/syn443-control-plane/tree/c1fae966a2a0030a2d6e949b35716d767ea79e4c/internal)
- [Control-plane acceptance](https://github.com/nd4y/syn443-control-plane/tree/c1fae966a2a0030a2d6e949b35716d767ea79e4c/docs/TESTING.md)

An earlier isolated API29 policy-bootstrap unavailable/rollback event has no
proved root cause and did not recur in the final three-API snapshot. Bounded
DEBUG worker diagnostics remain available; unrelated changes are not called its fix.
All builds run in GitHub Actions. Physical USB/Wi-Fi and privacy/cleanup evidence
remain separate. No production secret, provider URL, identity file or raw device
log belongs in source, fixtures, Issues, Actions artifacts or releases.


## Default proxy transport

The network compiler appends a terminal UDP drop for a TCP-only default proxy.
A UDP-only VLESS default gets the corresponding TCP drop. Destination and
application exceptions keep their authored priority, including an explicit
alternate that carries UDP. A VLESS exit carrying UDP through an HTTP entry
supports both transports and needs no extra rule. The signed engine document
contains the drop, so the Android client can explain it using the issued rules.
The control panel draft preview evaluates the rules supplied by the editor
before outbound resolution.

The portable limit is 128 authored rules. At the 129th position the adaptive
reader accepts only the exact terminal drop implied by the final outbound.
Inputs issued using the earlier limit still work. Compiler fixtures exercise
both protocol directions and the full rule budget. The PostgreSQL publisher
test reads the terminal UDP rule from the verified device-bound envelope.
Full per-transport traffic and address-family checks on supported physical
devices remain open for AC08.
