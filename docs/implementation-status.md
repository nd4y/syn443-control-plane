# Implementation and acceptance snapshot

Snapshot: 2026-11-01. Specification0.9 contains292 requirements and98 acceptance
scenarios. Those numbers describe scope, not completed work or test counts.
This document supersedes repository-wide readiness claims in historical stage notes.

## Accepted source and integration

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
private. The installed snapshot is the accepted implementation above, not a claim
that every later metadata-only merge APK was physically installed.

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
| M2 | Keycloak/OIDC/PKCE/DPoP pilot, Keystore identities, SQL device sessions, signed assignments, refresh/cache/lease/revoke, transactional activation and rollback | Release invitations/QR/manual binding; full enrollment acceptance, credential namespaces for managed overlays, signed route-check activation handoff, rotation |
| M3 | Embedded engines, separate enrollment API/publisher/support-web processes, and a read-only Remnawave 3.4 adapter with protected owner CLI | Persistent resource/account management, subscription normalization and publication, full protocol acceptance matrix, mobile edit/publish and full administration frontend |
| M4 | Reference comparator, bounded target checks, partial diagnostics and basic SQL support chat | Autonomous four-mode graph exploration/quarantine, cohort policy rollout, central telemetry/incident pipeline and full retention controls |
| M5 | Reproducible CI and scoped physical evidence | Complete version1.0 security/reliability/update/migration/restore and production acceptance |

HTTP/SOCKS/VLESS/SSH/selector/url-test and NetBird are accepted configuration
types in the embedded adapter. Full physical protocol/transport/chain acceptance,
including XHTTP and restrictive-cellular emergency VLESS paths, is still separate.
NetBird direct mode attempts P2P before relay fallback; VLESS mode has a dedicated
detour with no hidden direct fallback. Direct home access was physically checked;
that is not restricted-LTE acceptance or managed overlay enrollment acceptance.

Signed assigned configurations containing route_checks or unsupported managed
overlay credentials remain rejected until their activation/retirement protocols
enforce the same safety constraints. This limitation is not silently bypassed.
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
| LOG-01..04, ADB-01..04 | Bounded redacted lifecycle/exit/resource snapshots and debug own-UID/shell control | Full log channels/retention/redactor/bundle, complete CLI, release opt-in and server audit |
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
