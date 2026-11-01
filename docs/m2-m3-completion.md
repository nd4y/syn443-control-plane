# M2 and M3 completion contract

The preceding route-activation and read-only resource pilots are accepted slices,
not completed milestones. This work preserves specification0.9 and all292
requirements/98 scenarios. No new protocol, source format or UI-only success can
stand in for the complete user path below.

| Gate | Requirements | Required behavior and acceptance |
| --- | --- | --- |
| Identity and trust | AUTH-01..05, ONB-01..04, SEC-04..07, BOOT-06..15 | Browser OIDC and separately approved single-use link/QR produce the same device authority; trusted origins, proof/approval, idempotency, expiry/revoke, signing rotation and recovery |
| Managed overlay | NB-01..07, OVL-01..02/06, PROTO-04 | Account/device/resource/network identity isolation, addressed one-use enrollment secrets, stable peer through config/network changes, direct preference, bounded relay fallback, retirement and revoke reconciliation |
| Resources and sources | SUB-01..12, EXT-01..04/07..10, AUTH-03 | One scoped Remnawave resource; URI/base64/sing-box/Xray/Mihomo subscriptions; persistent owner/recipient/metadata/source history; server/device/manual fetch; source isolation, stable IDs, quarantine and explicit expiry |
| Durable jobs | SVC-02/03/06..09 | SQL jobs/outbox, lease/deadline/cancel, bounded admission and retries, scheduler dedup, stale-source/CAS fences, dead-letter status, separate parser/fetch and signer authorities |
| Compiler and publication | CFG-01..06, PROV-01..07, EDIT-04..09 | Explicit template/group/user/device/local layers, provenance/locks, dependency snapshots, scoped profile/secret authority, capability/chain validation, immutable revisions and independently authorized signing |
| Administration | EDIT-01..12, MOB-01..08, SRV-01..04, SVC-01/04/10 | Responsive web administration and native quick screens, separate admin audience, live scoped SQL grants, fresh MFA for sensitive changes, masked-secret operations, drafts/diff/conflicts/idempotent publication/audit |
| Embedded protocols | MOD-01..08, PROTO-01..04 | HTTP/HTTPS CONNECT, SOCKS TCP/UDP, VLESS TLS/Reality/WS/gRPC/XHTTP, pinned h2/h3 modes, SSH host-key trust, NetBird and supported bounded chains; field/capability matrix and native integration proof |
| Physical workflow | ONB/BOOT/EDIT/PROV acceptance scenarios | Exact Actions APK, actual onboarding and admin/edit paths, assigned VPN and overlay, Stop/rollback/Wi-Fi recovery and preserved/restored operator state; CI is separate evidence |

The complete normative acceptance definitions remain in the specification and
requirements register. The mapping above is a work/ownership index; it does not
remove requirements or claim that a planned row has passed.

## Component and authority boundaries

- Device API owns registered device sessions and narrowly addressed delivery.
  OIDC identity, manual enrollment and administrative sessions stay distinct.
- Control API owns user-issued drafts, resource/source/assignment definitions and
  scoped administrative mutations. All operations validate live SQL authority;
  the caller cannot supply its own role or infer authority from a debug build.
- Fetch/parser workers can claim bounded source jobs and create candidate source
  snapshots. They do not hold the publication private key or mutate actor grants.
- Publication workers independently check the authenticated request, current
  grants, immutable input snapshots and CAS revision before signing per-device
  assignments. A source snapshot or callback cannot publish on its own.
- Frontend reuses the bounded OAuth BFF. Browser code never receives refresh
  tokens, a signing key or provider management credentials. Native admin screens
  use a separate audience and the same server-side business validation.
- SQL holds definitions, source snapshots, revisions, jobs and audit. Secret
  material is encrypted and omitted from ordinary inventory/diff. Keep/replace/
  delete are distinct operations; display masks are never accepted as passwords.

Each administrative publication explicitly identifies device/user/group/template,
base revision, immutable dependency hashes and affected recipients. The default
target is the current device. Lost replies retry the same operation identity.
Conflicts retain base/local/server values instead of silently overwriting edits.
Local experiments preserve server revision, lease and identity and remain visibly
distinct from a server publication.

## Scope retained outside these milestones

Multiple active Remnawave instances, x-ui/3x-ui, Tailscale and ZeroTier remain
contract-only, with activation rejected until an implementation exists. M1 physical
LTE/restricted-LTE, natural Doze, unplugged energy and endurance are not closed by
Wi-Fi or emulators. M4 autonomous graph exploration, cohorts and telemetry analysis
and M5 complete release/production acceptance remain separate. The panel can edit
validated supported settings; it must identify unavailable runtime capabilities
and cannot label planned behavior operational.

## Current implementation evidence

The bounded normalization and pure quarantine components are described in
[the import matrix](subscription-import.md). The SQL catalog now also contains
resource definitions, impact-bound sensitive changes, resource-version job fences,
and the manual/HTTPS/Remnawave worker orchestration. HTTP service integration,
recipient review, compiler, administration and identity/overlay completion are
still pending. The catalog Actions gate runs actual role-restricted PostgreSQL,
TLS provider fixtures, cancellation and atomic rollback checks with an80% floor.
Remaining paths must each add positive, negative, concurrency
and boundary checks before the corresponding milestone can be accepted. All builds
and compiled tests execute in GitHub Actions. Private device/operator artifacts
never become public test fixtures or upload payloads.
