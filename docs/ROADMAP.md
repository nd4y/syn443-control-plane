# Implementation roadmap

Current evidence and remaining scope: [implementation snapshot](implementation-status.md).
The normative specification remains0.9; all292 requirements and98 scenarios are retained.

## M0 - contracts and executable reference core (foundation implemented)
Bounded shared Go/Kotlin inputs/results, deterministic reference ranking, context
generations and Stop/cancellation precedence are implemented. This is a foundation,
not complete path discovery or a production service. See the historical M0 note.

## M1 - physical Android vertical gate (partial)
Real isolated native/TUN ownership, direct/two-hop/NetBird forwarding, durable
intent, bounded recovery, route evidence and reproducible OS scenarios are implemented.
Accepted snapshot:159 JVM methods,138 Android outcomes per API29/35/37 and57
physical UI/storage cases plus actual USB Xperia Wi-Fi/route/controller/OS checks.
Physical LTE/restricted LTE, natural Doze, unplugged battery and endurance remain
open. Resource snapshots and emulator passes do not close these gates.
The complete REC-01..06 / AC82..90 scope is retained; no remote policy can disable
local Stop, hard limits, ownership fences or authorization checks.

## M2 - identity and provisioning (pilot implemented, milestone open)
OIDC/PKCE/DPoP, Keystore identity, SQL device sessions, separate API/publisher,
signed assignments, cache/lease/refresh/revoke and transactional rollback have
pilot code and tests. Remaining work includes release QR/manual invitations,
managed overlay credential namespaces/retirement, signed route-check activation,
rotation and full end-user/operational acceptance.

## M3 - engines, sources and administration (partial foundation)
Embedded engine adapters exist. A [read-only Remnawave resource pilot](remnawave-resource.md) adds a scoped HTTPS reader/owner CLI; persistent resource sync and publication remain open. Subscription adapters,
complete protocol/chain acceptance, mobile edit/publish and the full responsive
administrative frontend remain open. The existing support-chat web service is not
the full panel. Multiple Remnawave/x-ui/3x-ui are extension contracts only.

## M4 - autonomous routing and support (partial)
Reference ranking and bounded per-target checks exist. Basic SQL user/admin chat,
Android/web UI and device media compression have scoped acceptance. Full contextual
quarantine/graph exploration for four network modes, cohort rollout, central
telemetry/incident analysis and operational retention controls remain open.

## M5 - version1.0 acceptance (open)
Complete security, update/migration/restore, real network, battery and endurance
evidence plus production operations are required. Continuing independently testable
M2/M3 work does not waive the remaining M1 or release gates. Production deployment
and enrolling real users are separate operations. Every implementation PR updates
the register with concrete scope and evidence; no percentage is inferred from CI.
