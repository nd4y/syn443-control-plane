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
pilot code and tests. Manual invitations use independent approval and the
normal device session. The control plane can build a static HTTPS landing page
and sign an installation profile offline. The managed overlay broker and the
signed activation report have scoped SQL acceptance. Full physical enrollment,
public-domain association, root rotation and live managed overlay acceptance
remain open.

## M3 - engines, sources and administration (partial foundation)
Embedded engine adapters exist. The scoped [Remnawave reader](remnawave-resource.md)
now has a [persistent catalog/API and independent source worker](control-catalog.md),
multi-format normalization, recipient CAS and quarantine review. A bounded
[layer/rebase component](layered-configuration.md) preserves field ownership.
The publisher compiles approved network layers, binds the signed issuance to
the desired revision and displays the device report separately. Source jobs
have bounded expiry processing and staggered retries. Device fetch, full
settings coverage, complete protocol/chain acceptance, native editing and full
administration remain open. Multiple Remnawave/x-ui/3x-ui remain extension contracts.

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
