# Implementation roadmap
## M0 - contracts and executable reference core
Normative bounded decision inputs/results, reference ranking, context generations, cancellation/Stop precedence, shared Go/Kotlin fixtures.
A buildable Android diagnostic shell and CI tests are deliverables, not proof of VPN connectivity.
## M1 - physical Android vertical gate (ARC-02)
Single VpnService/TUN owner and isolated native host; direct path, two-hop ingress/exit, NetBird/internal probe.
Real Wi-Fi/cellular handover, fault attribution, native hang/crash, offline config recovery and energy budgets.
Required before the full panel: REC-01-06 / AC82-AC90. Persist desiredOn/config/intentGeneration across UI, tile, notification and API; reconcile with bounded exponential backoff/jitter and shared budgets. Stop fences every pending/current effect. Prove optional-outbound startup/recovery without private-route leaks, full native hang detection, controller/service death and exclusive TUN/identity ownership. Validate reboot/unlock, Force stop, revoke, competing VPN, Always-on/lockdown and truthful per-route status with minimal redacted events.
At implementation, every reproducible scenario runs in GitHub Actions with controlled clock/jitter/fault injection; actual Wi-Fi/LTE/restricted LTE, Doze, OS behavior and energy budgets require separate Pixel evidence. These requirements are planned; the existing JVM fence and responsive-control process harness do not implement them.
Do not build the full panel before this gate proves feasibility.
## M2 - identity and provisioning
Keycloak/QR device enrollment, DPoP, signed bundles/trust/lease, transactional activation, revoke/rollback and durable jobs.
## M3 - engines, sources and administration
All required proxy protocols, one Remnawave API adapter, subscription adapters, mobile editing/publication and responsive frontend.
## M4 - autonomous routing and support
Contextual quarantine, bounded graph exploration, per-route health plans, budgets, redacted diagnostics/incident pipeline, cohort rollout.
## M5 - version 1.0 acceptance
All required scenarios, restore/update/migration, security and physical reliability evidence.
A green M0 CI does not satisfy M1-M5.
