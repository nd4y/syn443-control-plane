# M0 implementation status
Implemented:
- Contract0.1.0, strict bounded integer/JSON parsing, 28 valid and12 invalid shared vectors.
- Go and Kotlin deterministic route selection: eligibility, six-field context, freshness, stability/energy/latency/confidence/ID.
- Synchronized coordinator model: desiredOn, Stop precedence, network/activation/engine generations and overflow rejection.
- Go loopback-only side-effect-free preview HTTP API; no authentication placeholder and no network probing.
- Android Compose diagnostic shell consuming the same fixture, with UI automation for Stop and stale network completion.
- CI unit/permutation/concurrency/fuzz/HTTP/schema/coverage, Android JVM/lint/APK/emulator gates.

Partial requirements: ARC-03, ARC-07, ENG-01, ENG-06; AC66 is only M0 conformance, not complete evaluator acceptance.
Not implemented: VPN/TUN/native host, actual health collection, path graph enumeration, hysteresis/quarantine, provisioning/auth/signing, storage/jobs, provider adapters, telemetry and full frontend.
Physical ARC-02 gate is pending. No app installation or settings changes on the user's phone have occurred.
M0 is not a production release; do not distribute it as a working VPN.

The preview API runs on an explicit loopback IP only. It accepts synthetic measured data and never fetches URLs.
GET /healthz returns productionReady=false; POST /v1/decision-preview is capped at1MiB.
No credentials, remote code or arbitrary probe destinations are accepted.
Contracts are owned by control-plane and vendored in Android with identical bytes and SHA256 lock.
Record the upstream commit in Android's lock when importing an approved snapshot; CI never uses a broad cross-repository token.

