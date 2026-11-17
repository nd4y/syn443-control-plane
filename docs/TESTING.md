# Testing and release gates

The [refresh-family boundary correction](session-refresh-boundary.md) adds six
mandatory PostgreSQL roots in the existing enrollment job. Its actual Go JSON
stream must contain each exact enrollment-package run and pass once, one package
completion, and no failure, skip or error. Five validator unit cases run in the
existing documents job. JSON and coverage evidence retain the privacy/secret
scans before upload; race, timeout, role and coverage limits are unchanged.
Source is ready; execution, deployment and client recovery remain pending.

Operation-reconciliation candidate: the existing disposable catalogue and provisioning PostgreSQL jobs must provide all28 named outcomes (5 catalogue,23 provisioning), checked by `tools/check_operation_reconcile_evidence.py`. Its6 validator unit cases run in the existing documents job. These are pending source gates. Existing race, coverage, privacy, quota, HTTP and worker checks remain mandatory; no live database or client activation runs in CI. See [operation outcome reconciliation](operation-outcome-reconciliation.md).

Protocol eligibility source candidate: `tools/check_operation_version_evidence.py` requires14 exact package/source-bound outcomes:7 normal roots from the existing complete Go race JSON,4 provisioning PostgreSQL roots and3 catalogue HTTP/PostgreSQL roots from their existing JSON streams. Each root needs one `run` then one `pass`, and its package must complete successfully once; failure, skip, error, missing/renamed/duplicate/late outcome or foreign package cannot substitute. Six validator unit cases run in the existing documents job, including source-name drift and malformed evidence negatives. No job, product test command, runtime limit, upload or privacy/coverage guard is relaxed. All14 actual outcomes and validator cases remain pending Actions. The read's owner declaration is eligibility only, never deployment proof or permission; retained pending versions stay immutable. See [service protocol eligibility](operation-outcome-reconciliation.md#service-protocol-eligibility---source-pending).

The [public Go layer-wire fixture](layer-wire-fixture.md) adds six mandatory
source-bound race outcomes before generating a separate synthetic artifact.
Actual Go Marshal/production hash and merge/decode/compile results preserve raw
parent layer bytes for native-editor interoperability; no live API, user rights
or configuration changes are included. New fixture execution is pending Actions.

The optional [public signed-service discovery](service-discovery.md) source adds
five bootstrap and two enrollment-API roots. Both the complete race JSON stream
and a separate ordinary targeted JSON stream must contain each exact package/test
run and pass once, both package completions, and no failure or skip in either
package. The checker locks its required names to the two source files; negative
checker cases run in the documents job. Both evidence payloads retain the
existing always scan/archive flow, and the bootstrap85% coverage gate remains
unchanged. Source is pending Actions, deployment and Android integration; these
tests do not establish production root custody, native SSO, MFA or role grants.

The [independent configuration worker](configuration-worker.md) adds eleven named
core/runtime outcomes and two actual PostgreSQL roots to the mandatory adaptive
evidence gate. PostgreSQL checks exercise original TLS/OIDC/DPoP/MFA receipts,
wrong SQL roles, live source/ACL fences, unchanged approved-device lease renewal
and separate desired-head publication. The separate worker binary has its own
Actions artifact, source/hash manifest and privacy/secret payload gates. Synthetic
tests do not establish a deployed administrator session or phone activation.

The PatternFly support workspace adds seven mandatory browser cases, bringing
the required floor to79 without dropping any of the original72. They cover
hostile text, a full25MiB upload/verified download, lost send acknowledgement,
separate chat-role withdrawal, late response cancellation on logout, visible-only
failure backoff and a narrow empty/oversize-file state. The standalone chat runs
through the same controller and retains all five original transfer/access cases.
Only syntax/diff inspection is local; executable suites and builds run in Actions.

Console/chat integration adds actual proof/nonce HTTP boundaries for two pinned
API origins and default-disabled chat forwarding. A separate80% owner-grant gate
covers owner-only web accounts, zero-device enrollment denial, idempotent grant
replay, CAS races, live withdrawal and transaction rollback on audit failure.
The original1..16 database constraint is migrated in the real PostgreSQL test;
normal device grants remain1..16. Console chat UI and actual deployment remain
open until their own browser/live acceptance.

Separate chat administrator issuers are covered by three required configuration
and signed-token cases in `internal/enrollment/chat_provider_test.go` and the
PostgreSQL `TestChatAdminAuthorityCannotCrossIssuersWithTheSameSubject` case.
They retain single-issuer discovery, separate client/audience, DPoP and live SQL
authority. Exact-head Actions and live pilot integration remain required.

Device discovery adds required PostgreSQL scope/expiry, pagination, redacted
metadata, activation-versus-connectivity, audit failure and authority expiry
under a real row lock. Four mandatory browser cases cover ordinary selection,
explicit pagination on a narrow screen, atomic rejection of invalid responses
and state erasure on withdrawal/expiry with manual-lookup fallback. See
[the discovery contract](device-inventory.md). These do not close full M2/M3.
All automatable implemented behavior must run on pull requests and main in GitHub Actions.
- Documents: source hashes, 292 unique requirements, 98 unique sequential scenarios, traceability/evidence integrity.
- Contracts: strict schema validation, shared fixtures, unsupported fields/versions and bounded numeric inputs.
- Go: unit, property/permutation, fuzz seed/smoke, race detector, vet, coverage and HTTP boundary tests.
- Android: same fixtures on JVM, lifecycle/state tests, lint, APK build and connected instrumentation on emulator API 29 and 35.
- Cross-platform: identical fixture bytes and SHA lock; server/client expected route and explanation agree.
- Later: Postgres migrations/transaction races, job retries, provider fixtures, browser UI/API E2E, fault/load/security checks as components arrive.

Physical-only release gates: real restricted LTE, RF handover, vendor power management, measured idle energy, external-provider availability and long endurance.
CI must list these as pending rather than skip them and report success.
Coverage applies to implemented code; line coverage alone is not behavioral coverage.

Portable managed NetBird adds required Go compilation and PostgreSQL publication
cases described in [its scope and limits](portable-netbird.md). The regular race,
fuzz and configuration85% gates remain unchanged. These cases exercise direct and
VLESS composition, internal DNS, invalid branches/authority fields, missing broker
retention and stable addressed enrollment reference across transport changes.
All fixtures use synthetic endpoints, identifiers and secrets. No real provider credentials are needed in CI.
Every later feature PR updates requirements-register with scope and concrete evidence.

The mandatory `keycloak` Actions job uses a digest-pinned temporary IdP and generated fixture credentials. It validates the isolated test-realm representation and real authorization-code/PKCE, token verification, disabled grants and refresh-replay behavior. See [scope and limits](keycloak-test-realm.md); it does not close Android enrollment, API authorization or the M2 provisioning gate.

M1 recovery gates (REC-01-06 / AC82-AC90) have partial cross-repository implementation and scoped acceptance; see [current evidence](implementation-status.md). Implemented paths require deterministic model/trace tests and Android fault injection must cover durable intent/config, exponential backoff/jitter and flapping, Stop/stale effects, optional-outbound partial startup without private leaks, full native hang and controller/service death, truthful status with detailed logs disabled, and persisted budgets across restart/reboot/clock changes. Physical Pixel evidence separately covers Wi-Fi/LTE/restricted LTE, actual OS restart/Force stop/revoke/Always-on behavior, Doze and energy. A live control looper, a JVM timeout, or process isolation alone does not prove these gates.

M2 identity/enrollment pilot: see [scope and evidence](enrollment-pilot.md). Actions must run strict OIDC/DPoP crypto and schema tests, real temporary PostgreSQL role/transaction races, Keycloak code/key/refresh conformance, and the Android identity JVM suite with its 90% protocol-class line gate. These do not establish Android browser enrollment or physical policy activation. Raw operator identity/device evidence is never an upload payload.

The enrollment job includes the [isolated PostgreSQL restore drill](database-recovery.md).
Its dump is temporary and must not be uploaded.

The telemetry web console requires PostgreSQL tests for exact grant, wildcard
denial, revocation and read audit, a BFF scope test, and Playwright tests for
populated/empty/mismatched reports, session expiry and preservation of unrelated
drafts on a scoped denial. The browser fixture contains only synthetic counts.

The control console uses the pinned PatternFly React and React packages in
[console-ui](../console-ui/package-lock.json). GitHub Actions installs the lock
and runs the console bundle before embedding it in support-chat-web and before
the Chromium suite. The control-console-ui artifact records the exact source
revision and SHA-256 checksums of the embedded JS, CSS, fonts and images. The
browser gate covers same-origin resources, isolated sections, browser history,
focus and preservation of unsaved drafts across navigation.

The [control reauthentication recovery](control-session-reauthentication.md)
requires scoped PostgreSQL no-mutation/withdrawal tests, owner-bound callback and
logout-race checks, and five named browser outcomes. All59 existing and new
browser cases must pass without skips. A fresh-MFA challenge preserves an exact
pending operation; explicit retry still passes all live authority checks.

[Runtime observations](device-runtime-observations.md) add mandatory strict wire/fuzz,
actual device-session/SQL rollback/idempotency/rate/role and scoped-reader expiry
checks. All64 browser outcomes must pass, including five named runtime cases.
The [foreground refresh follow-up](runtime-console-refresh.md) adds five required
clock-driven cases plus three shared-request timeout cases (72 total), including immutable receipts, hidden/section/session
fences, timeout and late-selection response rejection. Ingestion and the new reader each require80% coverage. No phone heartbeat or
independent traffic attestation is established by these synthetic server/UI tests.
