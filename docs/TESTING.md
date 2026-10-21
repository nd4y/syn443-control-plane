# Testing and release gates
All automatable implemented behavior must run on pull requests and main in GitHub Actions.
- Documents: source hashes, 277 unique requirements, 90 unique sequential scenarios, traceability/evidence integrity.
- Contracts: strict schema validation, shared fixtures, unsupported fields/versions and bounded numeric inputs.
- Go: unit, property/permutation, fuzz seed/smoke, race detector, vet, coverage and HTTP boundary tests.
- Android: same fixtures on JVM, lifecycle/state tests, lint, APK build and connected instrumentation on emulator API 29 and 35.
- Cross-platform: identical fixture bytes and SHA lock; server/client expected route and explanation agree.
- Later: Postgres migrations/transaction races, job retries, provider fixtures, browser UI/API E2E, fault/load/security checks as components arrive.

Physical-only release gates: real restricted LTE, RF handover, vendor power management, measured idle energy, external-provider availability and long endurance.
CI must list these as pending rather than skip them and report success.
Coverage applies to implemented code; line coverage alone is not behavioral coverage.
All fixtures use synthetic endpoints, identifiers and secrets. No real provider credentials are needed in CI.
Every later feature PR updates requirements-register with scope and concrete evidence.

M1 recovery gates (REC-01-06 / AC82-AC90) remain planned. At implementation, deterministic model/trace tests and Android fault injection must cover durable intent/config, exponential backoff/jitter and flapping, Stop/stale effects, optional-outbound partial startup without private leaks, full native hang and controller/service death, truthful status with detailed logs disabled, and persisted budgets across restart/reboot/clock changes. Physical Pixel evidence separately covers Wi-Fi/LTE/restricted LTE, actual OS restart/Force stop/revoke/Always-on behavior, Doze and energy. A live control looper, a JVM timeout, or process isolation alone does not prove these gates.
