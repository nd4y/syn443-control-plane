# Testing and release gates
All automatable implemented behavior must run on pull requests and main in GitHub Actions.
- Documents: source hashes, 270 unique requirements, 80 unique sequential scenarios, traceability/evidence integrity.
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
