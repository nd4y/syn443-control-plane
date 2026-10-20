# SYN443 development rules
Read docs/spec/TECHNICAL_SPEC_RU.md, docs/ROADMAP.md and docs/TESTING.md before changes.
Preserve all version 1.0 scope. Mark partial work honestly in requirements-register.
No production secrets, setup keys, real subscription URLs, phone backups or private network identifiers in fixtures.
Every implemented path needs meaningful positive, negative and boundary checks in GitHub Actions.
Never equate emulator tests with physical cellular/Doze/battery acceptance.
Keep policy safety invariants local, bounded and deterministic. No remote executable policy.
Do not deploy, enroll real users or alter production infrastructure as part of CI.
Use separate branches and pull requests for changes after the initial bootstrap.
Pin dependencies/actions. Do not weaken checks to make CI pass.

Public repository: follow docs/PUBLIC_DATA.md. Keep all device/provider/user data outside the repository, issues, Actions and releases. Run privacy/secret checks on history and upload payloads. Never bypass these checks or log finding values.
