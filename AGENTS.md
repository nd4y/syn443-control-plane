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

## Repository development standard

Follow .standards/rules.en.md or .standards/rules.ru.md and the profiles in .repo-policy.json. Preserve existing project-specific instructions and CI. Read docs/en/development-standard.md or docs/ru/development-standard.md for setup. Run node .standards/check.mjs staged before commit and use the repository-standard CI result for the complete PR. Update both configured README files and both documentation languages in the same PR. Do not weaken checks, broaden permissions or report unverified product evidence as complete. Use a branch and PR; merge remains the owner's action unless explicitly authorized.
