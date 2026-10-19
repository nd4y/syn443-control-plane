# CI evidence delivery
All test/build/lint/fuzz/race/security gates are mandatory. Artifact upload is a separate delivery step, allowed to fail with a visible job summary when GitHub storage quota is exhausted.
This does not skip tests, allow empty JUnit evidence, or accept missing APKs. Test logs remain in Actions. Private prerelease assets provide a separate reviewed delivery path.
GitHub returned403 for protected main on this account's private repositories: Pro is required. Repositories remain private, no billing change or cleanup of unrelated artifacts is authorized. Until protection is available, only merge PRs after all mandatory checks pass.
Physical cellular/Doze/energy/native-host gates remain pending and cannot be inferred from CI.

