# CI evidence delivery
All test/build/lint/fuzz/race/security gates are mandatory. Artifact upload is a separate delivery step, allowed to fail with a visible job summary when GitHub storage quota is exhausted.
This does not skip tests, allow empty JUnit evidence, or accept missing APKs. Test logs remain in Actions. Private prerelease assets provide a separate reviewed delivery path.
Both SYN443 repositories are public by owner request. Public source and artifact privacy gates are mandatory. Branch protection capability must be checked separately; no billing change or cleanup of unrelated artifacts is authorized. Merge only after mandatory checks pass and the owner authorizes the merge.
Physical cellular/Doze/energy/native-host gates remain pending and cannot be inferred from CI.

