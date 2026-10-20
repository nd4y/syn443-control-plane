# Public source and private operations

Only source code, synthetic fixtures, public specifications and sanitized CI evidence belong here.
Device identifiers, enrollment/setup keys, provider subscriptions, internal names/addresses,
user telemetry, phone backups, real diagnostic bundles and signing material stay outside GitHub.
Use GitHub noreply email for commits. Never paste device output into issues or CI inputs.

Before publication, all reachable source history, GitHub discussions and delivery assets are reviewed.
The privacy gate checks history, deleted files, author emails and selected artifact payloads.
Gitleaks uses pinned, checksum-verified binaries and default secret detectors. Its only exception
is one exact public OpenAPI content digest in the contract lock file. No directories or commits
are excluded from secret scanning. Detection logs redact values.

All PRs and main runs must pass `public-data`. Artifact uploads must pass payload checks;
delivery failures now fail CI. Use only explicit artifact paths, never whole working directories
or device logs. Keep raw physical-device evidence in private operator storage and publish only
a reviewed summary without identifiers. A green scan cannot prove there is no private data:
human review remains required, and any exposure requires removal and credential revocation.

Local history preflight: `python3 tools/check_public_data.py --history` and
`bash tools/scan_secrets.sh`. Run the same payload checks before manual release uploads.
