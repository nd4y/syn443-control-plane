# Public source and private operations

Only source code, synthetic fixtures, public specifications and sanitized CI evidence belong here.
Device identifiers, enrollment/setup keys, provider subscriptions, internal names/addresses,
user telemetry, phone backups, real diagnostic bundles and signing material stay outside GitHub.
Use GitHub noreply email for commits. Never paste device output into issues or CI inputs.

Before publication, all reachable source history, GitHub discussions and delivery assets are reviewed.
The privacy gate checks history, deleted files, author emails and selected artifact payloads.
Gitleaks uses pinned, checksum-verified binaries and default secret detectors. Its exceptions
are exact reviewed public OpenAPI content digests in the contract lock file and one synthetic public-key thumbprint, each scoped to its value/path. Recursive hex decoding remains enabled; Go/Kotlin derive that thumbprint from the public SPKI fixture, and scanner tests reject a changed value or another path. No directories or commits
are excluded from secret scanning. Detection logs redact values.

All PRs and main runs must pass `public-data`. Artifact uploads must pass payload checks;
delivery failures now fail CI. Use only explicit artifact paths, never whole working directories
or device logs. Keep raw physical-device evidence in private operator storage and publish only
a reviewed summary without identifiers. A green scan cannot prove there is no private data:
human review remains required, and any exposure requires removal and credential revocation.

Local history preflight: `python3 tools/check_public_data.py --history` and
`bash tools/scan_secrets.sh`. Run the same payload checks before manual release uploads.

Before development, install local guards with `git config core.hooksPath .githooks`.
Python 3 and Gitleaks 8.30.1 are required. Optional machine-local Git config keys
`syn443.python` and `syn443.gitleaks` select executable paths without storing them in source.
Pre-commit inspects the actual staged bytes; pre-push checks all reachable history.
Missing scanners fail closed. Hooks are a local safeguard, not a server-side access boundary.
CI tests that each exact digest exception accepts its reviewed value and rejects changed
values or the same value at another path.

The credential URL check recognizes finite exact Go read-only data layouts in the
Linux ELF runtime. Their adjacent eight-byte literals come from Go 1.27.4
(`regexp/backtrack.go:168`, `net/textproto/reader.go:838`,
`crypto/internal/fips140/pbkdf2/cast.go:33`, `crypto/x509/pem_decrypt.go:105`),
jsonschema v6.0.3 (`draft.go:145`), pgx v5.11.0 (`pgconn/config.go:125,504,714,716,723`,
`pgconn/defaults.go:58`, `pgconn/errors.go:245`) and, for the overlay worker,
four public identity field names in `internal/overlay/identity.go`.
The check requires the three pinned version markers and the complete match,
including the prefix that begins before the URL match. Other credential matches
and all other privacy and secret checks still run. Changes to the sequence or
dependencies require fresh provenance before updating the rule.

The enrollment worker has two separately bounded layouts. The 208-byte layout
starts with the public HTTP status literals `Continue`, `Accepted`, `Conflict`
(`net/http/status.go:84,96,146`). The 192-byte layout, observed in the original
Actions 43842084651 compiled diagnostic, starts with `bad inst` and `https://`.
Its URL regexp match starts at byte 4, so the predicate also verifies the four
preceding bytes. Both layouts contain the exact public eight-byte literals
`username`, `password`, `insecure`, `short_id`, `security`, `protocol`, `settings`,
`Settings`, then `host-key` or `host_key`, then `short-id`, then each of
`audience`, `ownerTag`, `deviceId`, `provider` exactly once, and the fixed pgx/Go
suffix without a second `password`. In the 192-byte layout the prefix ends at 80,
the host spelling at 88, `short-id` at 96, the overlay fields at 128 and the suffix
at 192. No other bytes or lengths are accepted.

The repository literals are defined in `internal/subscriptions/import.go`
(`308,381,426,600`), `internal/subscriptions/xray.go` (`19,177`),
`internal/subscriptions/yaml.go` (`137,180`) and `internal/overlay/identity.go:98`;
`protocol` comes from Go's `net/http/internal/http2/server.go:2124`. The new
layout reuses the same pinned dependency/toolchain provenance above. Tests cover
all 48 host/overlay arrangements, mutation of each of the 192 bytes including the
pre-match prefix, missing or wrong build markers, non-ELF/source text, duplicate
fields and extra adjacent bytes. Separate real credential URIs remain detected
on both sides of C0/DEL separators and of an accepted public sequence.

The independent configuration-worker artifact has one additional exact 160-byte
layout, observed in the sanitized compiled diagnostic from
[Actions 43846630571](https://github.com/nd4y/syn443-control-plane/actions/runs/43846630571).
Its 156-byte regexp match is preceded by the four public bytes `bad `, giving the
same complete 80-byte `bad inst`/`https://`/subscription-field prefix used above.
After `host-key` or `host_key` and `short-id`, it joins directly to the same fixed
64-byte pgx/Go suffix. The overlay identity fields are dead-stripped in this
separate executable; no optional fields or unspecified bytes are accepted by
the 160-byte alternative. The complete span is checked from four bytes before
the match through its end: prefix 0..80, host 80..88, short-id 88..96, suffix 96..160.
Every byte has the same public source provenance listed above; toolchain and
both dependency markers remain mandatory and unchanged. Tests cover both host
spellings, mutation of all 160 positions including the pre-match prefix,
missing/wrong markers, non-ELF/source text, inserted fields, modified suffix and
extra `@` text. Separate real credential URIs remain detected on both sides of
every C0/DEL separator. The 208-byte and 192-byte rules are unchanged.

APK payloads are additionally scanned as ZIP containers: Gitleaks otherwise skips the
binary `.apk` file. The real scanner self-test checks both a clean APK and detection
inside an embedded synthetic asset. Upload allowlists match the scanned report paths.

Go 1.27.4 provenance was rechecked from the exact Actions compiled-URL
diagnostic and the public source locations above. All layouts retain both
dependency pins and the single accepted toolchain marker, 1.27.4; both the
previous 1.27.3 marker and future versions fail
closed. Arbitrary userinfo, modified suffixes and extra adjacent bytes remain
mandatory negative cases.
