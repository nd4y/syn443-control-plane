# Read-only native owner-grant fingerprints

`enrollment-admin fingerprint-grants` reads the ordinary grant JSON array from
stdin and emits only fingerprints and access metadata. This is a separate
read-only command for deployment preflight. It does not call `authorize`, open
a database, run migrations, read a configuration path or obtain input from an
environment variable. Every other CLI command retains its existing behavior.

The exact command accepts no flags. Input is limited to524288 bytes and1..16
closed native `enrollment.Grant` documents, using the same strict operator
decoder and full `Grant.Validate` rules. The live clock is observed only after
the complete bounded stdin snapshot. Unknown/duplicate fields, invalid grants,
expired access, duplicate native owners and trailing documents fail before any
stdout write. Owners and grant hashes use the actual `enrollment.Owner` and
`Grant.Hash` functions; there is no external hash reimplementation or SQL input.

The complete output is buffered before its single write and is at most16384
bytes, with this closed shape:

```json
{"version":1,"grants":[{"owner":"<native-owner>","enabled":true,"deviceLimit":2,"validUntil":1800003600,"grantHash":"<native-grant-hash>"}]}
```

`validUntil` is in Unix seconds. Rows retain the input array order. Output never
contains the template, issuer, subject, raw grant input, signing keys or input
errors. All failures return the generic finite CLI failure. An OS write error
or short write can leave partial stdout; a nonzero exit makes **all stdout
invalid** and preflight must discard it. Validation failures emit no prefix.
Operator output can still identify private account rights and must remain in
the scoped private preflight evidence, outside public artifacts and source.

A matching fingerprint is a read-only observation. It does not prove that the
live database account is unchanged, that every migration is idempotent, or
that rerunning an owner initialization is safe. The existing `authorize`
command can upsert account rights from its input; preflight must not execute
it merely to compare grants. Current database metadata, migration ownership
and any authorized writes have their own independent checks and permissions.

## Mandatory evidence and limits

Six tests in `cmd/enrollment-admin/grant_fingerprint_test.go` cover native
hash/owner equivalence and closed metadata, strict fields/expiry/templates,
byte/count/trailing-data bounds and post-read clock, duplicate owners, atomic
validation plus finite I/O errors, and the actual early command with unavailable
configuration paths and no database dependency. The actual command test owns
its process arguments and standard streams and does not run in parallel.
All fixtures are synthetic; no operator files or deployed database are used.

`tools/check_grant_fingerprint_evidence.py` consumes the existing
`exit-country-core-tests.jsonl` from the complete ordinary Go race suite. It
requires the exact six source names, exact `cmd/enrollment-admin` package, one
ordered run/pass per root and one package completion. Any failure, skip or
error in that package is rejected; unrelated package success cannot substitute
for a required root. The complete Go command still retains shell `pipefail`
and its original suite-wide failure behavior. Five validator unit cases reject
missing/repeated/out-of-order roots, substituted packages, malformed JSON and
source-name drift.

The existing JSON privacy/secret scans, artifact flow, eight runtime builds,
resource limits and all other CI gates are unchanged. No new job or operator
output artifact is added. Current status is source-pending: Actions, the exact
built binary and the separate read-only operator preflight still require their
own evidence. This command does not establish a deployment or account change.
