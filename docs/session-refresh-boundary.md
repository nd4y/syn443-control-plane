# Absolute refresh-family boundary

The device client requires `accessUntilMs <= refreshUntilMs`. A refresh family
has an absolute deadline created during enrollment; rotating its tokens does
not move that deadline.

The previous refresh mint capped access at the earlier of `now + 600 seconds`
and the current account deadline. It omitted the current refresh-family
deadline. In the final ten minutes of a still-live family, a successful refresh
could therefore return a session that the strict client correctly rejected.
For a synthetic example, 528 seconds remaining in the family and a 600-second
access lifetime would put access expiry 72 seconds after refresh expiry.

The correction caps newly minted access expiry at all three values:

```text
min(now + 600 seconds, current account deadline, current refresh-family deadline)
```

The family deadline comes from the session row reread under the existing
account/device/session locks. A stale caller `Binding` cannot supply it. Expired
accounts or families are still denied before rotation. Refresh expiry, token
rotation, generation increments, proof/nonce checks and exact same-request cache
replay retain their existing behavior. The change does not extend any lifetime
or repair a bad response already stored in the replay cache.

If an affected client already requires authentication, use its supported
explicit VPN Stop and same-account browser sign-in flow. That flow preserves
the device key and binding. Clearing application data or replacing device keys
is unnecessary. The mint correction alone is not evidence that an existing
client session has recovered.

## Mandatory evidence

`internal/enrollment/session_boundary_postgres_test.go` has six closed root
cases. The existing disposable PostgreSQL fixture tests the last seconds and
ten-minute boundary, a live locked deadline versus a stale lookup, a shortened
account, at/past-deadline denial without mutation, byte-exact early/late cached
replays, and repeated fresh rotations without extending the family. Fixture
owner SQL only prepares synthetic account/deadline state; registration and
refresh use the restricted API role with real signed proofs.

The existing enrollment Actions job captures the actual `go test` JSON stream
with `GOFLAGS=-json` and shell `pipefail`. The source-bound
`tools/check_session_boundary_evidence.py` requires all six enrollment roots to
run and pass exactly once, followed by one enrollment-package completion. It
rejects substituted packages, repeated/out-of-order roots, any failed/skipped
test or package, malformed metadata and evidence errors. Its five unit cases
also check missing outcomes, source-name drift and duplicate JSON fields.
The JSON log and ordinary coverage file pass the existing public-data and
secret scans before the existing artifact is uploaded. No new job or relaxed
resource, race, timeout, role or coverage limit is introduced.

Current status: source inspection and formatting only. Actions execution,
server deployment and supported client recovery are separate pending stages.
These synthetic tests do not establish the delivery or rejection history of
any particular refresh response.
