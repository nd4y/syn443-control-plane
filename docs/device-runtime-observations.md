# Device runtime observations

This is a separate, bounded device observation. A historical activation report
keeps its original meaning and is never reused as a current-online heartbeat.

`POST /v1/device/runtime` uses the existing device DPoP session, nonce, body binding,
replay protection and locked live account/device/session checks. A report has
version1, a persistent per-key sequence, build, phase, active policy revision,
engine-known/active flags, the coarse network class and a sample timestamp from
the client's conservative server-time model. It contains no device
identifier, wall-clock timestamp, free text, address, profile name or credential.
The authenticated session supplies identity. The body limit is1024 bytes.

SQL stores only the latest observation per device. An exact sequence/body retry
is acknowledged without changing receipt time. Changed or regressing sequences
conflict. New observations are limited to one per30 seconds. Server receipt time,
not the device wall clock, determines age. A sample older than120 seconds or more
than30 seconds ahead conflicts; a queued old body cannot become a fresh state by
merely obtaining a new proof. Freshness ends at the earlier of sample/receipt
plus180 seconds. The API cannot edit policy or ACLs and the
publisher cannot write observations. The active device key must match.

`configuration.runtime.get` uses the same live per-device read ACL as the card.
It locks and rechecks device/account/grant authority and audits the read. Responses
distinguish no observation, one received within180 seconds and an older observation.
The console labels this as **reported by the client**, with server receipt time;
it does not independently attest to current traffic or route health. The UI ages
the observation using elapsed time and removes it on a denied/changed selection.
Its [bounded foreground refresh](runtime-console-refresh.md) fetches later reports
while the selected card is visible. A read never renews the stored receipt.

The Android sender must reuse the existing supervisor and account transport,
send at most once per60 seconds, retain a single durable pending operation and
sequence, retry unchanged content with a fresh proof, and preserve Stop/account
generation fences. No new background timer, probe or wake lock is introduced.
Unsupported servers back off; missed reports become stale rather than implying
that a device is online. A stopped/background-suspended client need not emit a
final report. SQL retention is one latest row per registered device; revocation
is checked independently on every write/read.

Required acceptance: strict positive/negative/boundary wire tests, actual SQL
scope/replay/idempotency/rate/key/expiry/rollback/role tests, named browser
fresh/stale/unknown/substitution/denial cases, Android durable queue and cancellation
tests, exact Actions matrices and a private Xperia USB/Wi-Fi report/readback check.
The additive schema and transport remain unaccepted until those checks pass.
Rollback restores prior executables; the additional bounded table can remain
unused. The migration must not rewrite policy, account, session or activation data.
