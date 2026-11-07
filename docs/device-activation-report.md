# Device activation reports

`POST /v1/device/policy/status` accepts a bounded JSON report over the existing
device DPoP session. The report contains `version` (1), `policyRevision`,
`envelopeHash` (base64url SHA-256 of the exact signed response),
`activationGeneration`, `outcome` and `activePolicyRevision`. The outcome is
`committed`, `degraded` or `rolled_back`. A rollback reports the selected prior
journal revision, or zero if there was none. The selected revision describes
the activation decision at that time. Current traffic and lease status require
separate evidence.

The API locks the account, device and session and repeats expiry, key, nonce,
replay and request-body checks. It accepts only the current configure envelope
for the same device, key and account grant, with a valid signature and lease.
A newer publication invalidates reports for a superseded envelope. An exact
report retried with a fresh proof receives the same HTTP 204 outcome. A different
report for the same publication conflicts.

SQL retains one bounded observation per device with the server receipt time.
The publisher role cannot write it. The report carries no endpoint, test body,
token or user traffic. It grants no authority and cannot alter a desired head,
lease, publication or rollback decision. The status is supplied by the device
and does not attest to traffic independently of the device.

PostgreSQL tests cover a real signed delivery, valid device proof, proof replay,
changed body, wrong key and nonce, unpublished and superseded revisions,
idempotency, conflicting outcomes and rollback without a publication rewrite.
Android reporting and the administration view still require integration and
their own acceptance.
