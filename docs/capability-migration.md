# Independently approved device capabilities

The original approved enrollment request and receipt remain immutable. A fresh
login with a different set receives409 `capabilities_update_required`; it cannot
replace that evidence, mint an extra session on conflict or upgrade itself.
Capability availability does not widen an account grant or publish a VPN policy.

`GET /v1/device/capabilities` authenticates the current key-bound device session.
`GET /v1/devices/capabilities` authenticates fresh enrollment-audience OIDC proof
for the same already approved key/account. Both return the current capability
version/hash/set and an opaque authority binding. Version0 is derived from the
original approved request. Neither endpoint accepts a target device/owner URL.

POST to the same endpoint submits closed `requestId`, `previousHash` and
`capabilities`. The set must retain all currently approved features, contain the
three base capabilities, and have at most16 distinct bounded names. Reordering
and an already aligned set do not create another version. A changed request
under the same ID conflicts; a lost acknowledgement returns the original result
after authentication/live scope is checked again. Only API request columns are
writeable; approval heads and histories are not.

The API stores the original body and encrypted proof receipt with a maximum
180-second deadline, bounded by the current session/OIDC/account lease. The
publisher independently rechecks the exact POST/URI/body/token/key/nonce proof,
original grant and current account/device authority. OIDC verification occurs
outside SQL locks. The final transaction locks current authorization, immutable
request and head, repeats the prior-hash CAS, then atomically writes immutable
capability history/head, schedules ordinary policy renewal and marks the request
approved while erasing its credential receipt. Transient verification/storage
failure retains bounded pending evidence; deterministic denial clears it.

Device-session approval uses a narrow owner-defined boolean SQL fence. It locks
and checks exact session/device/generation/access-token digest, nonce and expiry, without
returning session hashes or granting publisher table access or minting rights.
The function has a fixed `pg_catalog` search path, fully qualified SQL and no
dynamic SQL. PUBLIC/API cannot execute it. Startup rejects additional publisher
session-read privileges or API approval/fence privileges. Migrate owner schemas
and roles before starting the updated binaries; runtime never self-migrates.

Pending requests are limited to4 and retained request receipts to64 per device.
Expired queued requests are rejected and credentials erased; terminal metadata
is cleaned after24hours in bounded batches. Strict capability additions imply at
most13 approved versions. Historical availability is non-secret and immutable.
Current head/version/hash/canonical-body corruption fails closed. Original
enrollment evidence, local device keys, sessions and native VPN intent are not
rewritten by an upgrade. Ordinary renewal and actual configuration previews use
the approved availability set, while all existing grant/source/activation gates
still apply. A capability approval is not a device activation acknowledgement.

New tests cover 3->4->5, equivalent ordering, lost replies, stale CAS/downgrade,
concurrent workers, independent OIDC and proof substitution, current key/account/
grant/session/generation withdrawal, lock-wait expiry, wrong cipher recovery,
bounded cleanup, original-evidence preservation and least-privilege boundaries.
Three separate80% source gates are added. This server source is pending Actions
acceptance. Android protocol, durable update admission/retry and exact integrated
device acceptance remain required; this component does not complete M2/M3.
