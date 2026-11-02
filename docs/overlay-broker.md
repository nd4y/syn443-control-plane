# Durable managed-overlay broker (integration and acceptance pending)

`internal/enrollment/broker.go` adds a publisher-reserved SQL journal and a
separately restricted `syn443_overlay_worker` role. It is not enabled by the
existing runtime configuration. No live NetBird account is changed by tests.
M2/M3 remain incomplete until resource/policy/scheduler/API/UI/device integration
and the complete acceptance contract pass.

The publisher locks the actual SQL account/device, derives the owner tag and
checks an independent approval/resource fence before reserving an immutable
device/key/namespace/resource/account/group/reference/version/deadline scope.
Scopes and returned setup material use distinct authenticated encryption AADs.
Duplicate reservations keep the original opaque operation; changed input conflicts.
At most16 unfinished records are admitted per device. The API cannot reserve,
read a provider secret, mark work complete or grant publication authority.

The provider worker cannot read identity devices/sessions, insert requests, change
scope/retirement intent or sign policy. It claims a45-second SQL lease with
`SKIP LOCKED`, resolves the pinned resource/account and commits `dispatched` before
issuing exactly one POST. A resource outage before dispatch retains retry authority.
A process crash or lost POST reply only permits exact-operation reconciliation;
missing/multiple matches never mean create again. Unresolved creation becomes
blocked after26 hours. Late replies cannot overwrite an expired/replaced lease
and do not independently revoke another worker's current provider key.

Credential cleanup and peer retirement are separate. At the short SYN443
deadline or confirmed use, the worker disables the one-off provider key, retaining
its usage counter. It commits unused or registered evidence before deleting the
provider key record, so a lost DELETE reply remains safely retryable. Used keys
require an account/resource-bound `peer.setupkey.add` receipt and current peer
creation identity; missing evidence blocks cleanup rather than guessing a peer.
The authenticated encrypted receipt is immutable once recorded. Established peer
retirement uses that receipt after audit retention, rechecking account and current
creation time before deletion. Expiring an enrollment key never retires the peer.

The independent publisher wraps issued values into addressed ES256 credentials
only after verifying the current signed policy, actual live account/device/JKT,
original grant and exact namespace/reference/epoch plus initial/final approval
fences. It preserves the original credential deadline. SQL ready state cannot
replace policy/signature/approval authority. A short polling loop must be wired
independently of the long policy refresh interval.

SQL tests use a real disposable PostgreSQL with owner/API/publisher/provider-worker
roles, covering dispatch commit before HTTP, response loss, crash before HTTP,
expiry, ownership, duplicate/conflicting reservations, quota, resource outage,
late lease callbacks, independent addressed installation, retained peer mapping
and retirement after audit retention. The broker has a separate required80%
coverage gate. Compiled tests run only in GitHub Actions.

Still required: configured resource resolver/worker binary, approved portable
overlay materialization, API pending-grant handling, independently scheduled
wrapping/retirement, bounded inventory/retention and controlled safe renewal.
Actual Cloud, root/capability upgrades, complete web/native administration and
final restored USB Xperia Wi-Fi acceptance remain open. LTE is not tested.
