# NetBird management API adapter (integration pending)

`internal/netbirdapi` is the single-account setup-key management subset for the
future managed overlay broker. It is not an enrollment authority or an enabled
catalog resource. It verifies the account before every operation, uses the
owner-configured HTTPS API origin/network grants and ordinary certificate checks,
and refuses redirects, environmental proxies, compressed/oversized/ambiguous JSON,
unbounded concurrency and unaddressed external-ID mutations. Provider credentials
stay server-side; error/default diagnostics omit request bodies, URLs and secrets.

Creation sends a non-ephemeral one-off key with usage limit1 and explicit approved
auto-groups, no extra DNS labels, and an opaque server-generated operation name.
The [NetBird API](https://docs.netbird.io/api/resources/setup-keys) has a minimum
provider expiry of86400 seconds. The addressed SYN443 credential lifetime must
remain much shorter; an independent durable cleanup job must revoke the provider
key at that deadline, on confirmed use/authorization loss or abandoned enrollment.
The adapter never retries creation. Any failure after dispatch is marked as an
unknown mutation outcome, including cancellation or an invalid successful reply.

The broker must persist dispatch intent before the request. Lost replies are
reconciled by that exact opaque operation name, with no setup value exposed by
metadata methods. Before deletion the adapter checks the current external key ID
and operation name again. Missing IDs are idempotently absent. Multiple/missing
list matches never automatically authorize another creation; neither does an
unavailable or malformed usage counter. Metadata reads are bounded to64KiB and
256 array entries. Exceeding that limit requires cleanup/operator action, not an
unbounded listing or speculative issuance.

Actions tests actual TLS/account/credential/request boundaries, one-off parameters,
ownership guards, exact no-retry behavior after a lost response, mutation outcome
classification, wrong account/root/address, invalid/duplicate/null/oversized data,
group/use-count/expiry/key mismatches, redirects/rate/errors, Close/cancellation
and bounded concurrency. The new package has a required80% coverage floor.
The initial adapter passed all eight mandatory jobs at48b95760464587c08304c0a9b11c4577827dbf02, [Actions41449596701](https://github.com/nd4y/syn443-control-plane/actions/runs/41449596701), including its80% coverage gate.

Durable SQL grant/dispatch/revocation jobs, setup-key issuer, resource/API/UI wiring,
provider peer reconciliation and client keyless recovery after interrupted
registration remain required M2/M3 integration. No real NetBird account is changed
by these fixtures. Multiple overlay providers remain contracts only.

## Revocation must preserve registration evidence

The adapter also exposes ownership-checked inspect and disable operations. Disable
uses the documented PUT revocation operation and retains the key's usage counter.
It cannot return setup material, silently lower a prior count, accept a different
ID/name/expiry/group set or label a lost mutation reply successful. Repeated
disabling of an already revoked key is metadata-only. Tests include registration
winning between the initial read and revocation, idempotent readback and uncertain
responses. The broker must preserve known use and registration evidence before
eventual record deletion; absence after deletion does not prove non-registration.
The usage-preserving extension passed all eight mandatory jobs atb7ec1467973ee00d8e1203b3be18a603ab60ccc3, [Actions41452793402](https://github.com/nd4y/syn443-control-plane/actions/runs/41452793402). It remains separate from the unimplemented durable issuer.

## Provider evidence for peer ownership (acceptance pending)

The pinned NetBird management implementation records `peer.setupkey.add` with the
setup-key ID in `initiator_id`, peer ID in `target_id` and opaque operation name
in `meta.setup_key_name`. `FindOwnedPeer` checks those exact fields, the registration
window and the current peer creation time. Hostname and IP are never authority.
`RevokeOwnedPeer` rediscovers this evidence before deleting only that peer;
missing, ambiguous, malformed or stale identity evidence causes no mutation.
An already absent, previously proven peer is idempotent. A lost DELETE reply
remains unknown until an explicit ownership-checked readback confirms absence.

The [audit endpoint](https://docs.netbird.io/api/resources/events) has no documented
pagination. The adapter streams at most2MiB and10000 events, keeping each event
under64KiB with the ordinary duplicate/depth/string guards. Oversized or unavailable
audit cannot authorize deletion. Tests cover more than256 unrelated events,
conflicting peers, forged operation/time/creation identity, cancellation and a
lost deletion reply. A durable broker must retain the verified mapping before
provider audit retention expires; these methods alone do not implement that store,
an enabled resource, automatic cleanup or actual Cloud acceptance.
