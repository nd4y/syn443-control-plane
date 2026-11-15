# Managed NetBird delivery and local ownership plan

This is the remaining implementation contract. The namespace and credential
cryptographic cores exist. The bounded SQL/API implementation is now present
and passed its Actions transaction/role gates at53ec35d405d6e93acea911856cf8655df78ea3ed
(run41384206025, all8 jobs). Protected Android cache and SDK
activation below are not implemented or accepted yet. Assigned NetBird stays rejected until all
three are complete. This document does not authorize production enrollment.

## Trusted sources and wire boundary

The owner-protected server configuration declares one stable service ID, checked
against any signed service descriptor. Owner tag is the canonical existing
service/issuer/subject digest. Device ID and thumbprint come from the locked
registered session. Overlay/resource/provider-network IDs and identity epoch come
from the signed assignment; no request supplies its own account or membership.
Provider network means tenant/network, never a Wi-Fi/LTE epoch or a peer group.

The independently signed engine config carries a typed managed NetBird reference containing
overlay/resource/network/identity epoch and setup reference/version. It contains
no plaintext setup key, imported SDK key or caller-selected state directory. The
client must advertise the new credential capability before such a policy can be
issued. Server and client reject unknown metadata, more simultaneous identities
than supported, future providers and incompatible detours before native effects.
Direct transport is the default; the emergency VLESS transport retains its exact
existing all-branches validation and never falls back to direct UDP implicitly.

## SQL and API authority

The independent publication authority issues the separate credential JWS only
for the authorized target, with expiry capped by the permitted policy lease.
Immutable grant data binds reference/version, owner/device/key, namespace,
security epoch, envelope hash and protected envelope. API/session and source/parser
roles cannot mint a signature. Provider management tokens never enter this table
or a device response; only the addressed one-use setup credential is delivered.
A grant's protected value may be erased, never replaced under the same revision.

Fetch and consumption acknowledgment use bounded POST bodies, an opaque durable
operation ID, current device-session DPoP/nonce and body hash, no browser Origin,
no query credentials and the existing IP/admission limits. Account, device and
session locks and replay protection precede the grant lock. The API repeats the
current approved signed-policy reference/namespace/epoch permission before
returning a secret and independently verifies the grant's signature/scope. It
checks time again at the final commit after waits. No durable successful reply is
reported on transaction/storage failure.

One delivery operation owns each reference/version. A lost fetch reply retries
the same protected operation/body and receives the same grant while permitted.
A different operation cannot silently start another SDK enrollment. The request
binds the stable reference/version/namespace, not a physical network, transport
mode or refresh-only config revision; a direct/VLESS change must not break a
pending enrollment. Fetch requires the latest authorized policy to reference that exact version.
Consumption acknowledgment is idempotent and returns no secret. After consumption
or expiry the API cannot return the value. Denial, transient outage, nonce change,
conflict and expiration are distinct fixed error states without protected values.

## Android durable state and native boundary

The controller persists a bounded generation-bound operation before network or
native effects. The credential consumer verifies the independent signature and
all addressed fields against its own authenticated state, using the conservative
trusted-time lower/not-before and upper/expiry bounds. A per-grant Keystore key
protects its no-backup cache. A stable ledger records pending enrollment,
acknowledged SDK identity and consumed/retiring states. Corruption or an unknown
key blocks activation; it does not reset to a new peer or use operator SDK state.

Only the trusted controller materializes an authorized credential for the native
host, with a short-lived owner/lease/config ticket. The host receives no general
file path from imported config. It uses the distinct managed namespace root.
Setup bytes are borrowed only for SDK preparation and zeroed on exit; immutable
runtime strings follow normal JVM/Go collection limits. Successful management
registration plus durable SDK identity precedes the consumed ledger record and
local credential/key erasure. A lost server acknowledgment retries without
recreating an enrollment secret. A lease refresh or mode change reuses the SDK
identity; explicit identity-epoch/resource/account changes use another namespace.

Stop/logout/revocation withdraw authority and advance the cancellation generation
first. Late network/crypto results cannot persist, start an SDK or resurrect a
retired identity. Retirement waits for confirmed native owner and SDK-lock release,
then erases only that owned managed state and keys. A still-permitted rollback
retains its old identity. Operator state is never moved, adopted or deleted.
No SDK callback or network operation runs while a UI/retirement lock is held.

## Required checks before enabling

Actions must cover actual restricted SQL roles, immutable grants, current-policy
reference substitution, owner/key/device/epoch changes, late revoke/expiry,
replay/nonce/rotated session, lost fetch/ack, different-body reuse, storage outage,
lock cancellation and fixed errors. Android must cover journal/key corruption,
reboot/time bounds, account switch, transport/config changes, canceled/late result,
native owner freeze/retirement, consumed-secret erasure and allowed rollback.

Native fake-provider and real embedded transport checks must verify one identity
through reconnects and direct-first relay fallback. Exact Actions APK acceptance
on Xperia must preserve the original operator identity and check assigned VPN,
Stop and Wi-Fi loss/recovery. LTE and production resources stay separate gates;
no simulator, RUNNING flag, compiled adapter or pure namespace hash proves them.

## Implemented delivery surface awaiting Actions acceptance

The enrollment API enables `POST /v1/device/overlay/fetch` and
`POST /v1/device/overlay/consume` only when the owner-only enrollment configuration
sets `overlayServiceId`. It must match any configured signed service descriptor.
Both bodies are identical: `operationId`, `namespace`, `reference`, `version`.
The opaque operation ID and exact body bytes remain stable across retries; DPoP
proofs are fresh and bind the endpoint, access token, body hash and session nonce.
Responses are `{envelope, consumed:false}` or `{consumed:true}`. No browser Origin
or query is accepted. A changed operation/body returns409; denied current scope403;
invalid proof/nonce401; unavailable signature/storage503. Endpoints are404 when
disabled. Envelope responses are never cacheable.

A signed NetBird outbound has a closed `managed` object with `overlayId`,
`resourceId`, `networkId`, `identityEpoch`, `setupReference`, `setupVersion`, plus
its ordinary `management_url`. It must not embed `setup_key` or `state_directory`.
The policy requires `overlay.credentials.v1`, which Android deliberately does not
advertise until its protected vault/native integration is complete. Device owner
and key derive from the locked session; namespace owner is the shared canonical
service/issuer/subject digest. The current publication records its authorizing
account grant hash, so a changed account assignment cannot redeem an older grant.

The migration adds immutable encrypted grants and one delivery operation per grant.
Only the separate publication role can insert/revoke grants; the API can consume
and erase values but cannot change addressed scope, revive or replace envelopes.
`InstallOverlayGrant` must run inside the independent publisher's final fenced
assignment transaction. Wiring provider enrollment and this issuer into the new
configuration compiler remains open. The API has no signing private key.

## Cleanup after a reference/lease refresh (acceptance pending)

Fetch still requires the exact current signed setup reference/version/security
epoch, an unrevoked and unexpired grant, independent envelope verification and
the final conservative time fence. Cleanup never grants another use or returns
a credential. An already-fetched immutable operation may now acknowledge erasure
after its setup value expires or the current signed policy changes its reference
or advances its security epoch, while authorizing the same namespace and device key.
The current account, session, signed policy/capability and namespace remain
mandatory; an older policy cannot retire a grant from a future security epoch.

An existing delivery requires its exact immutable operation/body. If a controller
crashed after reserving an operation locally but before dispatch, consumption can
also abandon its still-issued addressed grant: SQL reserves the operation and
erases the envelope in the same transaction. Late fetch is then permanently
denied. An unknown grant, another delivery operation or identity/device/key,
withdrawn capability and revoked account or session still fail. A revoked setup grant can be erased; it cannot be fetched.
The acknowledgment deadline uses the current signed authorization/session, never
the expired setup value. Erasure remains irreversible and idempotent and is
withheld until SQL commit. The server acknowledgment is not evidence of SDK
registration; the client must independently persist its native proof first.

New PostgreSQL cases use a separately signed one-second grant, not clock sleeps,
and check expired consumption/retry after reference+epoch refresh, no refetch,
protected-envelope erasure and current-scope rejection. Exact Actions acceptance
is pending. Android still needs its full preparation/materialization/proof/ack
integration before advertising the managed overlay capability.

Pending-grant replacement additionally checks unsent, expired/refreshed and revoked
grants against real SQL. Abandonment never confirms SDK registration or deletes
SDK identity. Android must retain its old operation until local key/cipher erasure
and this durable acknowledgment, then reserve a different signed reference.
