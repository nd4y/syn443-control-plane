# Configuration operation outcome reconciliation

Status: source/main accepted, deployment pending. The handler, immutable ledger,
transactional SQL guards and28 PostgreSQL/HTTP roots passed Actions43973718639
and resulting main43975423153. Safe Go-wire generation passed19 producer roots
in43988560182 and resulting main43991701436; signed specimens are not published.
This document does not enable a live API, database migration, permission,
worker action or client publication. Compatibility, protected integration and
device acceptance remain required. The existing client keeps an uncertain
operation pending.

## Service protocol eligibility - source pending

The existing `POST /v1/control/action` accepts a separate version-one read:
`configuration.protocol.get`, with a normal24..128-character request ID and
exactly an empty object `payload`. Its closed response is
`{"version":1,"configurationRequestVersion":1}` or
`{"version":1,"configurationRequestVersion":2}`. A current independent
administrative control token, exact one-use
DPoP and the restricted runtime role are required. This nonsecret service read
has no target, object ACL or fresh-MFA requirement and grants none of those
rights. Mutation authorization remains unchanged. Existing HTTP clock/proof
bookkeeping remains; the read creates no configuration, provider, publication,
draft, ledger or worker effect.

The owner-protected `SYN443_CONFIGURATION_CONFIG` may contain the optional integer
`configurationRequestVersion`. Absence,0 or1 advertises1. Only an explicit2
advertises2, after the owner has coordinated the schema and every queue consumer
upgrade. Null, case/duplicate fields, coercions and other values fail closed.
The declaration does not prove that every worker was upgraded. There is no
automatic feature enabling or provider/worker detection.

Clients may probe before creating a **new** mutation. A known unsupported old
server (`400 catalog_invalid`,404 or405) permits conservative version-one
creation. Authentication/MFA denial,403, quota429, cancellation, transport
failure or uncertainty is not unsupported and must not trigger that fallback.
An existing pending operation keeps its original bytes, request ID and version;
neither the probe nor a declaration rewrites it. The read envelope itself stays
version1, and version2 remains restricted to the existing four mutations.

The signed five-field administrative metadata, ordinary bootstrap, device/key
projection and administrative/device session bindings are unchanged. Adding
this action does not turn service eligibility into a role, MFA proof, preview,
publication grant or device activation. The14 new actual-outcome roots
(7 normal,4 provisioning PostgreSQL and3 catalogue HTTP/PostgreSQL) and6
validator unit cases are source-pending GitHub Actions. No live API, owner
declaration, migration or client activation has been performed by this change.

## Problem and evidence boundary

A failed HTTP dispatch is not evidence that an earlier dispatch with the same
request ID had no effect. The current draft receipt cache expires after 24 hours;
discard tombstones and drafts have a separate 30-day lifetime. Requests already
accepted into the configuration queue have another lifecycle. Authorization and
quota checks may reject a replay of an operation that previously committed.

In particular, `putDraft` checks a discard tombstone before its cached operation;
the existing PostgreSQL test expects a conflict when an earlier successful save
is replayed after discard. Queue admission checks current authorization before
looking up the earlier request. Consumed DPoP proofs are authentication replay
data, committed separately, and never prove a configuration outcome.

The client must preserve the original request ID, exact bytes, actor/service
binding and encrypted local CAS after transport loss, 400, 403, 409, 429,
malformed replies or an expired administrative session. It must not fabricate a
new publication or convert a legacy request into a newer protocol.

## Compact immutable ledger

Use a compact immutable ledger keyed by actor, existing lock family and original
request ID. Bind the exact action, lowercase SHA-256 of the original bytes,
protocol version, derived target, disposition and a typed effect reference.
Do not duplicate the configuration body, provider credentials, tokens or DPoP.

Preserve the existing independent actor lock families:

- `configuration-private-drafts/<actor>` for draft save/discard;
- `configuration-requests/<actor>` for preview/publication.

An ordinary mutation checks the ledger under its existing family lock. Its
business effect, ordinary receipt and immutable recorded disposition commit in
one transaction. A repeat with matching bytes returns a checked recorded result;
a different action, body or target for the same key conflicts. The ledger grants
no authorization: current ACL, MFA, expiry and final pre-commit checks remain.

Regular service roles may read/insert only the necessary rows. They cannot
update/delete the ledger or gain publisher/head authority. A payload may expire
separately, but its compact fence remains. Missing historical payload is a
recorded result unavailable, never a claim of no effect or VPN activation.

New immutable entries require atomic per-actor/day and global admission limits
before any business effect or fence is created. Repeated checked lookups and
recovery have a separate bounded reserve; entry admission cannot starve recovery.
Compaction requires a proved protocol retirement/horizon. TTL deletion alone
would re-enable a late legacy mutation after its ordinary cache expired.

Initial normal admission bounds are 512 new entries per actor/UTC day, 32768
globally per UTC day and 1048576 normal entries in total. Checked historical
backfill has a separate reserve of 128 per actor/day, 8192 globally/day and 65536
additional total entries. Existing lookups do not consume new-entry admission.
Use transactional counters instead of scanning the full ledger on each insert;
every path takes the family lock before counters, never in reverse order.
Reconciliation HTTP admission remains bounded by the existing hard ceilings.
The candidate reserves one of the existing four concurrent handlers for
reconciliation, with at most three ordinary handlers. Callback ownership keeps
its slot until the actual callback returns, including after cancellation. Shared
IP admission120/minute and DPoP proof admission256/actor/120seconds are unchanged;
they can still transiently throttle recovery. A reserved proof/IP budget is not
implemented or claimed by this candidate.

## Reconciliation protocol

Expose fixed `POST /v1/control/configuration/reconcile`, with an endpoint-specific
request limit of 524288 bytes. Configuration mutations keep their 262144-byte
limit. Preserve the existing mixed action route's larger source-upload envelope;
neither raise its hard ceiling nor accidentally tighten unrelated operations.
The new route accepts no arbitrary URL or actor.

The input includes canonical raw-base64url original bytes, decoded at most
262144 bytes, and an explicit lookup/seal intent. The server derives action,
request ID, target and body hash from those bytes; the verified current session
supplies the actor. Reject nested reconciliation, unknown versions/fields,
noncanonical base64, duplicate JSON keys and target/permission mismatches.

Under the same existing family lock, inspect the immutable ledger and native
legacy tables. Never infer absence from a current draft/head snapshot or from a
pruned receipt. Proposed outcome meanings are:

| Outcome | Meaning |
| --- | --- |
| `RECORDED` | Exact operation registered; return typed effect/job state. A queued/running job is not terminal. |
| `NO_EFFECT` | This exact new fenced request did not create an effect and cannot create one later. |
| `UNKNOWN` | Historical evidence is insufficient; keep pending. |
| `RECORDED_RESULT_UNAVAILABLE` | Exact operation is recorded, but its historical payload is unavailable. Do not invent its contents. |

Truthful `NO_EFFECT` requires a new body-bound protocol version/marker that old
strict servers reject before business mutation, and mandatory recording of all
new successful commits. An absent legacy-v1 row remains `UNKNOWN` because its
24-hour cache could have been pruned. Old pending bytes are immutable.

Sealing an absent operation atomically creates its fence under the same lock.
Database guards before insertion into native draft-ops/request tables require
a matching recorded ledger entry from that same transaction. The updated
handler creates its entry before the effect; a deferred guard verifies that the
corresponding native effect exists at commit. A delayed old writer without this
entry fails closed and rolls back its entire transaction, including draft edits
made before the guarded insertion. Old cached replies and existing queue rows
remain usable. There must be no global-lock/family-lock inversion.

This is not a transparent rolling upgrade for old administrative writers. Plan
and test migration/role initialization before enabling compatible writers; an
old binary can serve compatible reads but new administrative writes fail closed.
Code rollback must report that limitation, not infer write health from process
health. Never remove guards/fences as an automatic rollback. Actual deployment
requires its own backup, migration, compatibility and acceptance evidence.

An existing queued/running request returns `RECORDED`; initial reconciliation
does not cancel it or claim it absent. Worker row ownership, lease checks,
effect and terminal receipt remain atomic. New versions must not be advertised
until all queue consumers support their semantics. Older worker/API behavior
must be exercised by actual PostgreSQL races, not assumed from new code alone.

The candidate has no legacy unknown-past seal or `SEALED_UNKNOWN_PAST` wire
outcome. Such a future recovery mode would require an explicit warning, fresh
original-action authorization/MFA, authenticated current-state review and proved
old-API/worker late-commit prevention. It cannot become a `NO_EFFECT` shortcut.

Only the native table owner may import existing native history through its
owner migration path; the runtime API is never that owner. The ledger still
applies its quota and deferred consistency guards to owner inserts. Generic
restore ordering or reimport of counter rows is not established by this source
change. A reviewed owner-import/restore procedure and actual isolated recovery
evidence remain required. Do not add an automatic owner bypass or drop guards
to make an unverified restore appear successful.

## Client handling

Only an exact actor/service/action/request/body-bound checked receipt may resolve
the matching encrypted pending CAS. A live nonterminal job remains pending.
Local text survives resolution. Re-authentication, lookup or reopening a screen
does not publish, extend a preview, change an unknown request ID or grant rights.

A recorded result with missing historical contents needs explicit checked
current-state reconciliation before editing resumes; it is not reconstructed
from guessed fields. An optional unknown-past seal must retain that uncertainty
in the UI, prevent late original effects and require a new current-base preview
before a new publication. Publication acknowledgement and VPN activation stay
separate. Definitive HTTP refusal alone never clears pending.

## Required acceptance

PostgreSQL/HTTP tests must cover original-commit/lost-reply/rejected-replay;
seal-first and original-first races; actual old SQL insertion paths; nonterminal
worker ownership; pruned legacy receipts; same-key foreign hash/action/target;
expired/revoked authorization while blocked on a lock; lost seal replies;
payload pruning with a surviving fence; unsupported old servers/workers;
immutable SQL-role enforcement; quota exhaustion with reserved recovery; and
bounded malformed/oversized input. Existing privacy, coverage, race, source-lock
and deployment tests remain mandatory. Physical client acceptance uses the
authorized USB/Wi-Fi device, with cellular tests excluded.
