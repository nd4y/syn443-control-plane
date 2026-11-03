# Declarative configuration layers

## Original approval request queue (acceptance pending)

The API-side ConfigurationControl component preserves each original administrative
JWT, DPoP proof, exact operation body and server acceptance time in an encrypted,
immutable SQL request. It checks the separate administrative scope, fresh MFA,
body/key/token/origin binding and live object ACL. Lost replies reuse the same
operation and receipt. A changed body conflicts; bounded pending/receipt quotas
limit admission. Token/MFA expiry and ACL are checked again after SQL lock waits.
The larger256KiB configuration receipt decoder does not widen invitation inputs.

API SQL grants permit only initial request columns. The publisher owns state and
result fields and cannot rewrite original input. Neither role can use a queue
reply to mutate active configuration heads. Fetch workers cannot read receipts.
The new actual PostgreSQL scenarios cover encrypted original-proof recovery,
replay/conflict/ACL revoke, scope/MFA/key/body failures, size/quota bounds, an
observed admission lock expiring token authority and unchanged active heads.
A separate80% request-authority gate is required. This component is not yet wired
to the HTTP/BFF/native UI; publisher claim/preview/approval/atomic activation and
global layer assignments remain required before that workflow is usable.

## Persistent approved-artifact reader

The independent publisher now has an SQLNetworkLayers reader over immutable
publisher-only preview/version rows and a monotonically increasing per-device
configuration head. The encrypted body must match the signed portable proposal
and effective hashes, original actor/origin, full recipient/key/grant/capability
manifest and its original activation interval. Configuration-head revisions are
distinct from periodically renewed VPN policy revisions. The reader returns owned
portable layers to NetworkAuthority, which resolves current authorized source
snapshots and repeats its source fence in the final signing transaction.

An approved artifact may survive the original administrative token's expiry.
Every refresh still repeats current SQL ACL, live account/device/key/grant,
configuration-head CAS, original approval lifetime and source freshness checks.
New online policy issuance remains capped at seven days and by all shorter
dependencies. It cannot extend a downloaded offline lease or fall back to an
owner's raw template after an authority error. Runtime startup checks reject an
API role accidentally granted approval/head write rights; fetch workers receive
no artifact-body access. Normalized recipient memberships, global layer-version
heads, independent preview/request approval and atomic activation writes are not
provided by this reader yet.

The new PostgreSQL tests seed approved evidence as the fixture owner and exercise
the reader/compiled-policy/final-fence path, including a real signed refresh after
admin-session expiry. They are not end-to-end approval UI evidence. Corrupt/foreign/
expired bodies, recipient/capability mismatches, head/ACL/account/source changes,
immutability, role contamination and cancellation are covered by Actions and a
separate80% reader gate. Owner migrations and runtime CLI/API wiring, immutable
approved layer assignments, full supported application settings and web/native
publication remain required M3 work. No production migration occurs in tests.
All eight Actions jobs passed for the reader at
bdedcfc2d5e06386733b575092b780bac4a16886 (run41499280020).

## Signed preview manifest

The configuration package now defines a purpose-separated ES256 preview ticket.
It binds the actor/control origin, exact draft revision/hash, target scope, network
mode, immutable dependency/effective hashes and the complete ordered recipient
manifest. Each recipient binds its actual owner/device/key/grant, configuration
head revision/hash and advertised capability-set hash. A device preview cannot
name additional recipients; a user preview cannot cross owners. Counts, JSON
shape, origin, time, key and signature representation are bounded and closed.
The ticket lasts at most three minutes and contains no engine body or credentials.

The independent publisher must resolve/compile this manifest before signing and
repeat live ACL/MFA/dependency/recipient/head-CAS checks before publication. The
codec alone does not provide those authorities. API-supplied ready flags are not
inputs. Persistent preview requests, approved layer heads, assignments, approval
receipts, final fences and the web/native publication workflow remain required;
this component does not close the complete configuration flow. Actions exercise
independent cryptographic verification, purpose/actor/origin/impact binding,
expiry, signature malleability, duplicate/unknown JSON fields, key trust,
cancellation and recipient/capability bounds under the existing package gates.
All eight Actions jobs passed at4302019c2ffc6509cab9ba8dde877311e2208415
(run41495913038). This evidence covers the codec and existing paths, not the
complete independently approved publication workflow.

`internal/configuration` is the bounded merge/rebase component, not a compiler
or signing authority. Its output is usable only after a required supported-settings
schema validator accepts it. The catalog/compiler must independently resolve
authorized profiles, source snapshots, recipients and device capabilities.

The order is template, explicitly prioritized groups, user, device, local.
Equal-priority group writes that disagree block the result, including explicit
values equal to the template and parent-delete/child-write collisions. Input
permutation cannot change the result. Each field retains its layer/revision origin.

Changes are explicit set/delete operations on bounded named paths; arrays are
atomic ordered values. Overlapping changes in the same layer and nested null
values are rejected; deletion has its own operation. Default local access is denied. Parent/child locks survive
whole-object replacement. Choice/range/free restrictions combine by intersection;
a lower layer cannot invent a permission absent from its parent or bypass a lock.
An administrator edits an authorized source layer rather than silently flattening
the effective document over every template.

Three-way rebase keeps independent local/server changes, reports base/local/server
for conflicting values and distinguishes deletion from an explicit value. Arrays
and type changes conflict as units. A conflict result preserves server values and
returns an error; it is a review document, not a publishable revision.

Limits include20 layers,16 groups,512 total changes,256 restrictions,4096 fields,
16 path segments and256KiB effective documents. Closed decoding, finite bounded
numbers, explicit schema validation and cancellation apply before a result is
returned. Device identities, permissions granted by Android, counters/caches and
runtime results are not portable settings and must be excluded by the supported
client schema. No remote code, network fetch or shell is evaluated here.

Actions run permutation, permission, collision, rebase, cancellation, bounds,
race and fuzz checks with a new85% package gate. Persistent layer assignment,
source dependency compilation, independent final signing and web/native editors
remain separate required M2/M3 work; this component alone closes none of them.

## Outbound graph compiler

The bounded portable graph references source profiles by source/profile ID,
then compiles independently selected connection parameters into deterministic
native outbounds. There is no provider-routing import or arbitrary native option
injection. Explicit selector and URL-test groups, reusable entry groups/prefixes
and up to four physical proxy hops are validated with cycle, missing-reference,
count, byte and protocol-capability limits. TCP/UDP capability is conservative
across every balancer branch. VLESS datagrams can cross a TCP proxy hop; SOCKS
UDP association cannot silently acquire a direct UDP path through CONNECT.

A selector can be a chain entry. The new contextual expansion also clones every
branch of later selectors, URL-test groups and nested chains through the required
incoming prefix. Selected defaults and ordered members are remapped to the cloned
branches; URL-test measures each complete path. A later direct node aliases the
existing prefix and never discards it for a physical escape. Expanded output
retains the64-node/four-hop limits, and cached subtrees cannot hide a logical
dependency depth beyond16. The expansion passed all eight required jobs atbee360932c07a7f08e59b6708d1e60e6206b2173, Actions41387722951.
These capability results describe compiler constraints, not the native interoperability
acceptance matrix. Routing/DNS emission, full settings persistence and independently
authorized configuration publication remain unfinished. Profile credentials stay
server-private; diagnostics redact compiled data. Actions positive/negative/boundary
and fuzz checks retain the existing85% package gate.

## Typed DNS/routing compiler (acceptance pending)

The new portable network component accepts closed version1 fields instead of native
JSON injection. It emits ordered domain/suffix/keyword/RE2 rules, canonical IPv4/IPv6
prefixes, Android package names, network/port constraints, explicit reject and
explicit match-all rules. Route targets must exist and satisfy their required
TCP/UDP capabilities across every chain/balancer branch. An unspecified route
network requires both; a TCP-only route must declare that restriction.

DNS servers have bounded local/UDP/TCP/TLS/HTTPS/QUIC/H3 transport parameters and
explicit outbound references. Hostname bootstrap uses the app's physical resolver,
not a resolver depending on its own proxy. Unknown transports, insecure TLS flags,
URLs/queries instead of addresses or DoH paths, reserved identifiers, dangling
references and unsupported UDP over TCP-only hops fail before emission. DNS rules
retain ordered match/query-type semantics; deterministic output is bounded256KiB.
System DNS remains an explicit policy choice, not a claim of encrypted DNS.

The positive/negative/boundary tests passed all eight Actions jobs at
689dc43e2850fb691c32468f88eb1b3f378fc7da (run41397718493), retaining the85%
configuration package gate. Native parsing/traffic acceptance remains pending.
This network component does not yet provide the entire portable application-settings
schema, four-mode runtime selection, persistent layer assignment, independent
publication or administrative editors. Those M2/M3 requirements remain open.

## Independent compiled-publication handoff (acceptance pending)

The publisher now has an optional independent configuration-authority interface.
Its target is built from the actual device/account/key/grant row, including the
unchanged enrollment request capabilities and current publication revision. The
prepared network document cannot change the recipient, key, audience, revision,
algorithm or account lease. It must have a nonempty supported outbound graph and
existing final target; native inbounds, embedded setup values and SDK paths are
rejected. Required capabilities must be available on that device. The publisher
recomputes the signed content hash and copies activation input.

The prepared result must carry a final SQL fence. The publisher repeats it before
and after device/revision/ownership locks, with elapsed-time lease checks immediately
before commit. A missing result, changed/revoked dependency, authority outage,
cancellation or late expiry never falls back to a static template and cannot
replace the encrypted last-known-good publication. An unconfigured authority keeps
the existing operator-grant path for compatibility.

Actual PostgreSQL publisher tests cover device-bound compiled signing, two fences,
lease clamping, unavailable authority, first/final conflicts, cancellation and late
expiry. Pure negative tests reject unsupported capability and native authority
injection. A separate80% configuration-authority gate is required. The persistent
layer/approval provider is not wired to this interface yet; this is not acceptance
of the complete editable/publishable configuration flow or full administrative UI.

## Portable network-plan composition (acceptance pending)

NetworkPlan version1 closes the supported graph, DNS/routing and activation input
shape into one portable document. It accepts profile references, not embedded
source credentials or arbitrary native JSON. Compilation composes the existing
bounded graph and typed network compilers with the same required-HTTPS activation
validator used by signed policies. It returns owned native bytes, their SHA256,
activation and protocol-feature inventory. Schema/version/size, capabilities,
source errors, cancellation and caller mutation remain bounded and fail closed.

Layers can merge/rebase this document with field provenance and locks before
compilation. This component has no source-fetch, SQL, signature or publication
authority: the independent publisher must use an authenticated source selection
and final source/layer/recipient/approval fences. Required engine features are
inventory, not a replacement for device policy capabilities or authorization.
NetworkPlan does not yet cover application settings, managed overlay issuance,
route-check metadata, persistent assignments or administrative publication. Those
remain explicit full M2/M3 work. Actions require ordinary/race/85-percent package
gates and a new bounded parser fuzz smoke, with no local compilation.

## Private SQL network drafts (acceptance pending)

The catalog adds actor-private, encrypted NetworkDraft proposals with an explicit
template/group/user/device target, declared base hash/revision and expected draft
revision. Put/Get check live object-scoped ACL before accessing the body and
repeat authority checks after work/row-lock waits. Lost replies retain the exact
operation response and cannot overwrite newer drafts; another actor has a separate
namespace even with the same ID. Scope is immutable in SQL and authenticated AAD
binds actor/ID/revision. Source workers and the independent signer cannot read
these unapproved bodies. Incomplete semantic references may be saved for editing;
compilation/publication still require independent live resolution and approval.

A save changes only the proposal, encrypted operation receipt and hash-only audit.
No active layer, source assignment or device publication is touched. There are
hard per-actor bounds of64 drafts and256 saved-operation receipts. Draft discard,
retention, inventory, remaining API/UI lifecycle, immutable approved heads/assignments,
conflict preview, publication and web/native editors remain required work; this
internal persistence component is not the complete administrative workflow.
Actions add actual restricted-role PostgreSQL CAS/replay/scope/ciphertext/quota,
corruption/cancellation and late session/ACL expiry/rollback cases. No live data or
provider is changed and no compilation runs locally.

Basic control API wiring now exposes configuration.draft.get/put with the same
separate admin audience, DPoP body/key/token binding, durable replay protection and
live SQL ACL. A closed versioned NetworkPlan DTO rejects native escapes, unknown
members, null network containers, invalid scope and caller timestamps. Put has an
explicit270336-byte payload bound; all other ordinary action limits are unchanged.
The shared Android/control contract bytes and SHA lock are identical. New actual
HTTP/SQL cases cover private readback, stale revisions, server-owned metadata,
withdrawn rights, fresh-proof lost-reply retry and replay rejection. Exact Actions
acceptance is pending; these endpoints do not publish a configuration or provide
an administrative UI/approval workflow.

## Source-to-publisher composition accepted

At4867e3687c730630650142c5c1b570f2fe25b932 all eight mandatory jobs passed in
[Actions41442820334](https://github.com/nd4y/syn443-control-plane/actions/runs/41442820334).
The independent NetworkAuthority now joins approved portable layers and currently
authorized immutable source snapshots to the per-device publisher. Tests verify
actual ES256 output, recipient/key/grant/base binding, deterministic duplicate
profile aliases, source freshness lease caps, both transaction fences, late layer
denial/source disable/share-head changes/expiry, cancellation and SQL-role isolation.
The previously described plan and private draft/API paths passed their own full
Actions runs. This does not provide persistent approved heads, assignments,
preview/MFA publication, full application settings or the administration UI.

Locally derived managed-overlay waiting flags are forbidden in prepared publisher
input, alongside inline keys, SDK paths and namespace overrides. The Android
identity worker alone may render this fail-closed placeholder for a valid lease.

## Internal configuration work admission

The publisher's private queue plumbing now admits at most4 concurrent20-second
leases, at most3 attempts and the original180-second administrative deadline.
It commits the claim before independent OIDC/MFA/DPoP verification. The original
actor, request/body hash, action, target and accepted time must match; an API
receipt or queued state is never accepted as approval authority.

A package-private producer transaction repeats live object ACL, original session
expiry and exact row/lease ownership before and after its SQL effect. Failed,
cancelled, malformed-result, expired or stolen work rolls back both effect and
queue result. Actual row-lock waiting counts against the lease. A configuration
publication receipt is named `published`; activation on Android remains separate.
Legacy owner-fixture `applied` rows are retained but no new code produces them.
Work diagnostics redact original receipts and identifiers.

Actions use the actual API queue and restricted publisher role to test original
receipt tampering, concurrency, lease takeover, bounded retries, ACL withdrawal,
SQL rollback and cancellation, session expiry during an effect and observed row
lock expiry before effect admission. A separate80% gate covers this new plumbing.
The test SQL marker is explicitly not a signed preview producer: independent
recipient/layer/source resolution, preview signing, activation, HTTP/BFF/worker
loop wiring and the full administration/settings scope still require completion.

## Shared layer and recipient authority

The next SQL component keeps immutable encrypted global layer versions, monotonic
layer heads and publisher-only assignments tied to an approved configuration
version. Composite foreign keys bind both revision and body hash. An API draft or
an asserted group name cannot create membership. The runtime role guard rejects
even unexpected column-level INSERT rights on approval/global tables.

The independent resolver obtains actual live approved devices, their frozen
enrollment keys/capabilities and current account grants. User impact includes all
current approved devices; group/template impact comes only from committed current
assignment rows. Requests cannot omit/add/reorder recipients. Account locks fence
concurrent user enrollment inserts, and membership changes share a short publisher
transaction lock. Configuration heads and global layer versions use separate CAS;
periodic VPN policy renewal alone does not invalidate a configuration preview.

Every referenced layer requires read permission; initial shared-layer creation
and per-device assignment require their explicit rights. Existing non-target
parents must match the current immutable body/revision. A higher global revision
requires the corresponding target, complete recipient impact and exactly the next
revision. User/device/local layer identities must belong to the actual recipient.
Complete layer merging still enforces inherited field restrictions. Prepared
snapshots own their input bytes and repeat identity/grant/head/membership/ACL/time
and global-version checks in the final transaction; they have no approval method.

Actions exercise real SQL/roles for recipient/parent CAS, shared-body conflicts,
user/group/template membership, caller mutation, role contamination, missing
creation/read/assignment rights, source-independent authority changes and explicit
owner-only ciphertext corruption. A separate80% gate covers the resolver. Tests
seed approved artifacts/assignment rows as owner fixtures. The independent
producer below adds a separate composition test; these resolver fixtures remain
explicitly distinct from end-to-end approval. Full application settings and
automatic defaults for new users/devices also remain open.

### Independent preview and desired publication producer

`ConfigurationPublisher` consumes the encrypted original administrative receipt,
reverifies OIDC/DPoP/MFA and resolves actual live recipients/layers. It compiles
each recipient against current authorized source snapshots. A purpose-bound ES256
ticket binds the portable draft/effective hash, owner/device/key/grant/capabilities,
base configuration heads, layer/membership authority and compiled source dependency
vector. Source credentials and native configuration never enter the ticket.
Canonical recipient order is bytewise owner/device, independent of SQL locale.

The final publisher transaction repeats live authority/source fences and atomically
stores immutable global versions, CAS heads, complete device assignments and the
terminal queue receipt. A shortened preview/source deadline is checked before and
after SQL effects, including lock waits. A late failure rolls everything back;
lost acknowledgements reuse the same operation. Deterministic conflict/denial is
terminal; transient errors retain the bounded lease/retry path. No API role can
insert an approved artifact, and `published` remains distinct from device activation.

Actions tests cover independently signed preview -> real desired heads -> the
approved-layer reader/source compiler after the original admin session expires,
shared updates and unchanged global-row reuse, multi-recipient SQL rollback/retry,
scope/ACL/recipient/source changes and deadline expiry. This implementation is
pending its first complete Actions result. Device activation acknowledgements,
full settings and editing UI remain required work.

The optional `SYN443_CONFIGURATION_CONFIG` owner-only file enables the closed
`configuration.preview.request`, `configuration.publish` and
`configuration.request.get` actions in control-api and the control-audience BFF.
It contains the matching control origin, issuer, audience, allowed client IDs and
assurance ACR; distinct layer/source encryption keys; and public preview roots.
Unknown fields (including provider credentials) are refused. The control API
never receives the private preview key or an approved-result insertion method.

After installing identity/catalog owner schemas and roles, the owner explicitly
runs `enrollment-admin configuration-migrate` and `configuration-roles`. Runtime
processes do not migrate or grant themselves access. Enable the same protected
configuration in enrollment-worker, which independently verifies the control
audience, compiles queued work and renews device policies using `SQLNetworkLayers`.
Only that worker receives `SYN443_CONFIGURATION_SIGNING_KEY_FILE` and
`SYN443_CONFIGURATION_KEY_ID`; startup checks the matching public root. Ordinary
device publication runs before a separately bounded administrative step.

This is opt-in for a controlled assignment migration: every participating device
needs an approved configuration head before receiving a layered VPN policy. Missing/invalid authority fails closed,
without fallback to the old flat template. Preserve public signing-key history
and encrypted immutable versions across restarts. `published` means desired
server heads are committed; the device's activation receipt remains separate.
HTTP/SQL/role composition and protected runtime parsing have new Actions tests;
live deployment, activation delivery mapping and editing UI are not implied.

### Authorized desired-configuration view

`configuration.inventory.get` reads one live approved device under fresh control
authentication and object-scoped draft/layer read rights. It returns desired
configuration revision/hash, separately issued policy revision, selected layers,
effective portable values, field origins and inherited restrictions. It filters
the original multi-recipient proposal before constructing the response; other
device bundles, native profiles and source credentials are never returned. An
existing device with no layered assignment is explicitly `unassigned`, while an
absent/revoked/unauthorized device is denied. This view is not an activation ACK
or a connectivity check.

Owner migration adds only a non-authoritative `configuration_guard` column to
identity_devices. The API can update that guard solely for PostgreSQL row-lock
eligibility, while identity/key/receipt/active/approved fields remain protected.
The consistent read locks live account/device authority and repeats ACL/time
checks; current head/version/body integrity and complete inherited validation
still apply. SQL/HTTP tests cover scope filtering, field provenance, incomplete
assignment, revoked rights/account/device, ciphertext failures and role isolation.
The view and its editing integration still require complete Actions acceptance.

The dark responsive control console includes the desired-device view. It shows
the issued policy counter separately, preserves field origins/restrictions and
clears private rendered state on logout/revocation. Null empty permission lists
remain compatible with actual Go JSON. Device-response binding is checked before
display; pending mutations disable the viewer, and all values are DOM text. The
browser fixture checks assigned/unassigned/expired views, XSS, mobile overflow,
scope withdrawal and no publication side effect. This UI is read-only; editing,
local testing, three-way review and explicit publication remain separate work.

Layer identity is `(kind,id)`, matching immutable SQL histories and assignments.
The device and local layers may both use the actual device ID. Same-kind
duplicates remain invalid, and shared IDs never bypass inherited locks/choices.
Pure merge and actual multi-layer publication/readback tests cover this case.

### First device admission before configuration assignment

The identity publisher independently verifies the original OIDC/invitation
receipt, device-key proof, grant and advertised capabilities before marking a new
device identity approved. If the configured authority reports no desired head,
that identity admission freezes the original request/receipt but issues no VPN
policy, offline lease, native profile or overlay reservation. It does not fall
back to the owner's flat template. The existing policy endpoint remains pending.

The admitted device can then receive an explicitly authorized first layered
assignment through the same preview/publication pipeline. Device renewal is
scheduled after that atomic publication; ordinary signature/key/grant/source and
activation gates still apply. Admission locks account/device rows, repeats live
quota/receipt/grant/deadline checks and supports a lost reply without rewriting
identity. Original token expiry and invitation fences bound the initial effect.
Existing malformed/unauthorized configuration failures do not trigger admission.

Actions add HTTP direct-login and invitation/SQL/first-policy composition tests
with synthetic identity fixtures and real device-key proofs/transactions,
revocation/receipt substitution, quota shrink, cancellation and late expiry.
Automatic defaults for new accounts, full application settings and capability
upgrades remain required; identity admission is not VPN activation or a default
assignment. Its exact-source mandatory Actions jobs passed; the final integrated
device and full milestone gates remain separate.

### Actor-private layered drafts

The closed `configuration.layers.draft.get/put` actions store an encrypted private
proposal under the authenticated actor and draft ID. Saving requires live
object-scoped `configuration.drafts.write`; reading independently requires
`configuration.drafts.read`. Each save uses an expected revision and a stable
operation ID. An identical lost-acknowledgement retry returns the original saved
revision, even after a later edit or expiration of the proposal's approval time.
Reusing an operation ID with a changed body conflicts. Target scope is immutable.

Draft ciphertext binds actor, ID and revision. Bodies are bounded to256KiB,
64live drafts and256save receipts per actor. Drafts expire after30days, operation
receipts after24hours; a subsequent authorized save reclaims that actor's expired
rows under the same advisory lock. Reads never return expired drafts. Expired
approval windows must be refreshed before another save or preview. Publication
still independently verifies the original submitted proposal and live authority.
The publisher and subscription fetch roles cannot read mutable private drafts.

New SQL/HTTP tests cover concurrent-editor CAS, lost acknowledgements, scope
withdrawal, wrong actor/key, quotas/expiry, schema rejection and role contamination.
This persistence component awaits its complete Actions result. It does not queue
previews, approve configurations, change sources or activate a device. The full
editing/review/publication UI and explicit discard/inventory remain open work.
