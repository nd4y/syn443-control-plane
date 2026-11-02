# Declarative configuration layers

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
