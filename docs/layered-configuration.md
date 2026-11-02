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
dependency depth beyond16. Exact Actions acceptance of the new expansion is pending.
These capability results describe compiler constraints, not the native interoperability
acceptance matrix. Routing/DNS emission, full settings persistence and independently
authorized configuration publication remain unfinished. Profile credentials stay
server-private; diagnostics redact compiled data. Actions positive/negative/boundary
and fuzz checks retain the existing85% package gate.
