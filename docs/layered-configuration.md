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
atomic ordered values. Default local access is denied. Parent/child locks survive
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
