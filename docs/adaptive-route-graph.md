# Adaptive route graph - implementation contract

This is an in-progress M4 contribution. It does not advertise a new device
capability, accept a graph policy or change the installed client's routes.
The complete stage is tracked separately from the accepted v77 device/runtime scope.

The [closed metadata contract](../contracts/v1/route-graph.schema.json) describes
at most 500 profiles,4096 directed edges,64 templates and 16 destination/check
groups. Each template has 1-4 slots. A group fixes its exit intent and comparison
features. Physical entry mode is determined locally. All hops and edges must
support the requested capabilities and the last hop must declare the group's exit
class, or `PUBLIC` eligibility for RU/NON_RU only. A valid graph may have no
eligible path on the current network; that is
not permission to fall back to direct traffic.

Metadata IDs bind one-to-one to an independently authorized immutable catalogue.
The unactivated [catalogue snapshot compiler](adaptive-catalogue-snapshot.md)
owns that finite graph/profile binding; its source and Actions acceptance are
separate from signed issuance and runtime activation.
Metadata cannot grant access to another provider or inject transport credentials.
Actual protocol capabilities and TLS/SSH policies are checked separately against
the normalized profile. Declared exit metadata is not proof of the observed exit.
Each route group uses its bound check profile; metrics from incompatible check
profiles cannot be compared as interchangeable latency samples.

Both Go and Kotlin must reject duplicate/unknown/case-substituted fields,
malformed UTF-8, missing/null required containers, duplicate identifiers, invalid
references and edge capabilities outside their endpoints. Compute template
cardinality before expansion. The conservative sum of unique referenced templates
per exit intent must not exceed 4096; reject it explicitly rather than truncate it.
The entire UTF-8 metadata is limited to 262144 bytes. Individual limits need not
all fit simultaneously within that byte bound. Shared conformance fixtures are
required before this contract participates in policy activation.

## Preview candidate counts

The network draft editor can preview the maximum number of candidate chains.
For an adaptive plan, choose **Оценить число цепочек**. The console shows an
upper bound for each destination intent and each group, plus the maximum hop
count per group. Groups that share a template count it once toward their
intent. A draft above 4096 candidates per intent returns a narrowing suggestion.
Editing the draft clears its previous result.

The preview reads the submitted adaptive declaration and its local profile
references. The publication path uses the same Go graph decoder and limit.
Device measurements determine which of these candidates are reachable.

## Runtime ownership decision

The existing embedded engine constructs a static graph. Its pinned upstream
[manager](https://github.com/AlwaysBusyStack/sing-box/blob/476d2436e84995f97fb3af605934cf07d3f95907/adapter/outbound/manager.go)
can remove an entry before rejecting a dependency, and starts a replacement
before committing registry state. Dynamic candidates must therefore use a private
bounded pool, preserving the active and draining paths until ownership ends.
Never mutate or remove a live configured adapter to probe a candidate.

The pinned service helper's
[ContextWith](https://github.com/SagerNet/sing/blob/v0.8.10/service/context.go)
registers into the existing context registry. A candidate must first call
`service.ExtendContext` to clone that registry, then substitute its private
outbound manager. Parent router/platform/lease services remain bound to the
current native runtime. A partial construction failure cancels and retires only
that candidate. No separate NetBird SDK or identity is cloned into a proxy path.

```mermaid
flowchart LR
    P[Signed policy and authorized catalogue] --> V[Closed graph validation]
    V --> F[Finite cursor and local eligibility]
    F --> A[Shared resource admission]
    A --> C[Private candidate construction]
    C --> H[Bound group checks through exact path]
    H --> S[Fresh context-bound selection proof]
    S --> X[Atomic active-path change]
    X --> D[Previous path drains under ownership limits]
```

All resident native adapters share the local cap, including configured, active,
draining and probing entries. Recovery and active confirmation take priority over
optional exploration/diagnostics/telemetry. Capacity exhaustion defers work and
reports incomplete coverage. A metadata-valid path is not a fresh probe result;
neither a cached score nor a warm hint authorizes selection. Negative hints have
finite context-sensitive quarantine and cannot carry authority across a changed
network, intent, policy dependency or engine generation.

## Required remaining implementation and acceptance

Go/Kotlin semantic conformance has accepted CI in [Android PR65](https://github.com/nd4y/syn443-android/pull/65)
and [Control Plane PR40](https://github.com/nd4y/syn443-control-plane/pull/40).
The remaining scope includes native pool/lifecycle tests, shared admission and memory,
immutable source preview/issuance fences,
signed capability gating, client/UI integration and actual Wi-Fi proxy-chain
failure/recovery on Xperia. Required Actions and original-state restoration remain
mandatory. No physical LTE, natural Doze, unplugged energy or endurance gate is
closed by this stage's synthetic network-mode cases.

The original source added shared positive vectors, 21 path queries, 60 closed-failure
fixtures, exact byte/catalogue/combinatorial bounds, concurrent-read ownership,
redacted diagnostics and fuzzing. Kotlin also checks deterministic bounded cursor
results against the same paths and cross-language identities. These passed exact Actions [43701539388](https://github.com/nd4y/syn443-android/actions/runs/43701539388)
and [43700009850](https://github.com/nd4y/syn443-control-plane/actions/runs/43700009850).
The private constructor has separate [accepted evidence](https://github.com/nd4y/syn443-android/actions/runs/43715523260).
No graph policy decoder or capability is enabled.

## Public candidate metadata extension

The unactivated schemaVersion 1 metadata extension permits `exitClass: "PUBLIC"`
on a hop. It allows one normalized, authorized profile to be considered for both
RU and NON_RU groups without duplicating that proxy under aliases. It never
matches INTERNAL. Group intents and observed runtime `ExitClass` values remain
exactly RU, NON_RU and INTERNAL. `null` remains a transit declaration with no
terminal eligibility; unknown classes and ambiguous extra fields are rejected.

Kotlin represents this declaration as `RouteHop(publicCandidate = true, exit = null)`.
A public candidate with a non-null explicit exit is rejected by its constructor.
`publicCandidate` is an internal model field, not an additional wire property.
Entry-mode, complete-path feature/edge, simple-path, template and conservative
per-intent cardinality checks are unchanged. For example, a PUBLIC hop without
TCP cannot satisfy a TCP group; PUBLIC never supplies missing capabilities.

This is eligibility, not country evidence, cached authority or a direct fallback.
Each public group's immutable HTTPS country check must independently confirm its
requested class through the exact native candidate before a fresh bound receipt
can authorize selection. The same hop/path ID in two groups does not make their
check receipts interchangeable. No claim is made about an observed country here.

Older strict decoders reject PUBLIC. Assignment must require the separately
implemented `route.adaptive-tcp.v1` capability before this extension can activate;
this metadata change alone does not advertise that capability or accept policy.
The shared source fixtures now contain 3 valid graphs, 93 queries, 32 frontier
enumerations and 66 invalid graphs. All original 60 negative fixtures retain their
contents. The added cases cover all four modes, RU/NON_RU sharing, INTERNAL/null
denial, missing TCP, unknown/group/lowercase classes and closed ambiguous inputs.
New Go/Kotlin tests and existing shared conformance suites require GitHub Actions
acceptance; editing files and recomputing public hashes is not execution evidence.
