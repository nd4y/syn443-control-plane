# Adaptive catalogue snapshot - unactivated M4 primitive

`CompileAdaptiveSnapshot` binds the closed finite graph to one independently
authorized source selection. It performs no network fetch, SQL write, signing
or policy activation. The source resolver belongs to the publisher; a reference
or successful snapshot is never access or publication authority. Both initial
and final grant/source/recipient fences are still required at issuance.

The compiler copies graph bytes and all references before resolution, validates
the graph against exactly those local hop IDs and resolves in deterministic
order. Each profile must match its requested identity and normalized protocol,
including existing TLS/SSH validation. It decodes into owned maps before the
next callback. Caller buffers, names and references cannot mutate the result.
Returned profiles contain only local hop IDs and fresh outbound byte copies.
Ordinary formatting and JSON serialization expose no protected snapshot data.

At most500 profiles,65536 bytes per imported outbound and262144 bytes for the
complete graph/reference/normalized-profile binding are accepted. Repeated
source references and canonical duplicate transports are rejected: imported
copies must not circumvent repeated-hop/cycle checks through different aliases.
Source errors and partial revocation yield no usable partial snapshot. A late
resolver completion after cancellation cannot publish a result or start a
replacement worker. The helper creates no worker or background task.

The content hash covers graph bytes, actual normalized profile content and source
references. It is immutable after compilation and suitable as one input to the
eventual publisher dependency binding. It does not replace live SQL fences.
Declared path eligibility is expressly separate from protocol-transition,
observed exit, runtime lease and fresh native probe requirements. In particular,
this helper does not infer encapsulated UDP/ICMP support from a proxy label.

Required Actions tests cover500-profile acceptance, count/per-entry/aggregate
limits, exact graph binding, malformed/substituted/insecure profiles, alias and
cross-import transport duplicates, source revocation, cancellation before/after
and during blocked resolution, deterministic identity, defensive copying and
concurrent immutable reads. No real provider data is used. Exact-head CI remains
required before acceptance.

The accepted configuration schema and device capabilities are unchanged. Signed
graph issuance/preview, shared scheduling/memory, client integration and physical
alternative-chain acceptance remain open; this module is not a completed M4.
