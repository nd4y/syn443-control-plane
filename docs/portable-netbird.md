# Portable managed NetBird configuration

The existing approved layer/preview/publication workflow can now describe one
managed NetBird node as `graph.netbird`. Its closed fields are `tag`, `overlayId`,
`resourceId`, `networkId`, `identityEpoch`, `managementUrl`, optional `hostname`,
`mode` and optional `detour`. Canonical HTTPS management origins and stable
identity identifiers are required. The portable document contains no setup key,
provider token, SDK path, namespace, enrollment reference or forced-relay setting.

`mode: direct` uses physical networking. The SDK prefers peer-to-peer connections
and may use a relay when a direct peer path is unavailable. This underlay mode
does not claim that every peer currently has a P2P connection. `mode: vless`
requires an explicit graph detour. Every selectable branch must end in VLESS;
direct, HTTP, SOCKS, SSH, cyclic and missing branches are rejected before signing.
There is no automatic switch from an assigned VLESS underlay to physical access.
The current VLESS adapter carries relay traffic through that underlay and blocks
physical ICE/UDP sockets. P2P preference belongs to the normal direct mode; the
emergency VLESS path must not claim a direct peer connection or bypass its proxy.

The node can be a final/route target or an initial hop to a proxy inside the home
network. Its explicit VLESS detour provides the emergency ingress. Expanding the
same managed node as a later generic chain hop is rejected: compilation must not
clone its SDK identity. One managed node, four physical hops, sixteen dependency
levels, sixty-four emitted nodes and the existing byte limits remain enforced.

`network.dnsServers` accepts `transport: netbird` with an `outbound` naming the
actual NetBird node. Address, port, TLS name and DoH path must be absent. Ordered
DNS rules can route only the assigned internal suffixes through this server;
the ordinary final resolver remains explicit. A selector or a non-NetBird node
cannot impersonate the internal resolver. The native NetBird resolver propagates
errors rather than silently resolving the internal name through a public DNS.

The publisher still checks the independent approved layers, live recipient and
source fences. The device must advertise `overlay.credentials.v1`. A managed
configuration also requires a configured independent overlay broker. The broker
checks the actual resource/account/network/group grant and replaces its own
addressed reference atomically with policy publication. Changing direct/VLESS
transport does not change the overlay/resource/network/epoch identity. Neither a
portable field nor a successful preview enrolls a peer or authorizes a resource.

GitHub Actions runs direct/VLESS and source-chain compilation, closed decoding,
identity/hop/cycle/fail-closed checks and real role-restricted PostgreSQL signed
publication, missing-broker retention and reference-continuity tests. These tests
also require the credential module at the approved-layer boundary and retain the
shorter source-freshness deadline and final source fence for mixed configurations.
They
do not prove external provider availability or physical Android acceptance of
this exact compiled publication. Full application settings, four-context client
selection, templates for future devices and remaining mobile administration are
still required M2/M3 work. Current component acceptance is pending its exact CI.
