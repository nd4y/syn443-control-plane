# Managed adaptive TCP publication

The optional `NetworkPlan.adaptive` contains only canonical base64url graph
metadata, canonical source/profile bindings and group-to-outbound tags. The
publisher resolves these references using the actual addressed device, owner,
key and mode. A shared grant cannot enable `route.adaptive-tcp.v1`.

The dedicated selection lane permits the union of500 adaptive and32 ordinary
profiles. The ordinary selection limit remains64. Source availability, immutable
snapshot identity, expiry and revocation are rechecked under the existing final
SQL locks. Preview dependency fingerprints include the compiled algorithm as
well as engine/activation hashes, capabilities and source dependencies.

Compilation emits the closed `adaptive_routes` wire described by
[`adaptive-runtime.schema.json`](../contracts/v1/adaptive-runtime.schema.json).
It contains normalized protected credentials and must never enter inventory,
logs or public test evidence. The independently addressed publisher revalidates
the compiled wire before signing, including outputs from a substituted authority.
The ordinary inventory projects only explicitly allowed outbound fields.

This format requires key-bound schema2 configure policies, health checks,
`route.decision.v1`, `route.adaptive-tcp.v1` and compiled algorithm
`m4-graph-tcp-v1`. Public groups require a matching fresh HTTPS country predicate;
`PUBLIC` metadata is eligibility for RU/NON_RU, never observed exit authority or
eligibility for INTERNAL. Internal groups use their own reachability predicates.

Bounds:196608 UTF-8 wire bytes,262144 assigned-engine bytes,500 normalized
profiles,64KiB per profile,16 managed TCP groups, four hops,32768 shared decoded
tokens and depth16. Large graph/catalogue documents use dedicated decoders;
ordinary identity/object/array guards remain unchanged.

Managed TCP prefixes may participate in supported ordinary chains. The current
format rejects URLTest/legacy failover coexistence, UDP/ICMP managed groups and
NetBird SDK underlays that depend on a managed group, including hidden VLESS
prefixes. Direct NetBird remains compatible. These exclusions are explicit;
source acceptance does not establish full four-mode runtime or physical routing
acceptance. Those require the matching Android runtime and device verification.

Actions requires27 new core, six real provisioning PostgreSQL and two real
catalogue PostgreSQL outcomes, bound to exact packages and starts/completions.
All earlier race, schema, privacy, browser and coverage gates remain mandatory.
No private device/provider configuration is used in public fixtures.

## Administrative issuer boundary

The owner-only `SYN443_CONFIGURATION_CONFIG.issuer` pins the administrative OIDC
issuer. It may differ from the enrollment worker's device issuer, for example
when client devices and administrators use separate realms. The publisher uses
only this explicit control issuer with the unchanged control audience, pinned
clients, signed scope, DPoP and strong-authentication requirements. It never
falls back to device tokens. Production discovery uses verified HTTPS; the
device grant/issuer and control-API consistency checks remain independent.

The new source tests exercise real TLS discovery and signed tokens whose realms
share a key, kid and subject, plus normal SQL preview/publication and a renewed
key-bound device policy without changing enrollment identity. These additions
require exact-head Actions results; they do not establish live pilot acceptance.
