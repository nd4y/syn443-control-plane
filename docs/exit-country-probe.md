# Explicit public exit-country checks

The `https_exit_country` primitive is separately negotiated as
`route.exit-country.v1`. An approved per-device configuration may require it only
in a key-bound schema2 configure policy with `route.health.v1`. An older client
is denied this assignment; country support does not imply fixed-address support
and neither primitive can silently replace the other. A shared grant template
cannot bypass per-device approval. Existing live publication fences are retained.

The portable check contains `method`, `target` and `expected_exit_class` with the
exact enum `RU` or `NON_RU`. `expected_ip` is exclusive to `https_exit_ip`.
An HTTPS country target has only its root path, without a query, fragment or
userinfo. This prevents accidentally checking an arbitrary address lookup URL
instead of the caller's observed egress. The endpoint is administrator supplied;
no public provider, real user identifier or service credential is embedded.

The candidate connection must carry the request through the exact route being
tested. The endpoint contract is a bounded JSON object with an observed IP and
country. TLS validity, JSON/body/header limits, exact field parsing, known country
codes and cancellation/monotonic deadlines remain client responsibilities.
A valid response for the wrong class is distinct from endpoint failure or a
malformed response. The geo database behind an endpoint can be inaccurate or
stale: this is an observation at one time, not a physical-location guarantee or
authority for future untested connections. Names, flags and profile metadata are
never exit proof.

## Configure a check in the console

In a network draft, under **Проверки маршрутов**, choose an outbound and
**Страна выхода по HTTPS**. Enter the root HTTPS URL of your observer and choose
**Россия** or **За пределами России**. The draft stores the selected class as
`RU` or `NON_RU`. The same observer can be used on several routes. Saving the
draft and publishing it are separate actions.

When an outbound already has a version 2 check profile, the editor shows its
profile ID. You can change whether the profile is required during activation or
edit its conditions in the plan JSON. Editing another outbound preserves the
existing profile, including its gates, deadlines and stages.

The existing internal-only Wi-Fi failover pilot still requires comparable checks
against the internal destination. It rejects both public exit primitives; a
country response cannot establish access to a home service. Full adaptive public
graph activation, contextual quarantine, multiple predicate trees, provider
confidence and the physical Wi-Fi route acceptance remain separate work.

The configuration and policy tests cover method-specific fields, valid classes,
root-only targets, malformed predicates, signed capability matching, shared-grant
denial and the closed OpenAPI/schema contract. A PostgreSQL publication case
requires independent capabilities for a combined country/fixed-IP plan, preserves
both predicates and retains the live final SQL fence. Builds and executable tests
run only in GitHub Actions. Source presence is not CI or physical acceptance.
