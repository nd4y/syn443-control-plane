# Bounded route check profiles v2

This component implements part of CHK-04 / AC58. Its source, Actions, integration,
rollout and physical acceptance are separate gates. The full requirement still
includes parallel stages, explicit conditional/fallback branches, reusable profile
assignment and the other CHK-01..12 capabilities.

## Contract and compatibility

In the mobile console, open a network draft, select the outbound, and add its
checks. **Настроить условия проверок** groups them into sequential stages, all,
any or a quorum. TLS, exit IP and exit country remain mandatory gates. The
threshold applies to the remaining checks. The deadline is shared by the
profile. The direct outbound is selectable even when the graph defaults to a proxy.

The editor preserves leaf identities, gate order and the required flag when
revising an existing profile. Nested expressions open in their own JSON field.
Applying validates the proposed definition with the control-plane decoder and
updates only the open draft. Saving and publishing follow the regular device
capability, authority and revision checks.

A `routeChecks` control row, rendered as `route_checks` in the engine document,
contains exactly one of the existing `checks` array and the new `profile` object.
It never flattens or silently downgrades a profile. Legacy ordered all-of checks,
their serialized form, method validation and native proof hash remain unchanged.

The closed [profile schema](../contracts/v1/route-check-profile-v2.schema.json)
and [common vectors](../contracts/v1/route-check-profile-v2-vectors.json) are locked
in both repositories. The syntax is data rather than remotely executable code:

```json
{
  "outbound": "public-ru",
  "required": true,
  "profile": {
    "schemaVersion": 2,
    "id": "ru-connectivity",
    "revision": 1,
    "deadlineMs": 12000,
    "leaves": [
      {"id":"exit","check":{"method":"https_exit_country","target":"https://exit.example.invalid/","expected_exit_class":"RU"}},
      {"id":"a","check":{"method":"https_204","target":"https://a.example.invalid/probe"}},
      {"id":"b","check":{"method":"https_204","target":"https://b.example.invalid/probe"}}
    ],
    "gates": ["exit"],
    "stages": [{"any":[{"leaf":"a"},{"leaf":"b"}]}]
  }
}
```

The example endpoints are synthetic. Their names do not establish an exit country.
An actual country probe uses the existing strict response predicate and trust
rules through the measured path. HTTP redirects or a familiar host alone never
prove the exit or tunnel.

Profiles have one to four unique named primitive checks. Each declared leaf is
referenced exactly once across gates and stages. Duplicate check definitions,
unknown or unused references, explicit nulls, extra fields and non-integer numeric
tokens are rejected. IDs match `[a-z][a-z0-9._-]{0,63}`, revisions range from1 to
9007199254740991, and the profile deadline ranges from1 to12000 milliseconds.
Targets use bounded printable ASCII, lowercase DNS without a trailing dot or an
unscoped numeric IP, and at most five decimal port digits. Backslashes, URL user
information and fragments are rejected. Existing method-specific HTTPS and exit
predicates still apply; these rules do not add a redirect or protocol fallback.

An expression is exactly `{"leaf":"id"}`, `{"all":[Expr,...]}`,
`{"any":[Expr,...]}` or `{"quorum":{"k":2,"of":[Expr,...]}}`. An operator
has two to four children, and `k` lies between1 and its child count. There are at
most seven expression nodes across all stages, at most four levels per expression
and at most four sequential stages. Gates and stages cannot both be empty.

## Mandatory checks and bounded execution

Gates run first in their declared order. Stages then run sequentially. Both lists
form an implicit all-of. All explicit TLS, exit-IP and exit-country leaves must
be unconditional gates, outside optional alternatives. A public RU/NON_RU adaptive
group also needs a matching country gate. Every transport retains its own normal
certificate/name, proxy authentication and SSH host-key checks on every dial.

All/any/quorum use three-valued logic. `TRUE` means the predicate is established,
`FALSE` means it is disproved by completed observations, and `UNKNOWN` means the
available observations do not decide it. An any-of can succeed after one failed
endpoint; a quorum can succeed once enough children succeed. Short circuiting
marks unexecuted leaves `SKIPPED`. Unknown children can be followed by other
children, but an unknown required gate or stage prevents a successful whole plan.

Cancellation, profile or batch deadline, physical-network/context change, expired
lease or an invalid BOOTTIME fence invalidates the whole result as `UNKNOWN`,
including any earlier partial true or false result. These conditions create no
negative proxy evidence. The legacy distinction between a completed primitive
`check_timeout` and an expired parent budget remains intact.

Each adaptive negative witness belongs to the exact completed leaf whose admitted
dispatch was observed. A successful sibling's I/O cannot attribute another leaf's
local or unknown failure. An aggregate success ignores failed optional branches
for quarantine. Mandatory exit mismatch keeps its separate current-path withdrawal
rule; a later successful optional target cannot override it.

The existing three-second primitive deadline, twelve-second adaptive deadline,
thirty-second ordinary batch deadline, two ordinary workers, one adaptive owner
and current admission limits remain hard local ceilings. All declared leaves count
toward admission, including those that might later be skipped. Route metadata
retains its24000-byte limit and native requests their32768-byte limit. A policy
cannot create extra workers or raise these bounds.

In this initial component, ordinary v2 profiles use a concrete static HTTP/SOCKS/
VLESS/SSH path, optionally ending in direct, or a direct path. The path has at most
four nodes, and a direct node is terminal. Ordinary selectors, variable detours,
NetBird and selector-based legacy failover with v2 profiles are unsupported and
must be rejected before activation. Managed adaptive profiles use an independently
owned, pinned concrete candidate. Legacy checks and legacy failover are unchanged.
Supporting more path forms requires their own capture and acceptance work.

## Authority and rollout

The signed capability `route.check-plan.v2` is required exactly when a valid v2
profile is present, together with `route.health.v1` and every applicable existing
exit capability. The compiler and independent issued-engine validator inspect the
profile's real leaves and mandatory gates. Shared enrollment grants cannot request
this advanced capability or bypass per-device configuration approval. Missing
client capability is a rejection before publication, with no fallback to all-of.

Normal enrollment's advertised capabilities and approved device capability history
remain unchanged in this component. The new evaluator remains unadvertised pending
a coordinated capability rollout; existing assignment checks continue rejecting
unsupported delivery. Source or synthetic-client tests do not constitute approval
to change a real enrollment or managed policy.

The native owner copies and validates the whole plan. For v2 its proof hash is
SHA256 over the UTF-8 prefix `syn443-route-check-plan-v2\n` followed by typed Go JSON:
`schemaVersion,id,revision,deadlineMs,leaves,gates,stages`, with leaves sorted by ID.
Each leaf has `id,check`; check fields retain `method,target,expected_ip?,expected_exit_class?`.
Gates, stages and expression children preserve their execution order. Go's normal
HTML escaping is part of those bytes. Empty arrays remain arrays rather than null.
Legacy checks retain their original slice hash without this prefix.

A request-supplied hash, matching profile ID/revision or read-only UI result is no
authority. Ordinary approved-plan comparison and adaptive receipts bind the complete
owned plan as well as their existing path/group/previous-selection/context fences.
Fresh lease, owner and BOOTTIME checks still run after the last leaf and immediately
before publishing a proof or using a result.
The profile deadline bounds evaluation and proof minting. A proof minted within
that budget retains its existing one-use receipt freshness and commit fences;
the profile deadline does not replace or extend the receipt lifetime.

Read-only diagnostics may expose at most four leaf IDs and fixed outcome/code pairs
under `checkPlan`, together with profile ID/revision and aggregate outcome. They
contain no probe URL, credentials or raw errors and cannot select or publish a route.

## Acceptance

The common fixture contains9 valid profiles with canonical hash goldens,37 invalid
profiles,6 malformed/raw inputs,51 truth/short-circuit cases and a legacy hash golden.
Codec, compiler, publisher and runtime suites execute in GitHub Actions. Required
negative checks cover mandatory gate hiding, unsupported clients and path forms,
whole-plan substitution, per-leaf failure attribution, cancellation and final-proof
fences. Actual two-hop wire checks are separate from pure truth-table cases.

No physical managed-profile, provider, LTE, battery, natural Doze or endurance
acceptance follows from this document. Deployment and a real capability-approved
profile on the phone need their own recorded evidence.

## Checking an exact HTTPS response status

An operator can attach an HTTPS check to an assigned outbound. For a dashboard or
internal service, use HEAD when the endpoint implements it. Use GET when the service
handles HEAD differently. Both forms compare the final response code exactly.

```json
{"method":"https_status","target":"https://service.example.invalid/health","http_method":"HEAD","expected_status":200}
```

The method accepts final status codes from 200 through 599. A redirect can itself
be the expected result. The probe opens one connection through the selected path,
validates the TLS certificate and hostname, and reads up to 8192 bytes of headers.
It skips at most four interim responses, closes the socket at the final headers,
and never requests a redirect destination or evaluates the response body.
Cancellation and the existing route deadlines apply. A matching status establishes
availability of this endpoint. Exit geography still requires a country check.

Both ordered checks and v2 profile leaves support this predicate. Its verb and
status travel in the signed engine configuration and participate in the proof hash.
Publication requires the device capability `route.https-status.v1` together with
`route.health.v1`. Existing clients can continue to receive their existing checks.
