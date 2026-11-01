# Read-only Remnawave resource pilot

This first M3 slice is a server-side adapter and an owner CLI. It does not add a
device protocol or automatically assign a provider catalogue to SYN443 users.
No live panel credential or provider URL is required by CI.

## Pinned API contract

The implemented subset follows official Remnawave 3.4 contracts at
`52321390ac4efe04a610811446d87335f1d10a93`:

- [Get user by ID](https://github.com/remnawave/backend/blob/52321390ac4efe04a610811446d87335f1d10a93/libs/contract/commands/users/get-user-by-id.command.ts)
- [User model](https://github.com/remnawave/backend/blob/52321390ac4efe04a610811446d87335f1d10a93/libs/contract/models/users.schema.ts)
- [Protected subscription by ID](https://github.com/remnawave/backend/blob/52321390ac4efe04a610811446d87335f1d10a93/libs/contract/commands/subscriptions/get-by/get-subscription-by-user-id.command.ts)
- [Subscription metadata](https://github.com/remnawave/backend/blob/52321390ac4efe04a610811446d87335f1d10a93/libs/contract/models/subscription-info.schema.ts)

The protected API uses numeric user IDs in this version. UUID-based older APIs
are not guessed or advertised as compatible. Resource API version must be 3.4.
The adapter calls only GET `/api/users/{id}` and GET
`/api/subscriptions/by-id/{id}` on the configured origin. Returned user ID, short
UUID, status and expiration must agree. It never follows subscriptionUrl or a
returned connection link and never calls a provider mutation endpoint.

## Authority and transport

Every binding carries resourceId plus externalUserId; namespaced object keys do
not collide across resources. The registry enables exactly one implemented
panel.remnawave instance. Disabled extension descriptors may be retained, but
x-ui/3x-ui, multiple enabled panels and unknown API versions are not working
adapters. A later device endpoint must intersect authenticated SYN443 assignment
authority with the external binding; the owner CLI is not such an endpoint.

The endpoint is an HTTPS origin without userinfo/path/query/fragment. Ordinary
TLS and optional owner-installed CA roots are verified. Redirects, environment
proxies and compressed API responses are disabled/rejected. Each new connection
resolves at most eight addresses and rejects the whole set if any address is
forbidden. Non-public/private/link-local/special ranges require an explicit owner
CIDR grant. A returned URL cannot redirect this transport into another service.
The adapter permits two concurrent assignments, rejects excess admission without
an unbounded queue, has a 12-second total deadline and caps response bytes/headers,
JSON depth/items, link count/size and credential sizes. Close cancels active work;
late results cannot become a successful snapshot.

Duplicate JSON keys, cross-user metadata, invalid counts, inactive/expired
accounts and empty/suspicious snapshots are explicit failures. Errors expose fixed
codes and a retryable flag, not endpoints, bearer tokens or response bodies.
Resource/binding/client/snapshot ordinary and Go-syntax formatters are redacted.
No automatic retries or silent fallback reinterpret an access denial as success.

## Owner operation

`resource-inspect` reads an absolute, private regular configuration file and a
separate private credential file; symlinks and group/world-readable secret files
are refused. Secret-file parents cannot be group/world writable. Example config
contains only placeholders; supply real data outside the public repository:

```json
{"resourceId":"panel-a","providerType":"panel.remnawave","apiVersion":"3.4","endpoint":"https://panel.example.invalid","enabled":true,"credentialFile":"/run/syn443/private/remnawave-token","allowedNetworks":[]}
```

The optional certificateAuthorityFile holds trusted PEM roots. Public addresses
need no special network grant; a private panel requires narrow allowedNetworks.
No insecure-TLS or arbitrary HTTP option exists. API credentials are never sent
to Android or included in the normalized snapshot.

```text
resource-inspect -config /run/syn443/private/resource.json -user-id 42
resource-inspect -config /run/syn443/private/resource.json -user-id 42 -private-output /run/syn443/private/snapshot-0001.json
```

Default stdout contains only success/count/time metadata or a fixed error code.
Exit 0 means success; exit 1 means rejection/failure, with retryable in error JSON.
The explicit private export contains sensitive provider connection links and
scoped IDs. It creates a new file with mode 0600 and exclusive creation, never overwrites an
existing snapshot and leaves previous output untouched on provider failure.
The source body is not an already validated native-engine configuration.

## Acceptance and remaining M3 work

Actions runs Go/race tests using real temporary HTTPS servers: scoped endpoints,
credential headers, redirects, TLS rejection, malformed/duplicate/oversized JSON,
wrong users/versions, expired/denied access, cancellation/close/admission bounds,
precise integer metadata, namespace isolation and protected owner output. The CLI
is built into the existing runtime artifact with SHA256 inventory. JSON fuzzing
and package coverage thresholds remain mandatory; no local compilation is needed.

Still open: persistent SQL ResourceInstance/credential management, API capability
discovery/catalogue reconciliation, owner-to-SYN443 account linking, worker sync,
source diff/quarantine/retention, profile normalization/compilation, signed policy
publication, mobile edit/publish and administration UI. A live operator panel and
device provisioning from this adapter have not been accepted by synthetic tests.
Multiple Remnawave and x-ui/3x-ui remain extension contracts only. No LTE testing
or production/provider mutation is part of this slice.

Resource HTTP now uses the same `internal/egress` boundary as subscription fetches.
Every DNS answer and new connection is checked, including metadata addresses and
IPv4-mapped addresses. An internal-network grant cannot enable production
loopback. Literal loopback fixtures require the separately owner-configured
`fixtureLoopback` context; it is false by default and cannot apply to a public
hostname. Fixture flags are not device/admin resource-credential fields.
