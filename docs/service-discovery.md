# Public signed service discovery

This optional enrollment API module serves an explicitly owner-configured set of
public signed service descriptors. It wraps the existing HTTP server; it adds no
port, publisher, worker, DB role, IdP discovery, outbound fetch or signing-key
access. Publication workers remain unchanged. This is source preparation, not a
live deployment, Android refresh integration or native administrative SSO result.

`SYN443_SERVICE_DESCRIPTOR_CONFIG` is optional. An empty value preserves the exact
original handler and startup behavior. An explicit path must name a regular
owner-only file, with no group/other permission bits, at most262144 bytes. The
existing bounded file loader rejects symlinks and checks the opened file's
identity. Invalid explicit configuration fails before ordinary enrollment
configuration, database or IdP initialization; it never disables itself silently.

The closed JSON shape has exactly these required fields:

- `schemaVersion`: integer1.
- `publicAnchor`: the public `Anchor` object with exactly `id`, `spki`, `epoch`
  and `lastTransition`, following existing bootstrap validation.
- `descriptors`: between1 and32 raw signed service-descriptor JWS strings, each
  at most6144 ASCII bytes, with unique signed service IDs.

Unknown, case-variant, duplicate, null and missing members are rejected. Each
manifest passes existing `bootstrap.VerifyDescriptor` validation against that
configured public anchor and the startup clock. Only public endpoints and public
keys belong in this document. There is no credential, private root key, unsigned
administrative override or imported URL. The module owns immutable signed bytes
and validity fields; mutating the caller's input cannot change its catalogue.

The existing offline signing authority may produce descriptors containing the
optional closed `adminBootstrap` object. Descriptor revision/hash progression,
expiry and ordinary device projection remain client trust responsibilities.
Serving a descriptor does not install its root, grant an administrative role or
replace a device key/session. In particular, the generic Android installation
asset's isolated test root is not a production enrollment authority. A valid
production trust and signing-custody procedure remains a separate release gate.

The only served route is an anonymous bodyless `GET` to
`/.well-known/syn443/bootstrap/<serviceId>`, where the exact signed ID matches
`[A-Za-z0-9_-]{1,64}`. Encoded or absolute paths, extra slashes, query/fragment,
userinfo, alternate methods, transfer encoding, trailers and request bodies are
rejected. Authentication and Origin headers do not become authority, are not
reflected, and cannot enable an unknown service. No arbitrary URL, proxying or
credential forwarding exists. All unrelated paths retain the existing handler.

A valid response is the original JWS, without a newline, with
`Content-Type: application/jose`, a current HTTP `Date`, `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. Unknown or
expired services and malformed module requests return404 with no descriptor or
fallback body. A canceled admission publishes no response data. Descriptors are
checked against their signed issue/not-before/expiry bounds on every read.

One module-wide token bucket permits a burst of32 and refills at four requests
per second. It holds only bounded credit and a clock high-water mark behind one
mutex. Clock samples are normalized to UTC wall time without a monotonic component
before retention, comparison, refill and signed validity checks; it has no per-IP map, timer, queue or goroutine. Clock rollback cannot
refill or admit requests. Exhaustion returns429 without a descriptor. The
existing API server's header/body/time bounds remain in force.

There is no hot reload or automatic revocation feed. Replacing the owner
configuration requires the normal controlled API restart. A retired service ID
is absent from the replacement catalogue and cannot fall back to a different
service. An invalid replacement fails startup. Client floor checks reject older
signed descriptors independently; identical bytes do not extend their expiry.

Seven mandatory Go roots cover actual generated ES256 signatures, exact HTTP
bytes/headers and unchanged fallback, strict request/expiry/retirement boundaries,
closed owner configuration and32-service/byte limits, owned-copy behavior,
concurrent rate limits, clock rollback/cancellation, and startup ordering with the
real bounded owner-file loader. They require ordinary and race execution in
GitHub Actions. No executable test or build is run locally, and these synthetic
fixtures are not live service, phone, Keycloak, MFA or role acceptance.
