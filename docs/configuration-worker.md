# Independent configuration worker

`configuration-worker` consumes the existing administrative configuration queue
and publishes reviewed configuration heads. It does not enroll devices, issue
VPN leases, acknowledge activation or create administrative access.

Run this executable separately when bootstrapping managed configuration. Merely
mounting configuration inputs into the ordinary `enrollment-worker` also enables
its `NetworkAuthority`: approved devices without an assigned managed head then
cannot renew their ordinary policy. This worker provides no unassigned fallback
and does not change the enrollment worker's configuration or behavior.

## Inputs

The process reads exactly these environment variables:

- `SYN443_CONFIGURATION_WORKER_CONFIG`: owner-only regular JSON file, at most
  65,536 bytes.
- `SYN443_CONFIGURATION_SIGNING_KEY_FILE`: owner-only PKCS#8 P-256 private key;
  mount it read-only. The worker never writes this file.
- `SYN443_CONFIGURATION_KEY_ID`: an exact key ID from the configured public roots.

The runtime JSON has exactly two members:

```json
{
  "database": "host=db.example.invalid port=5432 user=syn443_identity_publisher dbname=syn443 sslmode=verify-full",
  "configuration": {
    "controlOrigin": "https://control.example.invalid",
    "issuer": "https://id.example.invalid/realms/admin",
    "audience": "syn443-control-api",
    "clientIds": ["syn443-control-web", "syn443-control-mobile"],
    "assuranceAcr": "urn:syn443:loa:2",
    "layerEncryptionKey": "<base64 encoding of the existing 32-byte layer key>",
    "sourceEncryptionKey": "<base64 encoding of the existing distinct 32-byte source key>",
    "roots": {"configuration-root": "<base64 P-256 public SPKI>"}
  }
}
```

These are placeholders, not a deployable configuration. Reuse the matching layer
and source keys from their existing compartments. The layer store receives only
the layer key; the source store receives only the source key. No identity
encryption key, enrollment config/grants, invitation file or overlay credential
is read or accepted. The administrative issuer is pinned independently of the
device realm, and the private signing key must match its configured key ID/root.

## Database and authority

The owner must have applied the existing configuration schema, roles and grants.
The process uses the existing restricted `syn443_identity_publisher` SQL role.
Both `ConfigurationRuntimeRole(..., true)` and source `PublicationRole` run before
administrative discovery or receipt access. A different/current session role,
unsafe role flags, inherited authority or incorrect table grants stops startup.

The new runtime supports one database endpoint. A pgx fallback with a different
host or port is rejected, including a loopback primary followed by a remote host.
The existing verified-TLS rules apply to every non-loopback connection; the
existing exact `127.0.0.1` exception permits a local database. Remote plaintext,
unverified TLS and TLS-to-plaintext fallbacks are rejected. Unix sockets and
multi-endpoint failover are not supported by this worker.

The existing publisher independently checks original token/DPoP receipts, fresh
MFA where required, live object ACL, preview tickets and source/layer fences.
There is no direct-head command, fabricated receipt path or automatic grant.
Publication is a desired-head result; device policy delivery and native
activation remain separate stages.

## Lifecycle

Startup role checks and pinned HTTPS discovery share a 15-second deadline. One
serial loop obtains time from the existing database identity clock, then calls
`ConfigurationPublisher.RunOnce` under a 20-second step deadline; the publisher
also retains its existing 18-second inner bound. A failed clock prevents that
publication attempt. No wall-clock fallback or overlapping catch-up queue exists.

The worker waits two seconds between completed steps. SIGINT/SIGTERM cancels
startup, database/provider work, an active step and the idle wait; it joins the
active synchronous operation and closes its DB pool. If a step fails, stderr
contains only `configuration_step_unavailable`. Startup/panic failure uses only
`configuration_worker_failed`; SQL URLs, credentials, provider errors and
configuration bodies are not printed.

Builds and executable checks belong in GitHub Actions. Unit source covers closed
runtime parsing, DSN/key/role rejection, actual fixture TLS issuer discovery,
encryption compartments, database-clock ordering, cancellation and serial loop
ownership. Metadata-driver unit tests do not establish real PostgreSQL role,
queue publication, device delivery or physical acceptance; existing PostgreSQL
publisher tests and explicit deployment checks remain necessary.
