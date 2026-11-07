# Technical telemetry ingestion

The device endpoint is disabled unless the enrollment API is configured with
`SYN443_TELEMETRY_INGEST=1` and its restricted database role passes startup
checks. It accepts closed DPoP-bound JSON batches of up to 32 events and
16 KiB. Device identity comes from the live session. The wire permits fixed
network, VPN, probe, route, policy, engine and overlay event codes. Names,
addresses, headers, raw errors, credentials and log attachments have no fields.

The SQL intake is insert-only for events. The primary key deduplicates event
IDs per device, and a separate counter limits ingestion to 256 events per
device per hour, including retry attempts. The API cannot read event bodies.

The separate retention role in `internal/telemetry/retention-roles.sql` is
allowed to read only keys and timestamps and delete expired telemetry. Run
`enrollment-admin telemetry-prune` with its DSN in
`SYN443_TELEMETRY_RETENTION_DSN_FILE`. One invocation removes at most 1,024
detailed events past 14 days and 1,024 budget rows past 48 hours. Operators
schedule pruning before enabling intake and monitor whether it catches up.

The initial API does not turn on Android uploads. Consent, a bounded durable
device queue, delivery scheduling, aggregation, operator views and retention
for backups and other telemetry categories require their own acceptance.
