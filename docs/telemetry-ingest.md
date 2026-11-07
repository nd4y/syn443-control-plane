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
The response acknowledges exactly the submitted event IDs in order, and is
sent only after the transaction commits. A retry after response loss receives
the same acknowledgement within the ingestion budget.

The separate retention role in `internal/telemetry/retention-roles.sql` is
allowed to read only keys and timestamps and delete expired telemetry. Run
`enrollment-admin telemetry-prune` with its DSN in
`SYN443_TELEMETRY_RETENTION_DSN_FILE`. One invocation removes at most 1,024
detailed events past 14 days, 1,024 budget rows past 48 hours, and summaries
for four hours past 180 days. Operators schedule pruning before enabling
intake and monitor whether it catches up.

The separate `syn443_telemetry_analysis` role can summarize one settled
UTC hour with `enrollment-admin telemetry-aggregate <UTC-hour>` using
the format `YYYY-MM-DDTHH:00Z`.
Configure its DSN via `SYN443_TELEMETRY_ANALYSIS_DSN_FILE` and apply
`internal/telemetry/analysis-roles.sql` after the schema migration. It
has access only to received time, category, code, mode and duration.
Aggregates contain no device, session or route identifiers. Counters
include event count, measured count and total measured duration per group.
An hour needs at least one hour to settle and must still be inside the
detail retention window. A run exceeding 100,000 events or 256 groups
leaves the previous summary intact. Do not expose these SQL roles through
the control panel or the enrollment API.

For offline analysis, `enrollment-admin telemetry-summary <UTC-hour>`
returns versioned JSON for one selected hour. The reader uses the separate
`syn443_telemetry_reader` role from `internal/telemetry/report-roles.sql`
and `SYN443_TELEMETRY_READER_DSN_FILE`. This role can read only the
aggregate table. An hour without aggregate rows reports
`available: false`; it does not claim that no events were received.

Enabling ingestion does not turn on Android uploads without device consent.
End-to-end delivery, scheduled analysis, operator views and retention for
backups and other telemetry categories require their own acceptance.
