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

### Capacity during reconnects

When intake is enabled, each enrollment API instance reserves a separate pool
of two database connections for uploads. The ordinary enrollment pool has four
connections. Include both pools in the PostgreSQL connection budget for each
replica. Disabling intake closes the upload path on the next service start.

The upload handler admits two concurrent requests and tracks up to 512 peer
addresses independently of policy delivery. Each address can submit 120
requests per minute. A full upload lane returns HTTP 503 with a five-second
retry hint before waiting for SQL. An exhausted address window returns HTTP
429. Session refresh and policy fetch retain their own admission budget for
devices behind the same gateway. A waiting upload checks its device session
again before inserting. Clients retry with a fresh proof and the same event
IDs after refreshing an expired or rotated session.

Both pools use the current identity API role in this deployment. The device
session, revocation checks, and event insertion share one SQL transaction.
Physical server capacity, database locks and a database outage can still
affect both pools.

### Standalone ingest process

The Linux release includes `telemetry-ingest`. Apply the enrollment schema
migration, create the `syn443_telemetry_ingest` login with NOINHERIT and
NOBYPASSRLS, and apply `internal/enrollment/ingest-roles.sql` as the owner.
The new process checks its role and its public-table column privileges at
startup and on readiness. Its login can lock the rows that bind each request
to a live device session. Device session refresh and enrollment handle expiry
of the shared proof replay records. Ingest can insert a proof once. It has
no access to refresh hashes, signed policies or historical event contents.

Set `SYN443_TELEMETRY_CONFIG` to an owner-only JSON file with `listen` (a
loopback address and port), `origin` (the existing public enrollment HTTPS
origin), `databaseFile` (the owner-only DSN file), `certificate` and
`certificateKey`. The ingest process uses its own two SQL connections. No
policy encryption key, identity provider credential or signing key is required.
Set up the edge proxy in the same network namespace to forward the exact
`/v1/device/telemetry` path to this listener. Preserve the original request
body and headers so the device's DPoP proof covers the public URI. Limit
`/livez` and `/readyz` to the service network.

#### Small-server Compose service

Download `telemetry-ingest-image-linux-amd64` from the protected release
workflow. Check `SOURCE.txt` against the chosen commit, run
`sha256sum -c SHA256SUMS` in the extracted directory and load the image with
`docker load -i telemetry-ingest.tar.gz`. Set `SYN443_TELEMETRY_IMAGE` to
the resulting `syn443-telemetry-ingest:<commit>` tag.

Set `SYN443_INGRESS_CONTAINER` to the existing reverse proxy container and
`SYN443_TELEMETRY_PRIVATE_DIR` to a private directory readable by UID 65532.
Place only the ingest configuration, its DSN and its server TLS files there.
Name the configuration `config.json` and use paths under
`/run/syn443/telemetry/` for its files. Give the private configuration,
DSN and key mode 0400 with that UID as owner. The service shares the
proxy's network namespace so its numeric loopback listener stays private.

Run `docker compose -f deploy/telemetry-ingest/compose.yaml up -d` and
inspect the container's health before switching the edge route. The image
runs as a non-root user with a read-only filesystem, a 128 MiB memory cap,
half a CPU and 64 processes. Its built-in check sends HEAD to the local
ingest readiness endpoint and verifies the response belongs to this service.
TLS uses the configured certificate bundle and the public origin's hostname.
Set the optional `readinessServerName` when the local listener's certificate
names an internal ingress host. The probe always dials the configured
loopback socket. It sends no device proof and opens no additional SQL pool.

The hosted container fixture uses the packaged binary and a disposable SQL
server on runner loopback. It checks Docker health, signed uploads, replay,
revocation, deduplication and continued policy delivery after stopping
ingest. The separate Compose service requires its own live cutover check.

Once the listener passes readiness and the ingress route is in place, set
`SYN443_TELEMETRY_INGEST=external` on enrollment. Policy responses advertise
telemetry. Enrollment itself serves only its other routes in this mode.
Existing deployments can continue to use `1` for embedded intake. During
cutover both modes share the same session, replay and event records. For a
rollback, restore embedded intake on enrollment and point the edge route
back to it before stopping the separate process. A failed ingest request
can be retried with a fresh proof and the same event IDs.

The separate retention role in `internal/telemetry/retention-roles.sql` is
allowed to read only keys and timestamps and delete expired telemetry. Run
`enrollment-admin telemetry-prune` with its DSN in
`SYN443_TELEMETRY_RETENTION_DSN_FILE`. One invocation removes at most 1,024
detailed events past 14 days, 1,024 budget rows past 48 hours, and summaries
for four hours past 180 days.

For periodic cleanup, run `enrollment-admin telemetry-prune-worker` as a
separate process with just that retention DSN file. The worker attempts one
transaction immediately and waits a minute after it finishes before trying
again. Each transaction gets 15 seconds, uses the database clock, checks
the dedicated login and its column privileges, and takes a nonblocking
database lock to avoid overlapping scheduled deletion. A failed attempt
emits a fixed diagnostic. Successful deletion reports only counts. Stop the
process to revert to manual pruning. Already expired rows removed in a
successful transaction are not restored by stopping the worker.

Configure a private PostgreSQL URL with an explicit host, port, database, the
`syn443_telemetry_retention` login and certificate verification. Use
`sslmode=verify-full` with the system trust store for remote databases.
Start the worker without other PostgreSQL connection settings in its
environment. The process rejects a backward database clock within its
lifetime. Keep database time synchronized and monitor backlog before enabling
intake. Live deployment, retention of backup copies and scheduling for other
data categories each require their own acceptance.

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
leaves the previous summary intact. Keep the analysis and retention SQL roles
out of the control panel and the enrollment API.

An external scheduler can run `enrollment-admin telemetry-aggregate-settled`
once per hour. This command takes no arguments and uses the dedicated analysis
DSN file, an explicit PostgreSQL URL and full certificate verification for
remote databases. Run it in a separate job with a synchronized clock and one
instance per schedule. The command rejects database clock skew over two minutes
and validates the analysis login and privileges inside the transaction.

The enrollment integration suite generates a temporary CA and a server
certificate for its disposable PostgreSQL instance. It runs the analysis
executable with the dedicated database login. It checks a trusted connection
and rejection of both an incorrect server name and an unknown CA.

Each invocation uses the database clock to select the latest UTC hour that has
been closed for at least one hour. It gets 15 seconds and shares the manual
command's transaction lock for that hour. Overlapping calls can retry the same
hour. The job emits the UTC hour and aggregate counts after commit. An empty
hour produces zero counts and no rows for the read-only summary.

For continuous operation, start `enrollment-admin telemetry-aggregate-worker`
as a separate service or container with the same analysis DSN file. It starts
immediately, processes up to one missing nonempty UTC hour in a 15-second
transaction, then waits one minute. It uses indexed time ranges over the
complete hours still inside the 14-day detail window. A locked or over-budget
hour can be retried after other hours have had a turn. If the service restarts,
committed summaries identify the completed hours. Empty hours stay unavailable.
The existing manual hour command can recompute a previously summarized hour.
SIGTERM stops the worker. Both scheduling options use the existing per-hour
transaction lock and preserve the event and group limits.

For offline analysis, `enrollment-admin telemetry-summary <UTC-hour>`
returns versioned JSON for one selected hour. The reader uses the separate
`syn443_telemetry_reader` role from `internal/telemetry/report-roles.sql`
and `SYN443_TELEMETRY_READER_DSN_FILE`. This role can read only the
aggregate table. An hour without aggregate rows reports
`available: false`; it does not claim that no events were received.

The administrative web console can request the same aggregate for one UTC hour
via `telemetry.summary.get`. Set `SYN443_TELEMETRY_READER_DSN_FILE` for
`control-api` to a private file containing a DSN for the dedicated reader. The
API validates the dedicated non-inheriting reader role and its privileges on
startup and uses a separate pool. With
no setting the action is disabled. Only a live, explicit catalog ACL for
`telemetry.summary.get / telemetry / global` grants access; a wildcard grant,
a support chat session or a device session is insufficient. The read audit
records the actor, hour and request ID before the result is returned. No raw
events, identifiers, route tags or targets are returned.

The optional view is hidden with HTTP 404 when disabled or when a valid
console administrator has no telemetry grant. A rejected console identity or
revoked console access still uses the existing session or authorization
failure. The browser clears administrative state in that case.

The UI distinguishes an unavailable hour from an available aggregate and shows
the mean duration only for timed events. It keeps the result in page memory and
clears it when the selected hour changes, on logout and on session expiry.
The console is a read-only operational view.

Enabling ingestion does not turn on Android uploads without device consent.
End-to-end delivery, live scheduling, cohort comparisons, incident analysis,
device erasure and retention for backups and other categories require their
own acceptance.

The hourly summary counts confirmed route reselections by the baseline and
conservative algorithms when Android includes a verified policy revision.
The analysis view exposes a bounded variant label to the worker. It does
not grant access to raw policy revisions, raw algorithm revisions, devices
or sessions. The report role still reads only hourly rows. Unknown revisions
and older clients contribute to the total reselection count with no variant
attribution. These are event counts and cannot measure rollout eligibility
or success rates. Older stored hourly rows have zero attributed events.
