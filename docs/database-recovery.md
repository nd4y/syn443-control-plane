# Control plane database recovery

The enrollment CI job restores a PostgreSQL custom-format dump into a new
database inside its own disposable container. It reopens the API using the
restricted runtime role and the original synthetic store encryption key.
The drill compares the exact device-bound signed policy, message history and
idempotency receipt, verifies the restored file and its digest, and checks
that another account still cannot download it. A message created on the
source after the snapshot is absent from the restored history. The API role
still cannot truncate the chat tables. The fixture archive never leaves
the container.

For a real recovery, keep the database backup, encrypted key backups, and
the versioned role/migration definitions separate. The database dump includes
chat content and attachments and must be encrypted, access restricted and
retained under the service's backup policy. Recover the corresponding
encryption, signing and identity provider material through their approved
paths; these values do not belong in the dump, repository or CI.

1. Record the source backup timestamp, application/schema version, backup
   checksum, and which authorizations changed after the snapshot. Keep the
   running service and its rollback point intact.
2. Prepare an isolated target with the matching PostgreSQL major version,
   expected owners and roles. Leave device API traffic, provisioning,
   scheduled jobs and external workers disabled. Restore to an empty database
   with `pg_restore --single-transaction --exit-on-error`, preserving object
   ownership and ACLs. Do not restore in place over a running database.
3. Start the matching service version against the isolated database. Check
   migration/readiness, least privilege, a device's signed assignment and
   chat message/file integrity. Reconcile post-snapshot account, session,
   grant and overlay withdrawals before reopening access. Reconcile external
   operations with uncertain results before enabling workers.
4. Record actual data loss, elapsed recovery time and the rollback route.
   Switch traffic only after the security and application checks pass. Keep
   the original environment available for rollback until the restored
   installation is accepted.

The CI drill does not recreate cluster roles, recover Keycloak or external
provider state, measure production RPO/RTO, verify retention of backup copies,
or accept an Android APK/data migration.
