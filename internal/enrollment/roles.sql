-- Run as the migration owner after creating NOINHERIT/NOBYPASSRLS non-owner LOGIN roles
-- syn443_identity_api and syn443_identity_publisher. Passwords are operator-managed, not in SQL.
-- These roles must have no membership in each other, the owner or any privileged role.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO syn443_identity_api,syn443_identity_publisher;
GRANT SELECT,UPDATE(second) ON identity_clock TO syn443_identity_api,syn443_identity_publisher;
-- PostgreSQL row locks require UPDATE on a column; the harmless guard grants no assignment authority.
GRANT SELECT,UPDATE(lock_guard) ON identity_accounts TO syn443_identity_api,syn443_identity_publisher;
GRANT SELECT ON identity_devices TO syn443_identity_api,syn443_identity_publisher;
GRANT INSERT(id,owner,jkt,request_body,receipt),UPDATE(active,request_body,receipt,retry_after)
 ON identity_devices TO syn443_identity_api;
GRANT UPDATE(approved,publication,revision,refresh_after,offline_until,retry_after,publication_error)
 ON identity_devices TO syn443_identity_publisher;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity_challenges,identity_sessions,identity_refresh_history,
 identity_replays,identity_requests,identity_revocations,identity_owner_revocations TO syn443_identity_api;
-- Publisher cannot mint or inspect device session hashes, challenges or idempotent replies.
REVOKE ALL ON FUNCTION identity_device_invariants() FROM PUBLIC;
