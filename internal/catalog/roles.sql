-- Roles are owner-created LOGIN NOINHERIT NOBYPASSRLS, with no cross-memberships.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO syn443_control_api,syn443_source_worker;
GRANT SELECT,UPDATE(second) ON catalog_clock TO syn443_control_api,syn443_source_worker;
GRANT SELECT,UPDATE(guard) ON catalog_acl TO syn443_control_api;
GRANT SELECT,INSERT,DELETE ON catalog_proofs TO syn443_control_api;
GRANT SELECT,INSERT,UPDATE ON catalog_resources TO syn443_control_api;
GRANT SELECT ON catalog_resources TO syn443_source_worker;
GRANT UPDATE(state,last_sync) ON catalog_resources TO syn443_source_worker;
GRANT SELECT,INSERT,UPDATE ON catalog_sources TO syn443_control_api;
GRANT SELECT ON catalog_sources TO syn443_source_worker;
GRANT UPDATE(active_snapshot,candidate_snapshot,state,last_sync,next_sync,fetch_cache,last_resource_revision) ON catalog_sources TO syn443_source_worker;
GRANT SELECT,INSERT,UPDATE,DELETE ON catalog_source_grants,catalog_dependencies TO syn443_control_api;
GRANT SELECT,INSERT,UPDATE ON catalog_share_heads TO syn443_control_api;
GRANT SELECT ON catalog_share_heads TO syn443_source_worker;
GRANT SELECT ON catalog_source_grants,catalog_dependencies TO syn443_source_worker;
GRANT SELECT,INSERT,UPDATE(state,reason) ON catalog_snapshots TO syn443_control_api,syn443_source_worker;
GRANT SELECT,INSERT,UPDATE ON catalog_jobs TO syn443_control_api,syn443_source_worker;
GRANT SELECT,INSERT,UPDATE,DELETE ON catalog_operations TO syn443_control_api;
GRANT INSERT(actor,action,target,request_id,observed_at,before_hash,after_hash,outcome),SELECT ON catalog_audit TO syn443_control_api;
GRANT INSERT(actor,action,target,request_id,observed_at,before_hash,after_hash,outcome) ON catalog_audit TO syn443_source_worker;
GRANT USAGE ON SEQUENCE catalog_audit_id_seq TO syn443_control_api,syn443_source_worker;
GRANT SELECT,INSERT,UPDATE ON catalog_outbox TO syn443_control_api,syn443_source_worker;
REVOKE ALL ON FUNCTION catalog_snapshot_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION catalog_audit_actor_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION catalog_source_immutable() FROM PUBLIC;
-- Neither source worker nor control API receives device session, signing key or
-- authority to approve identity publication. Additional signer grants are explicit.
