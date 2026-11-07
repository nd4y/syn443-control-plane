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
GRANT UPDATE(active_snapshot,candidate_snapshot,state,access_state,last_sync,next_sync,fetch_cache,last_resource_revision) ON catalog_sources TO syn443_source_worker;
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
REVOKE ALL ON FUNCTION catalog_terminal_input_erasure() FROM PUBLIC;
DO $$BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='syn443_identity_api') THEN
  GRANT EXECUTE ON FUNCTION catalog_control_panel_expiry(text,bigint) TO syn443_identity_api;
 END IF;
END$$;
-- Neither source worker nor control API receives device session, signing key or
-- authority to approve identity publication. Additional signer grants are explicit.

-- Optional independent signer reader. It receives no source/provider secrets,
-- fetch jobs, mutation rights or administrative grants.
DO $$BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='syn443_identity_publisher') THEN
  GRANT USAGE ON SCHEMA public TO syn443_identity_publisher;
  GRANT SELECT(id,owner,revision,spec,salt,mode,resource_id,enabled,valid_until,refresh_seconds,max_stale_seconds,active_snapshot,candidate_snapshot,state,access_state,last_sync,next_sync,last_resource_revision,fetch_device_id) ON catalog_sources TO syn443_identity_publisher;
  GRANT SELECT(id,revision,enabled) ON catalog_resources TO syn443_identity_publisher;
  GRANT SELECT ON catalog_snapshots,catalog_source_grants,catalog_share_heads TO syn443_identity_publisher;
  GRANT UPDATE(selection_guard) ON catalog_sources,catalog_resources TO syn443_identity_publisher;
 END IF;
END$$;

-- Unapproved drafts are API-owned staging. Fetch workers and the independent
-- signer receive no draft-body access or authority to treat them as active.
GRANT SELECT,INSERT,UPDATE ON catalog_network_drafts TO syn443_control_api;
REVOKE ALL ON FUNCTION catalog_network_draft_guard() FROM PUBLIC;
