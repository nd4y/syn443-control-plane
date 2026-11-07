REVOKE ALL ON identity_capability_versions,identity_capability_heads,identity_capability_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_capability_version_invariants(),identity_capability_head_invariants(),identity_capability_request_invariants() FROM PUBLIC;
GRANT SELECT ON identity_capability_versions,identity_capability_heads TO syn443_identity_api;
GRANT SELECT,INSERT ON identity_capability_versions TO syn443_identity_publisher;
GRANT SELECT,INSERT,UPDATE(revision,body_hash) ON identity_capability_heads TO syn443_identity_publisher;
GRANT SELECT,INSERT(device,request_id,owner,jkt,grant_hash,request_hash,body,receipt,accepted_ms,deadline_ms,auth_kind,session_id,session_generation) ON identity_capability_requests TO syn443_identity_api;
GRANT SELECT,UPDATE(state,receipt,result_revision,result_hash,error_code),DELETE ON identity_capability_requests TO syn443_identity_publisher;
REVOKE ALL ON FUNCTION identity_capability_session_fence(text,text,bigint,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity_capability_session_fence(text,text,bigint,text,text,bigint) TO syn443_identity_publisher;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='syn443_control_api') THEN
  GRANT SELECT ON identity_capability_versions,identity_capability_heads TO syn443_control_api;
 END IF;
END $$;
