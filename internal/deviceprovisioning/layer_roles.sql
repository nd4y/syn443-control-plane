GRANT SELECT,INSERT ON managed_configuration_previews,managed_configuration_versions TO syn443_identity_publisher;
GRANT SELECT,INSERT,UPDATE(revision,body_hash,guard) ON managed_configuration_heads TO syn443_identity_publisher;
-- Control reads still require live actor/object ACL in the service. No API or
-- fetch worker can turn a saved draft into an approved head or artifact.
GRANT SELECT ON managed_configuration_previews,managed_configuration_versions,managed_configuration_heads TO syn443_control_api;
GRANT SELECT ON managed_configuration_requests TO syn443_control_api,syn443_identity_publisher;
GRANT INSERT(id,actor,request_id,action,target_kind,target_id,created_ms,deadline_ms,body_hash,receipt) ON managed_configuration_requests TO syn443_control_api;
GRANT UPDATE(state,lease,lease_until_ms,next_ms,attempts,error_code,result) ON managed_configuration_requests TO syn443_identity_publisher;
REVOKE ALL ON FUNCTION managed_configuration_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION managed_configuration_head_invariants() FROM PUBLIC;
REVOKE ALL ON FUNCTION managed_configuration_request_invariants() FROM PUBLIC;
GRANT SELECT,INSERT ON managed_configuration_layer_versions TO syn443_identity_publisher;
GRANT SELECT,INSERT,UPDATE(revision,body_hash) ON managed_configuration_layer_heads TO syn443_identity_publisher;
GRANT SELECT,INSERT,UPDATE,DELETE ON managed_configuration_assignments TO syn443_identity_publisher;
GRANT SELECT ON managed_configuration_layer_versions,managed_configuration_layer_heads,managed_configuration_assignments TO syn443_control_api;
REVOKE ALL ON FUNCTION managed_configuration_layer_head_invariants() FROM PUBLIC;
