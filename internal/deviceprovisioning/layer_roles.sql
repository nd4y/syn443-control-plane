GRANT SELECT,INSERT ON managed_configuration_previews,managed_configuration_versions TO syn443_identity_publisher;
GRANT SELECT,INSERT,UPDATE(revision,body_hash,guard) ON managed_configuration_heads TO syn443_identity_publisher;
-- Control reads still require live actor/object ACL in the service. No API or
-- fetch worker can turn a saved draft into an approved head or artifact.
GRANT SELECT ON managed_configuration_previews,managed_configuration_versions,managed_configuration_heads TO syn443_control_api;
REVOKE ALL ON FUNCTION managed_configuration_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION managed_configuration_head_invariants() FROM PUBLIC;
