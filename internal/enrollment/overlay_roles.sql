GRANT SELECT,UPDATE(lock_guard,envelope) ON identity_overlay_grants TO syn443_identity_api;
GRANT SELECT,INSERT,UPDATE(lock_guard,revoked,envelope) ON identity_overlay_grants TO syn443_identity_publisher;
GRANT SELECT,INSERT,UPDATE(consumed_ms) ON identity_overlay_deliveries TO syn443_identity_api;
REVOKE ALL ON FUNCTION identity_overlay_grant_invariants(),identity_overlay_delivery_invariants() FROM PUBLIC;
