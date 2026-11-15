REVOKE ALL ON identity_overlay_resource_versions FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_overlay_resource_invariants() FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='syn443_overlay_worker') THEN
  GRANT SELECT ON identity_overlay_resource_versions TO syn443_overlay_worker;
 END IF;
END $$;
