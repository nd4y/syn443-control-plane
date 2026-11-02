GRANT SELECT,INSERT,UPDATE(retire) ON identity_overlay_broker TO syn443_identity_publisher;
GRANT SELECT(device,reference,version,owner,jkt,namespace,security_epoch,grant_hash,deadline_ms,state,retire)
 ON identity_overlay_broker TO syn443_identity_api;
REVOKE ALL ON FUNCTION identity_overlay_broker_invariants() FROM PUBLIC;
-- Optional worker role is installed separately. Existing API/publisher deployments
-- need not enable the broker; migration never creates privileged runtime roles.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='syn443_overlay_worker') THEN
  GRANT USAGE ON SCHEMA public TO syn443_overlay_worker;
  GRANT SELECT,UPDATE(second) ON identity_overlay_broker_clock TO syn443_overlay_worker;
  GRANT SELECT,UPDATE(state,lease,lease_until_ms,next_ms,attempts,dispatched_ms,provider_id,provider_expires_ms,provider_used,secret,peer_evidence,error_code)
   ON identity_overlay_broker TO syn443_overlay_worker;
 END IF;
END $$;
