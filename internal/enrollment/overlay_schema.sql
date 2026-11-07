-- Owner migration only. Addressed envelopes are immutable and encrypted at rest.
CREATE TABLE IF NOT EXISTS identity_overlay_grants (
 device text NOT NULL REFERENCES identity_devices(id), reference text NOT NULL,
 version bigint NOT NULL CHECK(version BETWEEN 1 AND 9007199254740991),
 owner text NOT NULL REFERENCES identity_accounts(owner), jkt text NOT NULL,
 namespace text NOT NULL, security_epoch bigint NOT NULL CHECK(security_epoch>=0),
 expires_ms bigint NOT NULL, envelope_hash text NOT NULL, envelope bytea,
 revoked boolean NOT NULL DEFAULT false, lock_guard integer NOT NULL DEFAULT 0,
 PRIMARY KEY(device,reference,version)
);
CREATE TABLE IF NOT EXISTS identity_overlay_deliveries (
 device text NOT NULL, reference text NOT NULL, version bigint NOT NULL,
 operation_id text NOT NULL, body_hash text NOT NULL, consumed_ms bigint,
 PRIMARY KEY(device,reference,version), UNIQUE(device,operation_id),
 FOREIGN KEY(device,reference,version) REFERENCES identity_overlay_grants(device,reference,version)
);
CREATE OR REPLACE FUNCTION identity_overlay_grant_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.device,NEW.reference,NEW.version,NEW.owner,NEW.jkt,NEW.namespace,NEW.security_epoch,NEW.expires_ms,NEW.envelope_hash)
 IS DISTINCT FROM (OLD.device,OLD.reference,OLD.version,OLD.owner,OLD.jkt,OLD.namespace,OLD.security_epoch,OLD.expires_ms,OLD.envelope_hash)
 OR (OLD.revoked AND NOT NEW.revoked) OR (NEW.envelope IS DISTINCT FROM OLD.envelope AND NEW.envelope IS NOT NULL) THEN
 RAISE EXCEPTION 'immutable overlay grant'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_overlay_grant_guard ON identity_overlay_grants;
CREATE TRIGGER identity_overlay_grant_guard BEFORE UPDATE ON identity_overlay_grants FOR EACH ROW EXECUTE FUNCTION identity_overlay_grant_invariants();
CREATE OR REPLACE FUNCTION identity_overlay_delivery_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.device,NEW.reference,NEW.version,NEW.operation_id,NEW.body_hash)
 IS DISTINCT FROM (OLD.device,OLD.reference,OLD.version,OLD.operation_id,OLD.body_hash)
 OR (OLD.consumed_ms IS NOT NULL AND NEW.consumed_ms IS DISTINCT FROM OLD.consumed_ms) THEN
 RAISE EXCEPTION 'immutable overlay operation'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_overlay_delivery_guard ON identity_overlay_deliveries;
CREATE TRIGGER identity_overlay_delivery_guard BEFORE UPDATE ON identity_overlay_deliveries FOR EACH ROW EXECUTE FUNCTION identity_overlay_delivery_invariants();
