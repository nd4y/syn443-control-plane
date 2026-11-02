-- Owner migration only. A mutable draft/request is never an approved layer head.
CREATE TABLE IF NOT EXISTS managed_configuration_previews(
 id text PRIMARY KEY,actor text NOT NULL,request_id text NOT NULL,
 body_hash text NOT NULL,body bytea NOT NULL,ticket text NOT NULL,
 issued_at_ms bigint NOT NULL,expires_at_ms bigint NOT NULL,
 UNIQUE(actor,request_id),CHECK(expires_at_ms>issued_at_ms),
 CHECK(expires_at_ms-issued_at_ms<=180000),
 CHECK(octet_length(body) BETWEEN 29 AND 524316),
 CHECK(octet_length(ticket) BETWEEN 128 AND 90000)
);
CREATE TABLE IF NOT EXISTS managed_configuration_versions(
 device text NOT NULL REFERENCES identity_devices(id),revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 owner text NOT NULL REFERENCES identity_accounts(owner),jkt text NOT NULL,grant_hash text NOT NULL,
 actor text NOT NULL,preview text NOT NULL REFERENCES managed_configuration_previews(id),
 body_hash text NOT NULL,approved_at_ms bigint NOT NULL,approval_receipt bytea NOT NULL,
 PRIMARY KEY(device,revision),CHECK(octet_length(approval_receipt) BETWEEN 29 AND 131100)
);
CREATE TABLE IF NOT EXISTS managed_configuration_heads(
 device text PRIMARY KEY,revision bigint NOT NULL,body_hash text NOT NULL,
 guard integer NOT NULL DEFAULT 0,
 FOREIGN KEY(device,revision) REFERENCES managed_configuration_versions(device,revision)
);
CREATE OR REPLACE FUNCTION managed_configuration_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable configuration evidence'; END; $$;
DROP TRIGGER IF EXISTS managed_configuration_preview_guard ON managed_configuration_previews;
CREATE TRIGGER managed_configuration_preview_guard BEFORE UPDATE OR DELETE ON managed_configuration_previews FOR EACH ROW EXECUTE FUNCTION managed_configuration_immutable();
DROP TRIGGER IF EXISTS managed_configuration_version_guard ON managed_configuration_versions;
CREATE TRIGGER managed_configuration_version_guard BEFORE UPDATE OR DELETE ON managed_configuration_versions FOR EACH ROW EXECUTE FUNCTION managed_configuration_immutable();
CREATE OR REPLACE FUNCTION managed_configuration_head_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.device<>OLD.device OR (NEW.revision,NEW.body_hash) IS DISTINCT FROM (OLD.revision,OLD.body_hash) AND NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'configuration head CAS'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS managed_configuration_head_guard ON managed_configuration_heads;
CREATE TRIGGER managed_configuration_head_guard BEFORE UPDATE ON managed_configuration_heads FOR EACH ROW EXECUTE FUNCTION managed_configuration_head_invariants();
