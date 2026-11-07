-- Separate from the subscription catalog: provider PATs are never source-worker
-- input. Preserve immutable revision metadata after erasing obsolete ciphertext.
CREATE TABLE IF NOT EXISTS identity_overlay_resource_versions(
 resource text NOT NULL,revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 body_hash text NOT NULL CHECK(length(body_hash)=43),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 29 AND 65564),
 created_ms bigint NOT NULL CHECK(created_ms>0),PRIMARY KEY(resource,revision)
);
ALTER TABLE identity_overlay_resource_versions ADD COLUMN IF NOT EXISTS retired_ms bigint NOT NULL DEFAULT 0;
ALTER TABLE identity_overlay_resource_versions ALTER COLUMN body DROP NOT NULL;
ALTER TABLE identity_overlay_resource_versions DROP CONSTRAINT IF EXISTS identity_overlay_resource_retirement;
ALTER TABLE identity_overlay_resource_versions ADD CONSTRAINT identity_overlay_resource_retirement
 CHECK ((retired_ms=0 AND body IS NOT NULL) OR (retired_ms>created_ms AND body IS NULL));
CREATE INDEX IF NOT EXISTS identity_overlay_broker_resource_pins
 ON identity_overlay_broker(resource,resource_revision) WHERE state<>'retired' OR secret IS NOT NULL;
CREATE OR REPLACE FUNCTION identity_overlay_resource_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable overlay resource history'; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'overlay resource write requires read committed';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.retired_ms<>0 THEN RAISE EXCEPTION 'immutable overlay resource history'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('overlay-resource/'||NEW.resource,0));
  RETURN NEW;
 END IF;
 IF (NEW.resource,NEW.revision,NEW.body_hash,NEW.created_ms) IS DISTINCT FROM
    (OLD.resource,OLD.revision,OLD.body_hash,OLD.created_ms) OR OLD.retired_ms<>0 OR
    NEW.retired_ms<=OLD.created_ms OR NEW.body IS NOT NULL THEN
  RAISE EXCEPTION 'immutable overlay resource history';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('overlay-resource/'||OLD.resource,0));
 IF NOT EXISTS(SELECT 1 FROM identity_overlay_resource_versions v
   WHERE v.resource=OLD.resource AND v.revision>OLD.revision AND v.retired_ms=0)
 OR EXISTS(SELECT 1 FROM identity_overlay_broker b
   WHERE b.resource=OLD.resource AND b.resource_revision=OLD.revision
   AND (b.state<>'retired' OR b.secret IS NOT NULL)) THEN
  RAISE EXCEPTION 'overlay resource still pinned or current' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_overlay_resource_guard ON identity_overlay_resource_versions;
CREATE TRIGGER identity_overlay_resource_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_overlay_resource_versions FOR EACH ROW EXECUTE FUNCTION identity_overlay_resource_invariants();

-- The publisher need not read the resource catalog. Serialize new references
-- with retirement without granting access to its credentials or history.
CREATE OR REPLACE FUNCTION identity_overlay_resource_pin() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'overlay resource reservation requires read committed';
 END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('overlay-resource/'||NEW.resource,0));
 IF EXISTS(SELECT 1 FROM public.identity_overlay_resource_versions v
   WHERE v.resource=NEW.resource AND v.revision=NEW.resource_revision AND v.retired_ms<>0) THEN
  RAISE EXCEPTION 'overlay resource retired' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION identity_overlay_resource_pin() FROM PUBLIC;
DROP TRIGGER IF EXISTS identity_overlay_resource_pin_guard ON identity_overlay_broker;
CREATE TRIGGER identity_overlay_resource_pin_guard BEFORE INSERT ON identity_overlay_broker
 FOR EACH ROW EXECUTE FUNCTION identity_overlay_resource_pin();
