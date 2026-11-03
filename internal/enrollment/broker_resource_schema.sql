-- Separate from the subscription catalog: provider PATs are never source-worker
-- input. Resource versions stay immutable for addressed broker cleanup.
CREATE TABLE IF NOT EXISTS identity_overlay_resource_versions(
 resource text NOT NULL,revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 body_hash text NOT NULL CHECK(length(body_hash)=43),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 29 AND 65564),
 created_ms bigint NOT NULL CHECK(created_ms>0),PRIMARY KEY(resource,revision)
);
CREATE OR REPLACE FUNCTION identity_overlay_resource_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable overlay resource history'; END; $$;
DROP TRIGGER IF EXISTS identity_overlay_resource_guard ON identity_overlay_resource_versions;
CREATE TRIGGER identity_overlay_resource_guard BEFORE UPDATE OR DELETE ON identity_overlay_resource_versions FOR EACH ROW EXECUTE FUNCTION identity_overlay_resource_invariants();
