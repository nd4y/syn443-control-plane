-- Owner migration only. The provider worker has no identity/session/signing rights.
CREATE TABLE IF NOT EXISTS identity_overlay_broker_clock(id boolean PRIMARY KEY CHECK(id),second bigint NOT NULL);
INSERT INTO identity_overlay_broker_clock VALUES(true,0) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS identity_overlay_reference_heads(
 namespace text PRIMARY KEY, device text NOT NULL REFERENCES identity_devices(id),
 owner text NOT NULL REFERENCES identity_accounts(owner), jkt text NOT NULL,
 reference text NOT NULL,version bigint NOT NULL CHECK(version BETWEEN 1 AND 9007199254740991),
 permit_until_ms bigint NOT NULL CHECK(permit_until_ms>0),
 obsolete boolean NOT NULL DEFAULT false,retired boolean NOT NULL DEFAULT false
);
CREATE OR REPLACE FUNCTION identity_overlay_head_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.namespace,NEW.device,NEW.owner,NEW.jkt) IS DISTINCT FROM (OLD.namespace,OLD.device,OLD.owner,OLD.jkt)
 OR NEW.permit_until_ms<OLD.permit_until_ms OR (OLD.retired AND NOT NEW.retired)
 OR (NEW.reference,NEW.version) IS DISTINCT FROM (OLD.reference,OLD.version) AND (NEW.version<>OLD.version+1 OR NEW.reference=OLD.reference) THEN
 RAISE EXCEPTION 'immutable overlay reference identity'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_overlay_head_guard ON identity_overlay_reference_heads;
CREATE TRIGGER identity_overlay_head_guard BEFORE UPDATE ON identity_overlay_reference_heads FOR EACH ROW EXECUTE FUNCTION identity_overlay_head_invariants();
CREATE TABLE IF NOT EXISTS identity_overlay_broker (
 device text NOT NULL REFERENCES identity_devices(id), reference text NOT NULL,
 version bigint NOT NULL CHECK(version BETWEEN 1 AND 9007199254740991),
 owner text NOT NULL REFERENCES identity_accounts(owner), jkt text NOT NULL,
 namespace text NOT NULL, security_epoch bigint NOT NULL CHECK(security_epoch>=0), grant_hash text NOT NULL,
 resource text NOT NULL, resource_revision bigint NOT NULL CHECK(resource_revision>0),
 scope_hash text NOT NULL, scope bytea NOT NULL, operation text NOT NULL UNIQUE,
 deadline_ms bigint NOT NULL, created_ms bigint NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','dispatched','uncertain','issued','disabled','registered','established','unused','cleared','retired','blocked')),
 lease text NOT NULL DEFAULT '', lease_until_ms bigint NOT NULL DEFAULT 0,
 next_ms bigint NOT NULL DEFAULT 0, attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10000),
 dispatched_ms bigint NOT NULL DEFAULT 0, provider_id text NOT NULL DEFAULT '',
 provider_expires_ms bigint NOT NULL DEFAULT 0, provider_used bigint NOT NULL DEFAULT 0 CHECK(provider_used BETWEEN 0 AND 1),
 secret bytea, peer_evidence bytea, retire boolean NOT NULL DEFAULT false,
 error_code text NOT NULL DEFAULT '',
 PRIMARY KEY(device,reference,version), UNIQUE(namespace,reference,version),
 CHECK(secret IS NULL OR state='issued'), CHECK(state<>'retired' OR secret IS NULL)
);
CREATE INDEX IF NOT EXISTS identity_overlay_broker_work ON identity_overlay_broker(next_ms,lease_until_ms,state);
-- Credential withdrawal is independent of peer retirement. Ordinary permission
-- changes must stop new enrollment without deleting an established identity.
ALTER TABLE identity_overlay_broker ADD COLUMN IF NOT EXISTS withdraw_key boolean NOT NULL DEFAULT false;
CREATE OR REPLACE FUNCTION identity_overlay_broker_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.device,NEW.reference,NEW.version,NEW.owner,NEW.jkt,NEW.namespace,NEW.security_epoch,NEW.grant_hash,NEW.resource,NEW.resource_revision,NEW.scope_hash,NEW.scope,NEW.operation,NEW.deadline_ms,NEW.created_ms)
 IS DISTINCT FROM (OLD.device,OLD.reference,OLD.version,OLD.owner,OLD.jkt,OLD.namespace,OLD.security_epoch,OLD.grant_hash,OLD.resource,OLD.resource_revision,OLD.scope_hash,OLD.scope,OLD.operation,OLD.deadline_ms,OLD.created_ms)
 OR (OLD.retire AND NOT NEW.retire) OR (OLD.withdraw_key AND NOT NEW.withdraw_key) OR NEW.attempts<OLD.attempts OR NEW.provider_used<OLD.provider_used
 OR (OLD.provider_id<>'' AND NEW.provider_id<>OLD.provider_id)
 OR (OLD.provider_expires_ms<>0 AND NEW.provider_expires_ms<>OLD.provider_expires_ms)
 OR (OLD.dispatched_ms<>0 AND NEW.dispatched_ms<>OLD.dispatched_ms)
 OR (OLD.peer_evidence IS NOT NULL AND NEW.peer_evidence IS DISTINCT FROM OLD.peer_evidence)
 OR (OLD.state<>'queued' AND NEW.state='queued')
 OR (OLD.state='retired' AND NEW.state<>'retired') THEN
 RAISE EXCEPTION 'immutable overlay broker authority'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_overlay_broker_guard ON identity_overlay_broker;
CREATE TRIGGER identity_overlay_broker_guard BEFORE UPDATE ON identity_overlay_broker FOR EACH ROW EXECUTE FUNCTION identity_overlay_broker_invariants();
