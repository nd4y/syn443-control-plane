-- Owner migration only. Runtime API and publication worker use separate restricted roles.
CREATE TABLE IF NOT EXISTS identity_clock (id boolean PRIMARY KEY CHECK(id), second bigint NOT NULL);
INSERT INTO identity_clock(id,second) VALUES(true,0) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS identity_accounts (
 owner text PRIMARY KEY, issuer text NOT NULL, subject text NOT NULL,
 enabled boolean NOT NULL, device_limit integer NOT NULL CHECK(device_limit BETWEEN 1 AND 16),
 valid_until bigint NOT NULL, grant_hash text NOT NULL, lock_guard integer NOT NULL DEFAULT 0,
 UNIQUE(issuer,subject)
);
CREATE TABLE IF NOT EXISTS identity_devices (
 id text PRIMARY KEY, owner text NOT NULL REFERENCES identity_accounts(owner), jkt text NOT NULL UNIQUE,
 active boolean NOT NULL DEFAULT true, request_body bytea NOT NULL, receipt bytea NOT NULL,
 approved boolean NOT NULL DEFAULT false, publication bytea, revision bigint NOT NULL DEFAULT 0,
 refresh_after bigint NOT NULL DEFAULT 0, offline_until bigint NOT NULL DEFAULT 0,
 retry_after bigint NOT NULL DEFAULT 0, publication_error text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS identity_challenges (
 owner text NOT NULL REFERENCES identity_accounts(owner), jkt text NOT NULL, nonce text NOT NULL,
 expires bigint NOT NULL, PRIMARY KEY(owner,jkt)
);
CREATE TABLE IF NOT EXISTS identity_sessions (
 id text PRIMARY KEY, device text NOT NULL REFERENCES identity_devices(id),
 access_hash text NOT NULL UNIQUE, refresh_hash text NOT NULL UNIQUE,
 access_until bigint NOT NULL, refresh_until bigint NOT NULL, generation bigint NOT NULL,
 nonce text NOT NULL, active boolean NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS identity_refresh_history (
 hash text PRIMARY KEY, session text NOT NULL REFERENCES identity_sessions(id), expires bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_replays (
 jkt text NOT NULL, jti text NOT NULL, expires bigint NOT NULL, PRIMARY KEY(jkt,jti)
);
CREATE TABLE IF NOT EXISTS identity_requests (
 owner text NOT NULL REFERENCES identity_accounts(owner), jkt text NOT NULL, kind text NOT NULL,
 request_id text NOT NULL, body_hash text NOT NULL, response bytea NOT NULL,
 session text NOT NULL REFERENCES identity_sessions(id), generation bigint NOT NULL,
 expires bigint NOT NULL, PRIMARY KEY(owner,jkt,kind,request_id)
);
CREATE TABLE IF NOT EXISTS identity_revocations (
 device text NOT NULL REFERENCES identity_devices(id), request_id text NOT NULL,
 body_hash text NOT NULL, access_hash text NOT NULL, jkt text NOT NULL, nonce text NOT NULL,
 expires bigint NOT NULL, PRIMARY KEY(device,request_id)
);
-- The API can insert an unapproved enrollment and revoke it, never revive it or change identity.
CREATE OR REPLACE FUNCTION identity_device_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.id<>OLD.id OR NEW.owner<>OLD.owner OR NEW.jkt<>OLD.jkt
    OR (NOT OLD.active AND NEW.active) OR (OLD.approved AND NOT NEW.approved)
    OR NEW.revision<OLD.revision THEN
   RAISE EXCEPTION 'immutable device identity';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_device_guard ON identity_devices;
CREATE TRIGGER identity_device_guard BEFORE UPDATE ON identity_devices FOR EACH ROW EXECUTE FUNCTION identity_device_invariants();
CREATE INDEX IF NOT EXISTS identity_device_work ON identity_devices(active,retry_after,refresh_after);
CREATE INDEX IF NOT EXISTS identity_replay_expiry ON identity_replays(expires);
CREATE INDEX IF NOT EXISTS identity_session_device ON identity_sessions(device);
CREATE INDEX IF NOT EXISTS identity_refresh_expiry ON identity_refresh_history(expires);
CREATE INDEX IF NOT EXISTS identity_request_expiry ON identity_requests(expires);
CREATE INDEX IF NOT EXISTS identity_revocation_expiry ON identity_revocations(expires);
