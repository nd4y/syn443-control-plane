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
-- The stamp prevents an older publisher binary from attributing a later
-- issuance to the managed configuration recorded by a newer binary.
ALTER TABLE identity_devices ADD COLUMN IF NOT EXISTS publication_source_policy_revision bigint NOT NULL DEFAULT 0
 CHECK(publication_source_policy_revision BETWEEN 0 AND revision);
ALTER TABLE identity_devices ADD COLUMN IF NOT EXISTS publication_source_revision bigint NOT NULL DEFAULT 0
 CHECK(publication_source_revision BETWEEN 0 AND 9007199254740991);
ALTER TABLE identity_devices ADD COLUMN IF NOT EXISTS publication_source_hash text NOT NULL DEFAULT ''
 CHECK ((publication_source_policy_revision=0 AND publication_source_revision=0 AND publication_source_hash='')
     OR (publication_source_policy_revision>0 AND publication_source_revision>0 AND publication_source_hash ~ '^[0-9a-f]{64}$'));
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
CREATE TABLE IF NOT EXISTS identity_owner_revocations (
 owner text NOT NULL REFERENCES identity_accounts(owner), auth_jkt text NOT NULL,
 request_id text NOT NULL, body_hash text NOT NULL, expires bigint NOT NULL,
 PRIMARY KEY(owner,auth_jkt,request_id)
);
-- The API can insert an unapproved enrollment and revoke it, never revive it or change identity.
CREATE OR REPLACE FUNCTION identity_device_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.id<>OLD.id OR NEW.owner<>OLD.owner OR NEW.jkt<>OLD.jkt
    OR (NOT OLD.active AND NEW.active) OR (OLD.approved AND NOT NEW.approved)
    OR (OLD.approved AND (NEW.request_body,NEW.receipt) IS DISTINCT FROM (OLD.request_body,OLD.receipt))
    OR NEW.revision<OLD.revision
    OR (OLD.publication_source_policy_revision>0 AND OLD.publication_source_policy_revision=OLD.revision
        AND NEW.revision=OLD.revision AND NEW.publication IS DISTINCT FROM OLD.publication)
    OR ((NEW.publication_source_policy_revision,NEW.publication_source_revision,NEW.publication_source_hash)
        IS DISTINCT FROM (OLD.publication_source_policy_revision,OLD.publication_source_revision,OLD.publication_source_hash)
        AND (NEW.revision<=OLD.revision OR NEW.publication IS NOT DISTINCT FROM OLD.publication
             OR (NEW.publication_source_policy_revision<>0 AND NEW.publication_source_policy_revision<>NEW.revision))) THEN
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
CREATE INDEX IF NOT EXISTS identity_challenge_expiry ON identity_challenges(expires);
CREATE INDEX IF NOT EXISTS identity_owner_revocation_expiry ON identity_owner_revocations(expires);

-- Capture the exact owner grant that independently authorized this publication.
ALTER TABLE identity_devices ADD COLUMN IF NOT EXISTS publication_grant_hash text NOT NULL DEFAULT '';

-- One bounded, device-reported outcome per identity. Publication is independent.
CREATE TABLE IF NOT EXISTS identity_policy_activation (
 device text PRIMARY KEY REFERENCES identity_devices(id),
 policy_revision bigint NOT NULL CHECK(policy_revision BETWEEN 1 AND 9007199254740991),
 envelope_hash text NOT NULL CHECK(length(envelope_hash)=43),
 activation_generation bigint NOT NULL CHECK(activation_generation BETWEEN 1 AND 9007199254740991),
 outcome text NOT NULL CHECK(outcome IN ('committed','degraded','rolled_back')),
 active_policy_revision bigint NOT NULL,
 received_at_ms bigint NOT NULL CHECK(received_at_ms>0),
 CHECK ((outcome='rolled_back' AND active_policy_revision>=0 AND active_policy_revision<policy_revision)
   OR (outcome IN ('committed','degraded') AND active_policy_revision=policy_revision))
);
CREATE OR REPLACE FUNCTION identity_activation_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.device<>OLD.device OR NEW.policy_revision<=OLD.policy_revision OR NEW.received_at_ms<OLD.received_at_ms THEN
  RAISE EXCEPTION 'stale activation report';
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_policy_activation_guard ON identity_policy_activation;
CREATE TRIGGER identity_policy_activation_guard BEFORE UPDATE ON identity_policy_activation FOR EACH ROW EXECUTE FUNCTION identity_activation_invariants();

CREATE TABLE IF NOT EXISTS identity_telemetry_windows (
 device text NOT NULL REFERENCES identity_devices(id) ON DELETE CASCADE,
 period bigint NOT NULL CHECK(period>0),
 used integer NOT NULL CHECK(used BETWEEN 1 AND 256),
 PRIMARY KEY(device,period)
);
CREATE INDEX IF NOT EXISTS identity_telemetry_window_age ON identity_telemetry_windows(period);
CREATE TABLE IF NOT EXISTS identity_telemetry_events (
 device text NOT NULL REFERENCES identity_devices(id) ON DELETE CASCADE,
 event_id text NOT NULL CHECK(event_id ~ '^[A-Za-z0-9_-]{43}$'),
 session_id text NOT NULL CHECK(session_id ~ '^[A-Za-z0-9_-]{43}$'),
 build integer NOT NULL CHECK(build BETWEEN 1 AND 2100000000),
 policy_revision bigint NOT NULL CHECK(policy_revision BETWEEN 0 AND 9007199254740991),
 algorithm_revision integer NOT NULL CHECK(algorithm_revision BETWEEN 1 AND 1000000),
 received_at_ms bigint NOT NULL CHECK(received_at_ms>0),
 observed_at_ms bigint NOT NULL CHECK(observed_at_ms>0),
 elapsed_ms bigint NOT NULL CHECK(elapsed_ms BETWEEN 0 AND 9007199254740991),
 network_epoch bigint NOT NULL CHECK(network_epoch BETWEEN 0 AND 9007199254740991),
 kind text NOT NULL CHECK(kind IN ('network','vpn','probe','route','policy','engine','overlay')),
 code text NOT NULL CHECK(code ~ '^[a-z_]{2,32}$'),
 mode text NOT NULL CHECK(mode IN ('unknown','home_wifi','wifi','cellular_restricted','cellular')),
 path_id text CHECK(path_id ~ '^[A-Za-z0-9_-]{43}$'),
 duration_ms integer CHECK(duration_ms BETWEEN 0 AND 600000),
 PRIMARY KEY(device,event_id)
);
CREATE INDEX IF NOT EXISTS identity_telemetry_event_age ON identity_telemetry_events(received_at_ms);
REVOKE ALL ON identity_telemetry_windows,identity_telemetry_events FROM PUBLIC;
CREATE TABLE IF NOT EXISTS identity_telemetry_hourly (
 hour_start_ms bigint NOT NULL CHECK(hour_start_ms>0 AND hour_start_ms%3600000=0),
 kind text NOT NULL CHECK(kind IN ('network','vpn','probe','route','policy','engine','overlay')),
 code text NOT NULL CHECK(code ~ '^[a-z_]{2,32}$'),
 mode text NOT NULL CHECK(mode IN ('unknown','home_wifi','wifi','cellular_restricted','cellular')),
 events bigint NOT NULL CHECK(events BETWEEN 1 AND 100000),
 timed bigint NOT NULL CHECK(timed BETWEEN 0 AND events),
 duration_total_ms bigint NOT NULL CHECK(duration_total_ms BETWEEN 0 AND timed*600000),
 PRIMARY KEY(hour_start_ms,kind,code,mode)
);
REVOKE ALL ON identity_telemetry_hourly FROM PUBLIC;
ALTER TABLE identity_telemetry_hourly
 ADD COLUMN IF NOT EXISTS baseline_reselections bigint NOT NULL DEFAULT 0
 CHECK(baseline_reselections BETWEEN 0 AND events AND
  (baseline_reselections=0 OR (kind='route' AND code='reselected')));
ALTER TABLE identity_telemetry_hourly
 ADD COLUMN IF NOT EXISTS conservative_reselections bigint NOT NULL DEFAULT 0
 CHECK(conservative_reselections BETWEEN 0 AND events-baseline_reselections AND
  (conservative_reselections=0 OR (kind='route' AND code='reselected')));

-- The analysis worker can see the two known decision variants, without access
-- to the raw algorithm revision, policy revision, device or event identifiers.
CREATE OR REPLACE VIEW identity_telemetry_analysis_events WITH (security_barrier=true) AS
 SELECT received_at_ms,kind,code,mode,duration_ms,
 CASE WHEN kind='route' AND code='reselected' AND policy_revision>0 AND algorithm_revision IN (1,2)
  THEN algorithm_revision ELSE 0 END AS decision_variant
 FROM identity_telemetry_events;
REVOKE ALL ON identity_telemetry_analysis_events FROM PUBLIC;
