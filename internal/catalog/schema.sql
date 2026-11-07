-- Owner migration. Runtime API, fetch workers and signer have separate roles.
CREATE TABLE IF NOT EXISTS catalog_clock(id boolean PRIMARY KEY CHECK(id),second bigint NOT NULL);
INSERT INTO catalog_clock VALUES(true,0) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS catalog_acl(
 actor text NOT NULL,action text NOT NULL,target_kind text NOT NULL,target_id text NOT NULL,
 expires bigint NOT NULL,guard integer NOT NULL DEFAULT 0,
 PRIMARY KEY(actor,action,target_kind,target_id)
);
CREATE OR REPLACE FUNCTION catalog_control_panel_expiry(actor_id text, now_second bigint) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT COALESCE(max(expires),0) FROM public.catalog_acl
 WHERE actor=actor_id AND action IN('control.open','*')
   AND target_kind IN('control','*') AND target_id IN('panel','*') AND expires>now_second
$$;
REVOKE ALL ON FUNCTION catalog_control_panel_expiry(text,bigint) FROM PUBLIC;
CREATE TABLE IF NOT EXISTS catalog_proofs(actor text NOT NULL,jkt text NOT NULL,jti text NOT NULL,expires bigint NOT NULL,PRIMARY KEY(actor,jkt,jti));
CREATE INDEX IF NOT EXISTS catalog_proof_expiry ON catalog_proofs(expires);
CREATE TABLE IF NOT EXISTS catalog_resources(
 id text PRIMARY KEY,revision bigint NOT NULL CHECK(revision>0),
 provider_type text NOT NULL,api_version text NOT NULL,name text NOT NULL,
 enabled boolean NOT NULL,secrets bytea NOT NULL,state text NOT NULL DEFAULT 'unknown',
 last_sync bigint NOT NULL DEFAULT 0,
 CHECK(NOT enabled OR (provider_type='panel.remnawave' AND api_version='3.4'))
);
CREATE UNIQUE INDEX IF NOT EXISTS catalog_one_active_panel ON catalog_resources(provider_type) WHERE enabled;
CREATE TABLE IF NOT EXISTS catalog_sources(
 id text PRIMARY KEY,owner text NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 spec bytea NOT NULL,secrets bytea,salt bytea NOT NULL CHECK(octet_length(salt)=32),fetch_cache bytea,
 mode text NOT NULL CHECK(mode IN('server','device','manual','resource')),
 resource_id text REFERENCES catalog_resources(id),enabled boolean NOT NULL,
 valid_until bigint NOT NULL,refresh_seconds bigint NOT NULL CHECK(refresh_seconds BETWEEN 60 AND 86400),
 max_stale_seconds bigint NOT NULL CHECK(max_stale_seconds BETWEEN 300 AND 604800),
 active_snapshot text,candidate_snapshot text,state text NOT NULL DEFAULT 'pending',
 access_state text NOT NULL DEFAULT 'unknown' CHECK(access_state IN('unknown','allowed','revoked','expired','quota_exhausted')),
 last_sync bigint NOT NULL DEFAULT 0,next_sync bigint NOT NULL DEFAULT 0,last_resource_revision bigint NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS catalog_source_grants(
 source_id text NOT NULL REFERENCES catalog_sources(id),target_kind text NOT NULL CHECK(target_kind IN('user','group','device')),
 target_id text NOT NULL,PRIMARY KEY(source_id,target_kind,target_id)
);
CREATE TABLE IF NOT EXISTS catalog_share_heads(source_id text PRIMARY KEY REFERENCES catalog_sources(id),revision bigint NOT NULL CHECK(revision>0));
CREATE TABLE IF NOT EXISTS catalog_snapshots(
 id text PRIMARY KEY,source_id text NOT NULL REFERENCES catalog_sources(id),source_revision bigint NOT NULL,
 content_hash text NOT NULL,observed_at bigint NOT NULL,valid_until bigint NOT NULL,resource_revision bigint NOT NULL DEFAULT 0,
 count integer NOT NULL CHECK(count BETWEEN 1 AND 5000),profiles bytea NOT NULL,
 state text NOT NULL CHECK(state IN('candidate','quarantined','active','superseded','rejected')),
 reason text NOT NULL,quota jsonb NOT NULL,UNIQUE(source_id,id)
);
DO $$BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='catalog_active_snapshot_scope') THEN
  ALTER TABLE catalog_sources ADD CONSTRAINT catalog_active_snapshot_scope FOREIGN KEY(id,active_snapshot) REFERENCES catalog_snapshots(source_id,id);
  ALTER TABLE catalog_sources ADD CONSTRAINT catalog_candidate_snapshot_scope FOREIGN KEY(id,candidate_snapshot) REFERENCES catalog_snapshots(source_id,id);
 END IF;
END$$;
CREATE TABLE IF NOT EXISTS catalog_dependencies(
 owner text NOT NULL,layer_id text NOT NULL,layer_revision bigint NOT NULL,
 source_id text NOT NULL REFERENCES catalog_sources(id),profile_id text NOT NULL,
 PRIMARY KEY(layer_id,layer_revision,source_id,profile_id)
);
CREATE TABLE IF NOT EXISTS catalog_jobs(
 id text PRIMARY KEY,source_id text NOT NULL REFERENCES catalog_sources(id),source_revision bigint NOT NULL,
 base_snapshot text,resource_revision bigint NOT NULL DEFAULT 0,
 kind text NOT NULL CHECK(kind IN('fetch','resource','manual','device')),
 request_id text NOT NULL,actor text NOT NULL,body_hash text NOT NULL,
 phase text NOT NULL CHECK(phase IN('queued','running','succeeded','failed','cancelled','dead_letter')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
 not_before bigint NOT NULL,deadline bigint NOT NULL,lease text NOT NULL DEFAULT '',lease_until bigint NOT NULL DEFAULT 0,
 reason text NOT NULL DEFAULT '',payload bytea,created_at bigint NOT NULL,updated_at bigint NOT NULL,
 UNIQUE(actor,request_id)
);
ALTER TABLE catalog_jobs ADD COLUMN IF NOT EXISTS device_attempts integer NOT NULL DEFAULT 0 CHECK(device_attempts BETWEEN 0 AND 8);
ALTER TABLE catalog_jobs ADD COLUMN IF NOT EXISTS device_result_hash text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS catalog_one_source_job ON catalog_jobs(source_id) WHERE phase IN('queued','running');
CREATE INDEX IF NOT EXISTS catalog_due_jobs ON catalog_jobs(not_before,created_at) WHERE phase IN('queued','running');
CREATE INDEX IF NOT EXISTS catalog_active_job_deadlines ON catalog_jobs(deadline,id) WHERE phase IN('queued','running');
CREATE INDEX IF NOT EXISTS catalog_source_job_history ON catalog_jobs(source_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS catalog_terminal_inputs ON catalog_jobs(updated_at,id) WHERE payload IS NOT NULL AND phase IN('succeeded','failed','cancelled','dead_letter');
-- Retain replay/audit identity, never an unnecessary raw subscription after work
-- ends. Enforce at the SQL boundary for every cancellation and failure path.
CREATE OR REPLACE FUNCTION catalog_terminal_input_erasure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.phase IN('succeeded','failed','cancelled','dead_letter') AND NEW.phase<>OLD.phase THEN
  RAISE EXCEPTION 'terminal catalog job';
 END IF;
 IF NEW.phase IN('succeeded','failed','cancelled','dead_letter') THEN
  NEW.payload=NULL; NEW.lease=''; NEW.lease_until=0;
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS catalog_terminal_input_guard ON catalog_jobs;
CREATE TRIGGER catalog_terminal_input_guard BEFORE INSERT OR UPDATE ON catalog_jobs FOR EACH ROW EXECUTE FUNCTION catalog_terminal_input_erasure();
CREATE INDEX IF NOT EXISTS catalog_due_sources ON catalog_sources(next_sync) WHERE enabled;
CREATE TABLE IF NOT EXISTS catalog_operations(
 actor text NOT NULL,request_id text NOT NULL,action text NOT NULL,target text NOT NULL,
 body_hash text NOT NULL,response bytea NOT NULL,expires bigint NOT NULL,PRIMARY KEY(actor,request_id)
);
CREATE TABLE IF NOT EXISTS catalog_audit(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,actor text NOT NULL,action text NOT NULL,
 target text NOT NULL,request_id text NOT NULL,observed_at bigint NOT NULL,
 before_hash text NOT NULL,after_hash text NOT NULL,outcome text NOT NULL,
 service_actor text NOT NULL DEFAULT current_user
);
CREATE TABLE IF NOT EXISTS catalog_outbox(
 id text PRIMARY KEY,event_version integer NOT NULL CHECK(event_version=1),kind text NOT NULL,
 source_id text NOT NULL REFERENCES catalog_sources(id),snapshot_id text REFERENCES catalog_snapshots(id),
 created_at bigint NOT NULL,delivered_at bigint NOT NULL DEFAULT 0,attempts integer NOT NULL DEFAULT 0
);
CREATE OR REPLACE FUNCTION catalog_snapshot_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.id<>OLD.id OR NEW.source_id<>OLD.source_id OR NEW.source_revision<>OLD.source_revision
 OR NEW.content_hash<>OLD.content_hash OR NEW.observed_at<>OLD.observed_at OR NEW.valid_until<>OLD.valid_until
 OR NEW.count<>OLD.count OR NEW.profiles<>OLD.profiles OR NEW.quota<>OLD.quota OR NEW.resource_revision<>OLD.resource_revision THEN
  RAISE EXCEPTION 'immutable catalog snapshot';
 END IF;
 RETURN NEW;
END$$;
DROP TRIGGER IF EXISTS catalog_snapshot_guard ON catalog_snapshots;
CREATE TRIGGER catalog_snapshot_guard BEFORE UPDATE ON catalog_snapshots FOR EACH ROW EXECUTE FUNCTION catalog_snapshot_immutable();
CREATE OR REPLACE FUNCTION catalog_audit_actor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF current_user='syn443_source_worker' AND NEW.actor<>'' THEN
  RAISE EXCEPTION 'worker cannot impersonate administrator';
 END IF;
 NEW.service_actor=current_user;
 RETURN NEW;
END$$;
DROP TRIGGER IF EXISTS catalog_audit_guard ON catalog_audit;
CREATE TRIGGER catalog_audit_guard BEFORE INSERT ON catalog_audit FOR EACH ROW EXECUTE FUNCTION catalog_audit_actor_guard();
ALTER TABLE catalog_sources ADD COLUMN IF NOT EXISTS fetch_device_id text NOT NULL DEFAULT ''
 CHECK (fetch_device_id='' OR mode='device' AND fetch_device_id ~ '^[A-Za-z0-9_-]{1,128}$');
CREATE OR REPLACE FUNCTION catalog_source_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.id<>OLD.id OR NEW.owner<>OLD.owner OR NEW.mode<>OLD.mode OR NEW.salt<>OLD.salt
 OR NEW.resource_id IS DISTINCT FROM OLD.resource_id OR NEW.revision<OLD.revision
 OR (OLD.fetch_device_id<>'' AND NEW.fetch_device_id<>OLD.fetch_device_id) THEN
  RAISE EXCEPTION 'immutable catalog source identity';
 END IF;
 RETURN NEW;
END$$;
DROP TRIGGER IF EXISTS catalog_source_guard ON catalog_sources;
CREATE TRIGGER catalog_source_guard BEFORE UPDATE ON catalog_sources FOR EACH ROW EXECUTE FUNCTION catalog_source_immutable();

-- A non-authoritative lock guard permits the independent signer to take SHARE
-- row locks without UPDATE privilege on any actual source/resource field.
ALTER TABLE catalog_sources ADD COLUMN IF NOT EXISTS selection_guard integer NOT NULL DEFAULT 0;
ALTER TABLE catalog_resources ADD COLUMN IF NOT EXISTS selection_guard integer NOT NULL DEFAULT 0;

-- Mutable drafts are separate from every source/active/publication head. Only
-- independently approved immutable layers may later feed the signer.
CREATE TABLE IF NOT EXISTS catalog_network_drafts(
 actor text NOT NULL,id text NOT NULL,revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 target_kind text NOT NULL CHECK(target_kind IN('template','group','user','device')),
 target_id text NOT NULL,saved_at bigint NOT NULL CHECK(saved_at>0),
 body bytea NOT NULL CHECK(octet_length(body) BETWEEN 29 AND 524288),
 PRIMARY KEY(actor,id)
);
CREATE OR REPLACE FUNCTION catalog_network_draft_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.actor,NEW.id,NEW.target_kind,NEW.target_id) IS DISTINCT FROM (OLD.actor,OLD.id,OLD.target_kind,OLD.target_id)
 OR NEW.revision<>OLD.revision+1 OR NEW.saved_at<OLD.saved_at THEN RAISE EXCEPTION 'immutable draft scope'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS catalog_network_draft_invariants ON catalog_network_drafts;
CREATE TRIGGER catalog_network_draft_invariants BEFORE UPDATE ON catalog_network_drafts FOR EACH ROW EXECUTE FUNCTION catalog_network_draft_guard();
