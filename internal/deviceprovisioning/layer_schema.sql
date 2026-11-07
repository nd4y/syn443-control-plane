-- Owner migration only. A mutable draft/request is never an approved layer head.
CREATE TABLE IF NOT EXISTS managed_configuration_drafts(
 actor text NOT NULL,id text NOT NULL,target_kind text NOT NULL CHECK(target_kind IN('template','group','user','device')),target_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),body_hash text NOT NULL,body bytea NOT NULL,
 saved_ms bigint NOT NULL,expires_ms bigint NOT NULL,PRIMARY KEY(actor,id),CHECK(expires_ms>saved_ms),CHECK(octet_length(body) BETWEEN 29 AND 262172)
);
CREATE TABLE IF NOT EXISTS managed_configuration_draft_ops(
 actor text NOT NULL,request_id text NOT NULL,body_hash text NOT NULL,response bytea NOT NULL,expires_ms bigint NOT NULL,
 PRIMARY KEY(actor,request_id),CHECK(octet_length(response) BETWEEN 29 AND 262172)
);
ALTER TABLE managed_configuration_drafts ADD COLUMN IF NOT EXISTS discarded boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS managed_configuration_drafts_live_scope ON managed_configuration_drafts(actor,target_kind,target_id,saved_ms DESC,id) WHERE NOT discarded;
CREATE OR REPLACE FUNCTION managed_configuration_draft_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.actor,NEW.id,NEW.target_kind,NEW.target_id) IS DISTINCT FROM (OLD.actor,OLD.id,OLD.target_kind,OLD.target_id)
 OR OLD.discarded OR (NEW.discarded AND NEW.revision<>OLD.revision)
 OR (NOT NEW.discarded AND NEW.revision<>OLD.revision+1) THEN RAISE EXCEPTION 'configuration draft CAS'; END IF; RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS managed_configuration_draft_guard ON managed_configuration_drafts;
CREATE TRIGGER managed_configuration_draft_guard BEFORE UPDATE ON managed_configuration_drafts FOR EACH ROW EXECUTE FUNCTION managed_configuration_draft_invariants();
-- Non-authoritative row-lock guard for a consistent authorized device view.
ALTER TABLE identity_devices ADD COLUMN IF NOT EXISTS configuration_guard integer NOT NULL DEFAULT 0;
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
 PRIMARY KEY(device,revision),CHECK(octet_length(approval_receipt) BETWEEN 29 AND 524316)
);
ALTER TABLE managed_configuration_versions DROP CONSTRAINT IF EXISTS managed_configuration_versions_approval_receipt_check;
ALTER TABLE managed_configuration_versions ADD CONSTRAINT managed_configuration_versions_approval_receipt_check CHECK(octet_length(approval_receipt) BETWEEN 29 AND 524316);
CREATE TABLE IF NOT EXISTS managed_configuration_heads(
 device text PRIMARY KEY,revision bigint NOT NULL,body_hash text NOT NULL,
 guard integer NOT NULL DEFAULT 0,
 FOREIGN KEY(device,revision) REFERENCES managed_configuration_versions(device,revision)
);
-- API-owned immutable original receipts. The publisher alone owns work/result
-- fields, and a successful queue reply is never a configuration activation.
CREATE TABLE IF NOT EXISTS managed_configuration_requests(
 id text PRIMARY KEY,actor text NOT NULL,request_id text NOT NULL,
 action text NOT NULL CHECK(action IN('configuration.preview.request','configuration.publish')),
 target_kind text NOT NULL CHECK(target_kind IN('template','group','user','device')),target_id text NOT NULL,
 created_ms bigint NOT NULL,deadline_ms bigint NOT NULL,body_hash text NOT NULL,receipt bytea NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN('queued','running','ready','published','applied','rejected','expired','cancelled')),
 lease text NOT NULL DEFAULT '',lease_until_ms bigint NOT NULL DEFAULT 0,next_ms bigint NOT NULL DEFAULT 0,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 error_code text NOT NULL DEFAULT '',result bytea,
 UNIQUE(actor,request_id),CHECK(deadline_ms>created_ms AND deadline_ms-created_ms<=180000),
 CHECK(octet_length(receipt) BETWEEN 29 AND 524316)
);
CREATE INDEX IF NOT EXISTS managed_configuration_due ON managed_configuration_requests(next_ms,lease_until_ms,state);
-- Retain legacy owner-fixture 'applied' receipts; new publisher code emits only
-- 'published'. Device activation has its own independent acknowledgement.
ALTER TABLE managed_configuration_requests DROP CONSTRAINT IF EXISTS managed_configuration_requests_state_check;
ALTER TABLE managed_configuration_requests ADD CONSTRAINT managed_configuration_requests_state_check CHECK(state IN('queued','running','ready','published','applied','rejected','expired','cancelled'));
CREATE OR REPLACE FUNCTION managed_configuration_request_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.id,NEW.actor,NEW.request_id,NEW.action,NEW.target_kind,NEW.target_id,NEW.created_ms,NEW.deadline_ms,NEW.body_hash,NEW.receipt)
 IS DISTINCT FROM (OLD.id,OLD.actor,OLD.request_id,OLD.action,OLD.target_kind,OLD.target_id,OLD.created_ms,OLD.deadline_ms,OLD.body_hash,OLD.receipt)
 OR NEW.attempts<OLD.attempts OR OLD.state IN('ready','published','applied','rejected','expired','cancelled') AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'immutable configuration request'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS managed_configuration_request_guard ON managed_configuration_requests;
CREATE TRIGGER managed_configuration_request_guard BEFORE UPDATE ON managed_configuration_requests FOR EACH ROW EXECUTE FUNCTION managed_configuration_request_invariants();
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

-- Shared layers keep one immutable history across all device configuration
-- snapshots. Membership is committed with an approved configuration version;
-- neither caller-supplied group names nor mutable API drafts create membership.
CREATE TABLE IF NOT EXISTS managed_configuration_layer_versions(
 kind text NOT NULL CHECK(kind IN('template','group','user','device','local')),
 id text NOT NULL,revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 body_hash text NOT NULL,body bytea NOT NULL,actor text NOT NULL,
 preview text NOT NULL REFERENCES managed_configuration_previews(id),approved_at_ms bigint NOT NULL,
 PRIMARY KEY(kind,id,revision),UNIQUE(kind,id,revision,body_hash),CHECK(octet_length(body) BETWEEN 29 AND 262172)
);
CREATE TABLE IF NOT EXISTS managed_configuration_layer_heads(
 kind text NOT NULL,id text NOT NULL,revision bigint NOT NULL,body_hash text NOT NULL,
 PRIMARY KEY(kind,id),FOREIGN KEY(kind,id,revision,body_hash) REFERENCES managed_configuration_layer_versions(kind,id,revision,body_hash)
);
CREATE TABLE IF NOT EXISTS managed_configuration_assignments(
 device text NOT NULL,position integer NOT NULL CHECK(position BETWEEN 0 AND 19),
 kind text NOT NULL,id text NOT NULL,revision bigint NOT NULL,body_hash text NOT NULL,
 configuration_revision bigint NOT NULL,
 PRIMARY KEY(device,position),UNIQUE(device,kind,id),
 FOREIGN KEY(device,configuration_revision) REFERENCES managed_configuration_versions(device,revision),
 FOREIGN KEY(kind,id,revision,body_hash) REFERENCES managed_configuration_layer_versions(kind,id,revision,body_hash)
);
DROP TRIGGER IF EXISTS managed_configuration_layer_version_guard ON managed_configuration_layer_versions;
CREATE TRIGGER managed_configuration_layer_version_guard BEFORE UPDATE OR DELETE ON managed_configuration_layer_versions FOR EACH ROW EXECUTE FUNCTION managed_configuration_immutable();
CREATE OR REPLACE FUNCTION managed_configuration_layer_head_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.kind,NEW.id) IS DISTINCT FROM (OLD.kind,OLD.id) OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'shared configuration layer CAS'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS managed_configuration_layer_head_guard ON managed_configuration_layer_heads;
CREATE TRIGGER managed_configuration_layer_head_guard BEFORE UPDATE ON managed_configuration_layer_heads FOR EACH ROW EXECUTE FUNCTION managed_configuration_layer_head_invariants();
