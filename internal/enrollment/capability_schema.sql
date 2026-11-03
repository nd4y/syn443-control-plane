-- Separate approved availability history. The original enrollment receipt/body
-- remains immutable. Only the independent publisher can approve capabilities.
CREATE TABLE IF NOT EXISTS identity_capability_versions(
 device text NOT NULL REFERENCES identity_devices(id),revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 13),
 previous_hash text NOT NULL CHECK(length(previous_hash)=43),body_hash text NOT NULL CHECK(length(body_hash)=43),
 capabilities bytea NOT NULL CHECK(octet_length(capabilities) BETWEEN 1 AND 4096),
 original_request_hash text NOT NULL CHECK(length(original_request_hash)=43),
 request_hash text NOT NULL CHECK(length(request_hash)=43),proof_hash text NOT NULL CHECK(length(proof_hash)=43),
 approved_ms bigint NOT NULL CHECK(approved_ms>0),PRIMARY KEY(device,revision),UNIQUE(device,revision,body_hash)
);
CREATE TABLE IF NOT EXISTS identity_capability_heads(
 device text PRIMARY KEY REFERENCES identity_devices(id),revision bigint NOT NULL,body_hash text NOT NULL,
 FOREIGN KEY(device,revision,body_hash) REFERENCES identity_capability_versions(device,revision,body_hash)
);
CREATE OR REPLACE FUNCTION identity_capability_version_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable approved capabilities'; END; $$;
DROP TRIGGER IF EXISTS identity_capability_version_guard ON identity_capability_versions;
CREATE TRIGGER identity_capability_version_guard BEFORE UPDATE OR DELETE ON identity_capability_versions FOR EACH ROW EXECUTE FUNCTION identity_capability_version_invariants();
CREATE OR REPLACE FUNCTION identity_capability_head_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.device<>OLD.device OR NEW.revision<>OLD.revision+1 OR NEW.body_hash=OLD.body_hash THEN
 RAISE EXCEPTION 'immutable capability head CAS'; END IF; RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_capability_head_guard ON identity_capability_heads;
CREATE TRIGGER identity_capability_head_guard BEFORE UPDATE OR DELETE ON identity_capability_heads FOR EACH ROW EXECUTE FUNCTION identity_capability_head_invariants();

CREATE TABLE IF NOT EXISTS identity_capability_requests(
 device text NOT NULL REFERENCES identity_devices(id),request_id text NOT NULL,owner text NOT NULL,jkt text NOT NULL,grant_hash text NOT NULL,
 request_hash text NOT NULL,body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 8192),
 receipt bytea,accepted_ms bigint NOT NULL,deadline_ms bigint NOT NULL CHECK(deadline_ms>accepted_ms AND deadline_ms<=accepted_ms+180000),
 auth_kind text NOT NULL CHECK(auth_kind IN('oidc','device')),session_id text NOT NULL DEFAULT '',session_generation bigint NOT NULL DEFAULT 0,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN('queued','approved','rejected')),
 result_revision bigint NOT NULL DEFAULT 0,result_hash text NOT NULL DEFAULT '',error_code text NOT NULL DEFAULT '',
 PRIMARY KEY(device,request_id),CHECK(state='queued' AND receipt IS NOT NULL OR state<>'queued' AND receipt IS NULL)
);
CREATE OR REPLACE FUNCTION identity_capability_request_invariants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'queued' OR NEW.result_revision<>0 OR NEW.result_hash<>'' OR NEW.error_code<>'' THEN RAISE EXCEPTION 'unapproved capability request'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF OLD.state='queued' OR OLD.receipt IS NOT NULL THEN RAISE EXCEPTION 'active capability receipt'; END IF; RETURN OLD;
 END IF;
 IF (NEW.device,NEW.request_id,NEW.owner,NEW.jkt,NEW.grant_hash,NEW.request_hash,NEW.body,NEW.accepted_ms,NEW.deadline_ms,NEW.auth_kind,NEW.session_id,NEW.session_generation)
 IS DISTINCT FROM (OLD.device,OLD.request_id,OLD.owner,OLD.jkt,OLD.grant_hash,OLD.request_hash,OLD.body,OLD.accepted_ms,OLD.deadline_ms,OLD.auth_kind,OLD.session_id,OLD.session_generation)
 OR OLD.state<>'queued' AND NEW IS DISTINCT FROM OLD OR NEW.state='queued' AND NEW.receipt IS DISTINCT FROM OLD.receipt THEN
 RAISE EXCEPTION 'immutable capability receipt'; END IF; RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_capability_request_guard ON identity_capability_requests;
CREATE TRIGGER identity_capability_request_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_capability_requests FOR EACH ROW EXECUTE FUNCTION identity_capability_request_invariants();
CREATE INDEX IF NOT EXISTS identity_capability_work ON identity_capability_requests(state,accepted_ms);

-- A narrow boolean lock/fence, not a session reader or session minting method.
-- Fixed identifiers/search_path; no dynamic SQL or secret/hash output.
CREATE OR REPLACE FUNCTION identity_capability_session_fence(p_session text,p_device text,p_generation bigint,p_token_hash text,p_now bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER STRICT SET search_path=pg_catalog AS $$
DECLARE actual_device text;actual_active boolean;actual_generation bigint;actual_until bigint;actual_hash text;
BEGIN
 SELECT s.device,s.active,s.generation,s.access_until,s.access_hash INTO actual_device,actual_active,actual_generation,actual_until,actual_hash
 FROM public.identity_sessions s WHERE s.id=p_session FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 RETURN actual_device=p_device AND actual_active AND actual_generation=p_generation AND actual_until>p_now AND actual_hash=p_token_hash;
END; $$;
REVOKE ALL ON FUNCTION identity_capability_session_fence(text,text,bigint,text,bigint) FROM PUBLIC;
