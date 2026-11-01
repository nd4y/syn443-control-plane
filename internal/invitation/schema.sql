-- Owner migration after identity and catalog schemas. Invitation issuance never
-- creates an account, grants device session access or gives signing authority.
CREATE TABLE IF NOT EXISTS managed_invitations(
 id text PRIMARY KEY,owner text NOT NULL REFERENCES identity_accounts(owner),
 service_id text NOT NULL,bootstrap_revision bigint NOT NULL,grant_hash text NOT NULL,
 actor text NOT NULL,request_id text NOT NULL,body_hash text NOT NULL,code_hash text NOT NULL UNIQUE,
 issue_receipt bytea NOT NULL,issue_reply bytea NOT NULL,created_at bigint NOT NULL,expires bigint NOT NULL,
 revoked boolean NOT NULL DEFAULT false,version bigint NOT NULL DEFAULT 1,
 retry_after bigint NOT NULL DEFAULT 0,publication_error text NOT NULL DEFAULT '',
 claim_jkt text,claim_request text,claim_hash text,claim_payload bytea,claim_receipt bytea,
 claim_nonce text,pair_code text,claimed_at bigint,
 approval_actor text,approval_request text,approval_hash text,approval_receipt bytea,approved_at bigint,
 device text REFERENCES identity_devices(id),
 final_request text,final_hash text,final_session text REFERENCES identity_sessions(id),finalized_at bigint,
 UNIQUE(actor,request_id),CHECK(expires>created_at AND expires-created_at<=600),
 CHECK(version>0 AND version<=9007199254740991)
);
ALTER TABLE managed_invitations ADD COLUMN IF NOT EXISTS retry_after bigint NOT NULL DEFAULT 0;
ALTER TABLE managed_invitations ADD COLUMN IF NOT EXISTS publication_error text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS managed_invitation_owner ON managed_invitations(owner,expires);
CREATE UNIQUE INDEX IF NOT EXISTS managed_invitation_one_pending_key ON managed_invitations(claim_jkt)
 WHERE claim_jkt IS NOT NULL AND NOT revoked AND final_session IS NULL;
CREATE TABLE IF NOT EXISTS managed_invitation_replays(jkt text NOT NULL,jti text NOT NULL,expires bigint NOT NULL,PRIMARY KEY(jkt,jti));
CREATE INDEX IF NOT EXISTS managed_invitation_proof_expiry ON managed_invitation_replays(expires);
CREATE OR REPLACE FUNCTION managed_invitation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.owner,NEW.service_id,NEW.bootstrap_revision,NEW.grant_hash,NEW.actor,NEW.request_id,
 NEW.body_hash,NEW.code_hash,NEW.issue_receipt,NEW.issue_reply,NEW.created_at,NEW.expires)
 IS DISTINCT FROM ROW(OLD.id,OLD.owner,OLD.service_id,OLD.bootstrap_revision,OLD.grant_hash,OLD.actor,OLD.request_id,
 OLD.body_hash,OLD.code_hash,OLD.issue_receipt,OLD.issue_reply,OLD.created_at,OLD.expires)
 OR OLD.revoked AND NOT NEW.revoked OR NEW.version<OLD.version THEN RAISE EXCEPTION 'immutable invitation authority'; END IF;
 IF OLD.claim_jkt IS NOT NULL AND ROW(NEW.claim_jkt,NEW.claim_request,NEW.claim_hash,NEW.claim_payload,
 NEW.claim_receipt,NEW.claim_nonce,NEW.pair_code,NEW.claimed_at) IS DISTINCT FROM ROW(OLD.claim_jkt,
 OLD.claim_request,OLD.claim_hash,OLD.claim_payload,OLD.claim_receipt,OLD.claim_nonce,OLD.pair_code,OLD.claimed_at)
 THEN RAISE EXCEPTION 'immutable invitation key'; END IF;
 IF OLD.approval_receipt IS NOT NULL AND ROW(NEW.approval_actor,NEW.approval_request,NEW.approval_hash,
 NEW.approval_receipt,NEW.approved_at) IS DISTINCT FROM ROW(OLD.approval_actor,OLD.approval_request,
 OLD.approval_hash,OLD.approval_receipt,OLD.approved_at) THEN RAISE EXCEPTION 'immutable invitation approval'; END IF;
 IF OLD.device IS NOT NULL AND NEW.device IS DISTINCT FROM OLD.device THEN RAISE EXCEPTION 'immutable invitation device'; END IF;
 IF NEW.device IS NOT NULL AND OLD.device IS NULL AND (NEW.approval_receipt IS NULL OR NEW.claim_jkt IS NULL
 OR NOT EXISTS(SELECT 1 FROM identity_devices d WHERE d.id=NEW.device AND d.owner=NEW.owner AND d.jkt=NEW.claim_jkt))
 THEN RAISE EXCEPTION 'invitation device scope'; END IF;
 IF OLD.final_session IS NOT NULL AND ROW(NEW.final_request,NEW.final_hash,NEW.final_session,NEW.finalized_at)
 IS DISTINCT FROM ROW(OLD.final_request,OLD.final_hash,OLD.final_session,OLD.finalized_at)
 THEN RAISE EXCEPTION 'immutable invitation completion'; END IF;
 IF NEW.final_session IS NOT NULL AND OLD.final_session IS NULL AND NOT EXISTS(
 SELECT 1 FROM identity_sessions s WHERE s.id=NEW.final_session AND s.device=NEW.device AND s.active)
 THEN RAISE EXCEPTION 'invitation session scope'; END IF;
 RETURN NEW;
END$$;
DROP TRIGGER IF EXISTS managed_invitation_invariants ON managed_invitations;
CREATE TRIGGER managed_invitation_invariants BEFORE UPDATE ON managed_invitations FOR EACH ROW EXECUTE FUNCTION managed_invitation_guard();
