-- Run after creating the existing three non-owner runtime roles.
GRANT SELECT,UPDATE(lock_guard) ON identity_accounts TO syn443_control_api;
GRANT SELECT ON identity_devices TO syn443_control_api;
GRANT SELECT,UPDATE(guard) ON catalog_acl TO syn443_identity_publisher;
GRANT SELECT ON managed_invitations TO syn443_control_api,syn443_identity_api,syn443_identity_publisher;
GRANT INSERT(id,owner,service_id,bootstrap_revision,grant_hash,actor,request_id,body_hash,code_hash,
 issue_receipt,issue_reply,created_at,expires),UPDATE(revoked,version,approval_actor,approval_request,
 approval_hash,approval_receipt,approved_at) ON managed_invitations TO syn443_control_api;
GRANT UPDATE(claim_jkt,claim_request,claim_hash,claim_payload,claim_receipt,claim_nonce,pair_code,
 claimed_at,revoked,version,final_request,final_hash,final_session,finalized_at)
 ON managed_invitations TO syn443_identity_api;
GRANT UPDATE(device,version,retry_after,publication_error) ON managed_invitations TO syn443_identity_publisher;
GRANT INSERT(id,owner,jkt,request_body,receipt) ON identity_devices TO syn443_identity_publisher;
GRANT SELECT,INSERT,DELETE ON managed_invitation_replays TO syn443_identity_api;
REVOKE ALL ON FUNCTION managed_invitation_guard() FROM PUBLIC;
