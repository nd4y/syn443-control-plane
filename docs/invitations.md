# One-use invitation authority

The invitation component reserves a key for an existing enabled account/grant;
it does not create a user or infer authority from Keycloak login alone. An issue
request binds owner, grant hash, service/bootstrap revision and a maximum10-minute
expiry. A cryptographic32-byte code is hashed in SQL; the protected lost-reply
receipt retains the same invitation/link for an exact retry while still unclaimed.

Issuance, approval and revocation require the distinct administrative audience,
DPoP body/key/token binding, live scoped SQL ACL and fresh MFA. Inventory uses the
current session without forcing MFA. Original signed requests are encrypted for
the independent signer to revalidate; a parsed row or control API flag alone is
not publication authority. The control role cannot replace a claim key or issue
device sessions; the device API cannot approve itself.

A claim proves possession of the submitted device key and consumes the code for
that immutable key/request/body. Exact lost-reply retries return the same pairing
code/nonce. Another key cannot rebind it. Claims reserve a bounded account seat
but return no session, profile, subscription or chat access. The administrator
must explicitly confirm the matching key/pair code and current version. Database
constraints prevent owner/key/approval/device/session substitution and revival.

The control API exposes closed invite.issue/get/approve/revoke actions. The
identity API exposes POST /v1/invitations/{claim,status,complete,abandon}, with no
browser Origin or bearer authorization, strict8KiB JSON, body/key/nonce-bound
proofs, bounded admission and durable replay rejection. Both APIs remain disabled
unless an owner-only SYN443_INVITATION_CONFIG supplies separate invitation
ciphertext key, installation anchor, signed descriptor and pinned admin verifier
settings. API, worker and control origins/issuers must agree; startup refuses an
unexpected runtime SQL role. The source worker receives no invitation key.

The publication worker independently verifies original issue/approval/claim
receipts, then creates the ordinary unapproved identity device under exact
account/invitation/version fences. Per-item30-second backoff prevents a bad
receipt from starving the next16 eligible items. Device creation and invitation
binding are one transaction. The normal publisher rechecks approval through an
explicit external-approval interface and repeats all account/ACL/receipt/expiry
fences in its final commit; no parser can request arbitrary signatures.

Only after an active device has a committed permitted policy does complete mint
an ordinary key-bound session. Exact lost replies return the same encrypted
cached response for180seconds; refresh generations, account changes and device
revocation fence it. Another completion body/request cannot mint a second
session. Abandon revokes only the captured key/device and its sessions; repeated
cancellation is safe. Status reports provisioning until publication is actually
committed, never infers readiness from a device-row insert. OIDC registration
counts pending invitation reservations against the same device quota.

SQL role and end-to-end tests run serially on a dedicated disposable Actions
PostgreSQL fixture, with unchanged80% gates for invitation and its independent
publisher bridge. No real users/accounts are enrolled by CI. Native protected
trust/pending journal, camera/Intent/paste flow, root transition delivery and
physical acceptance are still pending; backend integration alone does not close
M2 or M3.
