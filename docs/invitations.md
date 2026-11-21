# One-use invitation authority

## Mobile and desktop console

Open **Приглашения** to issue a link for one new device. Use the recipient ID and
current grant fingerprint from the account assignment, plus the service ID and
revision of its signed bootstrap descriptor. The default lifetime is ten
minutes. Review the recipient and confirm issuance. The console displays the
exact returned link and generates its QR inside the browser. A link that exceeds
QR capacity can still be delivered as text.

After the recipient opens the link, look up its invitation ID. Once the new
device claims it, compare the device key fingerprint and enter the six-digit
code shown on the phone. Confirm to approve that key. Refresh the state to
follow publication and completion. Revocation requires the currently displayed
version and a separate confirmation. Completed devices have their own revocation
workflow.

The link and QR disappear on expiry, tab hiding, leaving the section or ending
the session. An ambiguous issue reply can be retried in the same active session
with the original request ID, recipient and expiry. The invitation API enforces
the actor's current ACL and MFA for every mutation.

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
PostgreSQL fixture, with 80% coverage gates for invitation and its independent
publisher bridge. CI enrolls synthetic accounts. The Android client handles
camera, image import and invitation links in its [enrollment screen](https://github.com/nd4y/syn443-android/blob/c92dc9f3c43a8b05d787f8a51840b9b0ff8cfcbe/app/src/main/kotlin/io/syn443/android/EnrollmentActivity.kt).
End-to-end acceptance of a freshly issued console invitation requires a
disposable device, its trusted descriptor and an authorized grant.

Revoking a link after device preparation also retires the still-uncompleted
identity through the narrow maintenance primitive; it cannot strand device seats.
A separate immutable retired marker prevents repeatedly consuming maintenance
slots. Completed sessions require the explicit device-revocation flow, rather
than confusing link invalidation with device revocation.

The closed invitation wire contract is contracts/v1/invitation-openapi.json.
Runtime request/response types are checked against it in Actions; unknown fields,
missing fields, wrong methods and over-budget bodies are rejected. The signer's
private approval receipt also bounds the final commit by the administrator's
access-token/MFA/proof lifetime, including time spent waiting for row locks.
Online device policy refresh is requested within5minutes, rather than30minutes.
