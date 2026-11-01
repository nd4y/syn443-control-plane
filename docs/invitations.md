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

Implemented component stages are issue, claim, approval, status and link revoke.
Signer receipt validation/device creation, session finalization/abandonment,
HTTP/schema integration, protected Android journal/camera/Intent/paste and final
device acceptance remain required before this flow is operational. No endpoint
or application capability advertises the incomplete flow. All SQL/role tests
execute on a dedicated disposable Actions database with an80% coverage gate;
no real users/accounts are enrolled by CI.
