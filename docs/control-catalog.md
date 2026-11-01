# Control catalog service

The `control-api` and `source-worker` executables use separate restricted SQL
roles and owner-protected configuration files. Neither receives a signing key,
device-session grants, schema ownership or permission to create administrative
ACL. Run owner migrations/initial grants separately. The source worker only
loads and normalizes data; a successful source job is not a policy publication.

The control audience is `syn443-control-api`, with the explicitly pinned
`syn443-control-web` and/or `syn443-control-mobile` public clients. Device/chat
tokens cannot substitute for it. The API requires signed scope `syn443.control`,
key/token/body/origin-bound DPoP, a durable unique proof identifier and live SQL
object authority. Initial ACL actor IDs are the SHA256/base64url identity hash of
`issuer + NUL + subject`; display names/email/provider user IDs are not identity.
Sensitive mutations additionally require a signed, pinned IdP ACR plus OTP or
security-key AMR and authentication within ten minutes. Token refresh alone does
not extend that assurance window. IdP configuration must actually issue these
claims after strong authentication; the client cannot assert them.

The [closed API contract](../contracts/v1/control-openapi.json) defines supported
catalog actions. Unknown/missing/case-variant members, URL queries, cross-origin
browser requests, replayed proofs and stale revisions are rejected. Lost replies
retry the same operation ID and body with a new proof. Inventory exposes IDs,
names, types, quota/expiry and state, never outbound credentials. Source import
has a separate10MiB decoded budget; ordinary identity/admin DTO limits stay small.

The source worker has40 seconds per claimed job inside its60-second lease,
bounded HTTP time/size/redirect/DNS egress and no provider writes. Resource/source
revision, active head, lease and cancellation are rechecked at commit. HTTP
authentication failures preserve only the existing bounded valid snapshot;
explicit upstream user revocation/expiry removes eligibility.
The durable access denial is separate from refresh state: rename, credential
rotation or a later network/authentication failure cannot revive a revoked cache.
Only a newly accepted verified snapshot can restore it. Cache TTL/provider expiry
remain visible even when the most recent refresh failed. Source recipient
changes require both share and receive authority; device-fetched data is personal.
Large removals are quarantined until an exact hash/head/revision-bound decision.
Review cannot approve expired/quota-exhausted access or dangling profile references.

Runtime files use `SYN443_CONTROL_CONFIG` / `SYN443_SOURCE_CONFIG`. Their schema is
the closed `catalog.RuntimeConfig`; verified remote PostgreSQL TLS is mandatory.
API listeners are loopback-bound and serve HTTPS behind an owner-configured ingress.
Fixture HTTP and literal-loopback provider access are separate owner-only process
settings, absent from all resource/source mutation DTOs. All binaries are built
and scanned in GitHub Actions. Actual service deployment and real users are not CI.

This is the catalog service stage of M2/M3. Dynamic compilation/signing, the full
web/native administrative UI, managed invitations/overlay and final physical
acceptance remain required. See [the completion map](m2-m3-completion.md).
