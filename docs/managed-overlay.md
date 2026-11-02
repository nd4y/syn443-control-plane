# Managed overlay identity boundary

The server and Android core now derive the same isolated NetBird state namespace
from authenticated service, owner tag and device plus the signed overlay,
provider resource, provider network/tenant, management origin and identity epoch.
The network ID does not mean Wi-Fi/LTE, a peer or a group. Configuration revision,
outbound tag, direct/VLESS mode, transient setup-key reference and signing-root
rotation do not change this identity. A deliberate identity epoch or authority
change does. Seven shared public vectors check cross-language agreement.

The managed root is distinct from the existing operator NetBird state directory.
The helper has no file, network, SDK, secret-delivery, signing or retirement
authority. It does not enable a managed outbound. Android continues rejecting
assigned NetBird configurations until addressed secret delivery, protected local
storage, native ownership/retirement and rollback are integrated and accepted.
Tailscale/ZeroTier remain unimplemented extension contracts.

Before activation the client must derive account/device binding from its verified
login/session, compare the signed overlay resource/network and obtain only that
identity's addressed credential. It must durably record enrollment before effects,
erase the setup secret after acknowledged enrollment, reuse the same SDK keys on
network/config changes and never substitute an operator identity. Logout/revoke
must withdraw permits first, wait for confirmed native owner release, then retire
only the owned managed identity; a permitted rollback retains the old identity.
These remaining paths require independent API/native/physical tests.

## Addressed enrollment-secret authority

The server core also signs and verifies a distinct bounded ES256 envelope with
`syn443-overlay-credential+jws` type and a separate audience. It binds the verified
identity address, device-key thumbprint, opaque reference/version, security epoch,
NetBird setup-key kind and a maximum30-minute validity capped by the policy's
permitted offline lease. A policy signature, parsed setup-key string, caller role
flag or SQL ready field cannot substitute for this signature. The value is only
the addressed setup key; provider management tokens and SDK private keys are not
permitted. Unknown/noncanonical JSON/header/encoding, wrong recipient/reference,
unsupported keys and exact expiry fail closed. Diagnostics redact all contents.
The cryptographic core is accepted separately. The new SQL/HTTP delivery surface
is described in [the delivery contract](overlay-delivery-design.md); its exact
Actions acceptance is pending. Managed SDK activation remains disabled.

Remaining delivery/storage contract: the publication authority signs a grant
only for a currently authorized assignment; the API returns it only under a
fresh session-bound DPoP request/nonce and current ref/namespace permission.
The device validates the independent envelope before any native effect. A stable
protected operation survives reply loss; an SDK enrollment acknowledgment consumes
the grant and erases its local setup secret. Retries after a lost acknowledgment
must be idempotent. A config/transport change does not itself create another SDK
identity. Generation/lease fences prevent late responses from reviving a logged-out
identity. A corrupt/unknown local record blocks activation instead of reusing an
operator SDK key or silently enrolling another peer.
