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
authority. Android enables a managed outbound through its controller after
verifying the assignment and addressed credential. The controller uses a
Keystore-backed vault and an SDK directory bound to this managed identity.
Tailscale/ZeroTier remain unimplemented extension contracts.

Before activation the client must derive account/device binding from its verified
login/session, compare the signed overlay resource/network and obtain only that
identity's addressed credential. It must durably record enrollment before effects,
erase the setup secret after acknowledged enrollment, reuse the same SDK keys on
network/config changes and never substitute an operator identity. Logout/revoke
must withdraw permits first, wait for confirmed native owner release, then retire
only the owned managed identity; a permitted rollback retains the old identity.
The [Android implementation and physical pilot evidence](https://github.com/nd4y/syn443-android/blob/4dfffe92c6dbf86f4be9b7b86c3473362f30d2d1/docs/managed-overlay.md)
record the tested enrollment, connectivity, recovery and retirement paths.

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
The [delivery contract](overlay-delivery-design.md) describes SQL/HTTP fetch
and consumption. The [portable configuration](portable-netbird.md) describes
how the publisher and broker bind them to a permitted provider resource.

The publication authority signs a grant
only for a currently authorized assignment; the API returns it only under a
fresh session-bound DPoP request/nonce and current ref/namespace permission.
The device validates the independent envelope before any native effect. A stable
protected operation survives reply loss; an SDK enrollment acknowledgment consumes
the grant and erases its local setup secret. Retries after a lost acknowledgment
must be idempotent. A config/transport change does not itself create another SDK
identity. Generation/lease fences prevent late responses from reviving a logged-out
identity. A corrupt/unknown local record blocks activation instead of reusing an
operator SDK key or silently enrolling another peer.

## Admitting an additional overlay provider

A resource adapter establishes management access. The device separately needs an
embedded engine that can carry traffic inside the application's single Android
VpnService. Registering a management endpoint or naming a provider in a policy
does not establish either capability. Tailscale and ZeroTier reserve names only.

| Review before enabling a provider | Required evidence |
| --- | --- |
| Management and enrollment | A scoped server adapter can issue and revoke a credential for the intended device and provider network. An unavailable adapter remains ineligible. |
| Embedded Android module | Pin its source and license in the engine lock, retain redistribution notices and verify the packaged ABIs in the release APK. |
| Device eligibility | The installed device advertises the exact provider capability. The signed addressed policy and credential match its service, account, device, resource and identity epoch. |
| Android networking | The module shares the existing TUN and socket protection. Exercise its DNS, IPv4/IPv6 capabilities, cancellation, owner death and reconnection with application traffic. |
| Resource and release acceptance | Measure memory, wakeups, network use and recovery on supported devices. An older or incompatible device keeps its working assignment. |

The current catalog tests reject activation and credentials for placeholder
providers. Android's provider-status test returns their unavailable state without
reading a running NetBird connection. Protected results are available from the
[Control Plane suite](https://github.com/nd4y/syn443-control-plane/actions/runs/45096827956)
and the [Android suite](https://github.com/nd4y/syn443-android/actions/runs/45070035378).
