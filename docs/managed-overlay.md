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
