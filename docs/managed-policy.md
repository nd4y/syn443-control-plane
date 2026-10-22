# M1 signed policy and activation contract

The M1 publisher is a separate operator role. Its ES256/P-256 private key never
enters the API or APK. The pilot API serves one immutable device-scoped artifact
behind a separately provisioned bearer capability. Full Keycloak/device enrollment,
RBAC, signing-job authorization, root rotation and cohort publication remain M2+.
The API executable binds loopback only; external delivery requires authenticated
TLS termination. Android debug builds additionally allow a specifically provisioned
127.0.0.1 transport only on disposable emulators. Physical and release delivery
require HTTPS. A separately trusted operator CA may be installed in the initial
binding for a private pilot; normal chain/expiry and hostname checks remain enabled.

Compact JWS has exactly three protected header members: alg=ES256,
kid=<pinned publication key>, typ=syn443-policy+jws. Unknown headers, algorithms,
key URLs and roots are rejected. Signature is the 64-byte JOSE R||S representation.
Payload uses RFC8785 canonical JSON with a deliberately restricted safe-integer,
ASCII-metadata schema: policy-payload.schema.json. Engine configuration bytes are
opaque UTF-8 inside unpadded base64url with an independent SHA-256 dependency hash;
floating point in engine JSON therefore never depends on metadata canonicalization.
The verifier rejects duplicate/unknown fields, noncanonical encodings and unsupported
capabilities. Limits are local and a policy cannot disable Stop or watchdog budgets.

Initial debug pilot binding is explicit, once only, through owner-only private
operator-policy.json and policy-bind-file. It pins device audience, publication
public key, delivery origin/capability and an initial trusted time anchor. This is
not trust-on-first-use from a network response. Ordinary import is locked afterward.
The first signed policy must match the current imported config, establishing an
authorized baseline without quietly importing another user's credentials.

| Phase | Durable state and effect |
| --- | --- |
| prepared | Signature/schema/audience/lease/capabilities/config checked; highest revision, epoch and revocation floor persisted before effects |
| applying | Baseline checks saved; isolated native ownership retired before replacement; candidate checks fenced by intent/network/activation/session |
| committed | Required candidate checks passed; active and last-known-good pointers committed in one encrypted AtomicFile |
| degraded | Policy explicitly permits a required target also unavailable on baseline; last-known-good is retained |
| rolled_back | Native failure, regression or deadline; one return to an unexpired, nonrevoked last-known-good snapshot, never repeated candidate activation |
| rejected | Invalid incoming bytes do not replace active state; only redacted code is recorded |

The complete snapshot, raw signed bundles and delivery capability are encrypted
under Android Keystore in no-backup storage. Process interruption while applying
poisons that candidate and restores the authorized pointer, without resetting
intent/restart budgets or reenrolling NetBird. Stop cancels checks and closes their
sockets; late results cannot commit. Applying while Off never turns the VPN on.

Baseline and candidate use the same assigned HTTPS-204 and/or bounded TCP-banner
checks through the TUN, at most eight per job. TLS verification and redirect refusal
remain enabled. An HTTPS required check is mandatory. A failed endpoint alone is
not proof of an engine failure. A degraded activation is explicitly visible.

Offline lease is absolute, at most seven days from issuance. Same-boot time uses
an elapsed-realtime anchor, not a mutable wall clock. Reboot requires a fresh
authenticated delivery response/time before managed traffic resumes. Repeated
bytes, rollback and reboot do not extend expiry; increasing epoch/floor can forbid
rollback. An unavailable control plane within a valid same-boot lease preserves
the active path. An expired/uncertain/unauthorized policy holds a TUN blackhole
while user intent is On, rather than selecting direct. Device-wide protection
outside this app's VpnService still requires Android lockdown.

The shell status exposes only revisions, phase, reason and generation; bundles,
targets, bearer values and NetBird identities do not enter durable events.
policy-stage-file and policy-refresh use the same activation path as delivery.
No debug reset/unmanage operation is exposed on a physical phone.

An explicit signed operation=release uses the same recipient, watermark, lease and
activation gates. It must preserve the original local config exactly and pass all
required checks before atomically clearing the delivery capability. Identity and
user intent remain intact; epoch/revision floors survive a later explicit binding.
This permits reversible pilot testing and authorized transfer of management. It is
not logout or upstream credential revocation. The operator signer requires an
explicit operation grant; an unsigned ADB flag cannot release a managed device.

An Android Activity is not a Connect command. After OS Force stop, reopening the
UI requires explicit Connect; OS stopped state is never bypassed. Revoke/competing
VPN follows the OS permission path. Actual reboot/unlock, Always-on/lockdown,
Doze and energy observations must be reported separately from emulator evidence.

Managed bundles must require `tun.lease.v1`. A native CLOCK_BOOTTIME guard checks TUN reads (including after a blocking read), writes and batched I/O. Expiry permanently retires that TUN owner; a renewal needs a new owner. No wakeup alarm or Java timer is required to deny data packets after suspend. Delivery admission is persisted across controller death, with a five-second manual minimum and a bounded 30-300-second automatic interval.
