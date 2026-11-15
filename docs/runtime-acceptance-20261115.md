# Runtime reporting acceptance - 2026-11-15

This supersedes the runtime delivery status in the earlier dated checkpoint.
Full M1-M5 and version1.0 remain open. The normative292 requirements and98
scenarios are unchanged. No LTE, restricted LTE, natural Doze, unplugged battery
or long endurance acceptance is implied.

| Component | Accepted source | Exact Actions evidence |
| --- | --- | --- |
| Android75 /0.9.47-runtime-observations | [`c32d03f`](https://github.com/nd4y/syn443-android/commit/c32d03f83d6d866816cdd569321f22e65a332775) | [43670328240](https://github.com/nd4y/syn443-android/actions/runs/43670328240): all8 jobs;235 outcomes each API29/35/37,165 identity JVM cases, zero skips/errors/failures |
| Runtime backend and console | [`f05dcd9`](https://github.com/nd4y/syn443-control-plane/commit/f05dcd94dc0ab650f7058216cc1ae5cf809c35f7) | [43663317952](https://github.com/nd4y/syn443-control-plane/actions/runs/43663317952): all8 jobs;64 browser outcomes, SQL/wire/role and actual temporary Keycloak checks |

Archives, manifest, APK/AAR, both native ABI hashes and signer were independently
verified. Re-signing preserved all non-signature APK members. The v74-to-v75
Xperia upgrade retained its key, binding, encrypted assignment, configuration
and VPN intent. Real runtime delivery passed online, Stop and unchanged stale
receipt, resume, consent withdrawal while VPN stayed online, controller restart
and Wi-Fi recovery. Actual engine/Android VPN and independent HTTPS204 were
checked. Current-key SQL samples had the expected build/policy/network and
respected the durable60-second budget after recovery.

One initial Wi-Fi collector attempt read the SSID before association. It remains
NOT_VERIFIED; only collector readiness was corrected, and the full case then
passed. Original consent-off, Wi-Fi, stay-awake and airplane settings were
restored, with VPN Online. This was a direct-only signed pilot policy: it does
not newly accept the complete encrypted proxy/NetBird/chain matrix.

The preceding [v74 source](https://github.com/nd4y/syn443-android/commit/65fa804e015397f260f9f2015100f123ca1c1e21)
passed [all8 jobs and228 outcomes per API](https://github.com/nd4y/syn443-android/actions/runs/43663104984).
It corrected the reproduced API29 journal allocation defect with bounded
streaming while retaining storage compatibility. Its physical native exit6,
controller and Wi-Fi recovery timings9.94s,8.58s and14.38s belong to v74.

The backend's additive migration and executable rollout preserved device,
account, ACL and activation fingerprints and database/gateway/publisher container
identities. Executable and HTTPS asset hashes matched Actions. Real personal
Keycloak SSO discovered Xperia, opened its configuration, displayed the actual
build75 report and aged it after Stop without renewing its timestamp. Personal
write/MFA acceptance remains separate; no additional personal rights were granted.

An open card retaining its old report after real recovery was reproduced. The
[foreground refresh correction](runtime-console-refresh.md) has its own72-case
CI, artifact and live web-only rollout gates. The accepted backend64-case
snapshot alone does not accept this correction.

Android [PR61](https://github.com/nd4y/syn443-android/pull/61) merged to
[`c26906f`](https://github.com/nd4y/syn443-android/commit/c26906fd243453ac4f2155ae13cb5f6af76fc4fc)
with the exact accepted c32 tree; separate main validation is
[43677632814](https://github.com/nd4y/syn443-android/actions/runs/43677632814).
Backend [PR38](https://github.com/nd4y/syn443-control-plane/pull/38) merged to
[`092e062`](https://github.com/nd4y/syn443-control-plane/commit/092e0628f5a9b59e7f071014accac62b736a4afb)
with the f05 tree and [all8 main jobs](https://github.com/nd4y/syn443-control-plane/actions/runs/43672933382).
The earlier public-digest scan failure remains historical evidence. Exact
reviewed path/field/value exceptions retain default detectors, full-history
scanning and negative checks; unverified side branches remain separate.

Full administration/settings, managed overlays, protocol/chain acceptance,
four-mode graph routing, telemetry/retention and release gates remain required.
Raw device, credential, user and provider evidence stays outside public GitHub.
