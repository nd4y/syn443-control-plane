# Accepted non-LTE checkpoint - 2026-11-15

This checkpoint records specific source, CI and physical evidence. Full M1-M5,
version1.0 and production acceptance remain open. The normative specification's
292 requirements and98 acceptance scenarios are unchanged. LTE, restricted LTE,
natural Doze, unplugged battery and long endurance were not tested in this round.

| Component | Accepted source | Exact GitHub Actions evidence |
| --- | --- | --- |
| Android v73 /0.9.45-runtime-security | [`c68398ec23db7338e004e68bf3bc51733011db19`](https://github.com/nd4y/syn443-android/commit/c68398ec23db7338e004e68bf3bc51733011db19) | [43652632634](https://github.com/nd4y/syn443-android/actions/runs/43652632634): all8 jobs;225 mandatory outcomes on each API29/35/37, zero skips/errors/failures |
| Control Plane | [`4189e4750cb62881d83367e724e4fae1ff87f0f2`](https://github.com/nd4y/syn443-control-plane/commit/4189e4750cb62881d83367e724e4fae1ff87f0f2) | [43655979806](https://github.com/nd4y/syn443-control-plane/actions/runs/43655979806): all8 jobs;59 required browser outcomes and actual temporary Keycloak OTP |

## Android delivery and device checks

The exact Actions archive, manifest, APK hashes and both native ABI libraries were
verified. The AAR uses Go1.26.11; the synthetic Go/Kotlin fixture uses Go1.27.4.
Engine source/patch pins are unchanged. All four serialization consumers use
1.13.0. Strict wire and journal recovery checks remain required.

The USB Xperia XQ-CT72 received the APK with its existing private development
signer. Re-signing preserved every non-signature APK member. Upgrade retained the
Keystore identity, registration, intent and configuration, then recovered Online.
An actual native SIGABRT/exit6 recovered in9.91s, controller process death in8.07s
and Wi-Fi loss/return in14.73s. Each check retained identity/configuration/generation,
confirmed an active Android VPN and independently received HTTPS204. Original
Wi-Fi and stay-awake settings were restored; airplane mode stayed enabled.

This round used a direct-only signed pilot policy. It verifies lifecycle,
identity and connectivity recovery; it does not prove encryption, the complete
proxy matrix, NetBird or LTE on this new binary. Earlier protocol/device evidence
remains dated evidence, not a new acceptance of every route.

## Control console and pilot

The actual PatternFly React console discovers only devices allowed by the live
scoped read grant. Pagination, malformed metadata, expiry/revocation and keyboard
focus have mandatory browser coverage. The selected card shows desired settings,
issued policy and the last activation report separately. Lease renewal does not
invent a new activation event, and an old report is visibly historical.

Scoped sensitive operations can ask for explicit fresh MFA without erasing the
original tab's edit and exact pending request. The callback pins the original live
session and verified owner, requires configured ACR/AMR/authentication time and
cannot win a logout race. Retry remains manual. SQL preflight cannot mutate or
publish, and withdrawn rights still erase private UI data. The actual disposable
Keycloak fixture verifies password-only denial followed by real OTP and signed
assurance claims; browser fixtures alone are not used as identity evidence.

The private pilot received the exact verified control/web/publisher binaries and
the matching optional BFF assurance setting. Database, gateway, owner/device
services and grants were preserved. Real personal Keycloak SSO, authorized Xperia
discovery and card/settings readback passed after deployment. Personal sensitive
write/MFA acceptance remains open: the account currently has read-scoped grants.
No additional personal privileges were granted during this checkpoint.

## Integration and remaining scope

The integration branches preserve the accepted executable source and add only
this evidence update, roadmap/register notes and corrected historical headings.
Merge state and main CI are separate GitHub observations; a pinned feature run
is not a claim that main or an installed APK has a different source revision.
Unverified dependency and side branches remain separate.

Native administration, complete application settings/provenance, full protocol
and chain acceptance, live managed overlays, complete four-mode discovery and
route scoring, telemetry/retention operations and the remaining release gates
stay required. Multiple Remnawave/x-ui/3x-ui and Tailscale/ZeroTier remain extension
contracts by explicit scope. Raw device, credential, user and provider evidence
stays outside public GitHub source, discussions and artifacts.
