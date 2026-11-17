# Source, deployment and USB/Wi-Fi checkpoint - 2026-11-17

This checkpoint distinguishes accepted source/main, an actual deployed service
and physical Android outcomes. It supersedes the current checkpoint pointer,
without rewriting historical results or closing the full specification.

## Accepted integration

Each row passed all eight mandatory CI jobs on the candidate and resulting
protected main. Independent verification matched the exact source trees;
later documentation and operational deployment are separate stages.

| Component | Exact accepted source and candidate CI | Protected main and its CI |
| --- | --- | --- |
| Android comparison UI, v89 | `e75d9c919abbeb48d2d2388b1d68a41ae0afc4dc`; [43971441797](https://github.com/nd4y/syn443-android/actions/runs/43971441797) | `6815210c71d1258e85e18f5cc2ced2ddc1027c10`; [43979882809](https://github.com/nd4y/syn443-android/actions/runs/43979882809) |
| Session refresh boundary, PR60 | `54893d535ccba1aee1e1c52744f84b714838de5a`; [43994599921](https://github.com/nd4y/syn443-control-plane/actions/runs/43994599921) | `477856b7bae63e372e52bdabb8cd20f8e6377534`; [43997830289](https://github.com/nd4y/syn443-control-plane/actions/runs/43997830289) |
| Protocol eligibility, PR61 | `e8c120f7973e38ecc72d09964266abd61b22e25e`; [44006215112](https://github.com/nd4y/syn443-control-plane/actions/runs/44006215112) | `28f58cdda37d0f24309d59cabac2ba1a30436fdb`; [44009146272](https://github.com/nd4y/syn443-control-plane/actions/runs/44009146272) |
| Read-only operator fingerprints, PR62 | `38a8577d06f28274341dd320dc8f64df9fd19c92`; [44010317494](https://github.com/nd4y/syn443-control-plane/actions/runs/44010317494) | `656cfc5c157901a44490d03d18a00f8897dce9c7`; [44013627735](https://github.com/nd4y/syn443-control-plane/actions/runs/44013627735) |

Android v89 passed449 JVM cases, including288 identity cases,398 required
outcomes on each API29/35/37 and53 native roots in ordinary and race runs.
The later v90 operation-reconciliation candidate is not covered by that receipt.

PR61 adds fourteen actual Go/PostgreSQL/HTTP outcomes and six validator cases.
PR62 adds six actual CLI outcomes and five validator cases while retaining the
fourteen eligibility outcomes. Its fingerprint command reads bounded owner
input and returns closed metadata including native owner and grant hashes;
it does not authorize an account, load runtime
configuration, connect to SQL or prove live ownership. It has not been executed
against the pilot. Neither PR61 nor PR62 is claimed as a deployed feature.

## Actual Android and refresh-boundary acceptance

The exact Actions v89 APK was installed on the USB test Xperia with the existing
development signer and identical non-signature payload. Encrypted pre-install
recovery material and APK/source/native-library hashes were kept privately.

The physical run passed68 unique outcomes:20 original presentation/storage
cases,13 administrator presentation cases,19 editor presentation cases and16
comparison presentation cases. Synthetic identity, signing-root, coordinator
and encrypted-owner fixtures stayed on CI emulators. These phone outcomes are
not authenticated native administrator SSO, server editing or publication.

The same phone exercised two real Wi-Fi loss/return cycles and an actual native
engine process failure. The replacement process, TUN ownership and independent
HTTPS204 were checked. The original device identity, assignment, consent and
system settings were preserved; all15 cleanup steps passed. The test APK was
removed and the accepted application remained Online on Wi-Fi in airplane mode.
An independent verifier parsed every unique instrumentation outcome and checked
the installed APK hash and fresh VPN state.

PR60 fixes a server access-session deadline that could exceed its absolute
refresh-family deadline near the end of that family. The client correctly
rejects such a session; the server now caps the access deadline by the current
refresh deadline as well as the account deadline. Six actual PostgreSQL roots
cover the boundary. The precise last HTTP delivery or rejection in the earlier
phone incident was not captured, so the incident is not attributed solely to
that defect.

Only the accepted device API binary was deployed. Its actual process hash,
mount and stable health were checked; the other running service instances and
account/device/schema/effective SQL grants remained unchanged. The existing
migration-only owner input and binary were preserved and reviewed for
idempotence. A rollback plan and old binary remain available; rollback was not
needed. No new administrative grants or version-two owner declaration were made.

After deployment, a natural scheduled phone refresh advanced its session while
preserving the absolute refresh deadline, device identity and configuration.
The access deadline stayed within that family and VPN/HTTPS remained available.
This is a real scheduled refresh, not a physical24-hour family-expiry test.

## Open acceptance

The full292 requirements and98 scenarios remain the product scope. This
checkpoint does not promote broad requirement statuses from component results.

- Native administrator SSO, scoped rights/MFA, real edit/preview/publish,
  conflict handling and lost-response reconciliation still need live acceptance.
- The ledger, protocol eligibility and coordinated version-two queue-consumer
  activation remain deployment/migration work.
- A managed signed adaptive configuration still needs actual chain selection,
  context invalidation, fault recovery and policy rollback on the phone.
- Full protocol/transport acceptance, first-launch invitation/QR/root rotation,
  cohort policy rollout, complete telemetry/retention and operational restore
  remain open where their specific receipts are absent.
- LTE/restricted LTE and Wi-Fi/LTE transitions are excluded. Natural Doze,
  unplugged battery and endurance are also unverified.

All builds and executable off-device suites run in GitHub Actions. Phone
identifiers, private service/provider addresses, credentials, configurations,
backups and raw operational/device evidence are excluded from this repository.
