# Device chat and accepted source - 2026-11-15

Android77 passed scoped USB/Wi-Fi acceptance with working device chat. Both
repositories have accepted source in main. Full M1-M5 and version1.0 remain open;
the specification still contains292 requirements and98 acceptance scenarios.

| Scope | Source and exact Actions evidence |
| --- | --- |
| Installed Android77 /0.9.49-chat-recovery | [26e5b1c](https://github.com/nd4y/syn443-android/commit/26e5b1c88483a246290992a48d01767322b9def5), [43715973501](https://github.com/nd4y/syn443-android/actions/runs/43715973501): all8 jobs,240 actual unique zero-skipped outcomes per API29/35/37 |
| Android integration | [b85bc1d](https://github.com/nd4y/syn443-android/commit/b85bc1d11e9cce35c417f9adb06cc2f460cbf440), [43721394149](https://github.com/nd4y/syn443-android/actions/runs/43721394149): all8; main [665ba5a](https://github.com/nd4y/syn443-android/commit/665ba5a9694ac4aaf8b5d862f4f76cabacefa72f), [43728343944](https://github.com/nd4y/syn443-android/actions/runs/43728343944): all8 |
| Separate administrator issuer | [f804da1](https://github.com/nd4y/syn443-control-plane/commit/f804da108d4208711c356dcbc26ccc878418f377), [43722191556](https://github.com/nd4y/syn443-control-plane/actions/runs/43722191556): all8,72 actual browser outcomes; provider11/11 covered statements |
| Separate console/chat API and web-only accounts | [0c5c970](https://github.com/nd4y/syn443-control-plane/commit/0c5c970890079da454e1d293bc02aa49e83f6562), [43731289519](https://github.com/nd4y/syn443-control-plane/actions/runs/43731289519): all8; main [2021983](https://github.com/nd4y/syn443-control-plane/commit/202198318727bd2e7295bdd3fdd5945466b50a9f), [43732876881](https://github.com/nd4y/syn443-control-plane/actions/runs/43732876881): all8 |

The Android integration Git trees are identical to the accepted installed source.
The installed APK remains pinned to26e; later source/documentation heads are not
presented as a different APK already installed on the phone. Delivery checked the
Actions archive hashes, source-input manifest, APK/AAR and both native ABIs.
The existing private signer was retained, preserving every payload member.

## Actual device acceptance

The Xperia upgrade retained its Keystore key, registration, encrypted assignment,
configuration and telemetry consent-off setting. The operator intentionally
stopped VPN before installing. Three chat UI cases ran while it remained Off,
including repeated recreation/background transitions. Explicit resume restored
an actual Android VPN and independent HTTPS204.

The screen first showed the accurate unavailable-chat state with an empty outbox.
After the isolated device API was enabled, the authenticated conversation and
composer loaded. Five distinct fresh chat entries kept the same VPN intent
generation and identity. A six-second Wi-Fi loss/return restored the original
network, a fresh chat response and HTTPS204. The final check verified the exact
installed APK, original radio/screen settings and rejection of an emulator-only
readiness probe on real hardware. No test messages or files were sent.

An initial readiness wait timed out; a following navigation encountered the
unsecured keyguard. Foreground readiness was corrected. Another attempt reached
the conversation but failed its independent HTTPS request. The later ready-chat,
Wi-Fi and final phases passed. Original failures are retained, and no permanent
network root cause is claimed from the later successful request.

This used a direct-only signed pilot policy. It does not newly accept the complete
encrypted proxy/NetBird matrix. LTE, restricted LTE, natural Doze, unplugged energy
and long endurance remain deferred.

## Client and test boundaries

Only the exact disabled chat self endpoint maps404 to unavailable. Empty queues
do not invent a saved message. One owned refresh uses bounded failure backoff,
manual/throttle floors, cancellation and account-generation fences. Eight named
JVM cases and23/23 covered scheduler lines passed. Raw Android XML verified240
unique actual outcomes on every supported API, including both new lifecycle
fixture boundaries. No skip, reset-guard relaxation or reduced gate was used.

## Source versus pilot deployment

The isolated pilot enables only the existing device chat API. Its anonymous
boundary, unchanged identity/ACLs and other six service containers were checked.
The encrypted SQL backup passed decryption/readback and archive-list verification;
a full restore was not tested. Rollback restores the prior compose/configuration
while retaining SQL history. Credentials, backups and physical evidence stay
outside public repositories and Actions.

The accepted administrator source separately pins its issuer and chat API origin.
Owner-issued web-only accounts use device limit0, CAS updates, idempotent replay
and atomic owner audit. Actual SQL tests denied VPN enrollment and stale grants,
preserved existing VPN accounts, and rolled back an audit failure. The independent
grant coverage gate passed86.8% against80%. These source changes have not yet
been deployed or used to grant a real administrator chat account. The PatternFly
support workspace is a later feature under separate CI/live acceptance.

## Adaptive routing remains open

Shared bounded graph conformance and private construction have accepted CI.
Runtime catalogue resolution, shared resource admission, active/draining owners,
connection pinning, fresh selection proofs, signed activation/issuance and actual
alternative-chain recovery remain required. The graph capability is unadvertised.
Component acceptance does not close the autonomous-routing or release milestones.
