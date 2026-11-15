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

The accepted API and PatternFly support workspace are now deployed in the
isolated pilot from [778f65c](https://github.com/nd4y/syn443-control-plane/commit/778f65c59b9e128994eff935ca342a659fbd8eb1).
[Exact Actions43735156473](https://github.com/nd4y/syn443-control-plane/actions/runs/43735156473)
passed all8 jobs and79 actual browser cases without skips. All13 UI asset bytes
were independently matched inside the shipped binary and over trusted HTTPS.
Anonymous API/BFF requests were denied. Device chat loaded freshly before and
after a new Wi-Fi interruption with the original installed Android77 identity,
configuration, intent generation and HTTPS204 preserved. No message was sent.

The owner CLI migrated the compatible zero-device constraint and owner audit
schema. Its temporary container used the exact database network namespace,
supported CPU-time/memory limits and a healthy-database dependency, then exited0
and was removed. An earlier unsupported CPU quota and incorrect temporary network
binding failed before SQL changes; both failures remain recorded. A compose
restoration recreated all seven pilot containers; service configurations and data
binds were checked separately from container IDs. No uninterrupted-process claim
is made. Encrypted SQL backups passed decryption/readback and archive listing;
a full restore remains untested. Rollback retains compatible schema and history.

The API separately pins the web issuer and chat origin. An explicit grant for the
existing administrator account has device limit0, an expiry of at most seven days
and atomic owner audit. Existing device/account/ACL/admin fingerprints and chat
history were preserved, runtime roles cannot insert owner audit, and no VPN device
was enrolled by this web-only role. Source SQL tests also deny stale grants and
VPN enrollment and roll back audit failures; the grant coverage gate passed86.8%
against80%. Actual normal Keycloak login, the administrator conversation and
phone/web text/file exchange remain open live gates. Source/browser tests and
asset hashes cannot substitute for them. Credentials, private network/device
identifiers, SQL backups and actual hardware evidence stay outside public repos.

## Adaptive routing remains open

Shared bounded graph conformance and private construction have accepted CI.
Runtime catalogue resolution, shared resource admission, active/draining owners,
connection pinning, fresh selection proofs, signed activation/issuance and actual
alternative-chain recovery remain required. The graph capability is unadvertised.
Component acceptance does not close the autonomous-routing or release milestones.
