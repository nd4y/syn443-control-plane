# Android failure and recovery evidence

The Android v153 [protected CI run](https://github.com/nd4y/syn443-android/actions/runs/45129470974) supplies the lifecycle, rollback, outage and diagnostics results on API 29, 35 and 37. The system installer scenario and historical APK comparison have separate jobs. These are bounded emulator results. The combined cases below remain partial.

## Rollback after policy failure

AC07 covers the effect of an invalid runtime candidate on a previously accepted network setup. The signed candidate that regressed health rolled back, and a separate controller-death case restored its authorized cache.

- `enrolledCandidateRegressionRollsBack`
- `enrolledControllerDeathRecoversAuthorizedCache`

Remaining work includes a crash at every application checkpoint and evidence that NetBird does not register again during that recovery on the original device.

## Control channel outage

AC17 includes actual refusal at the synthetic management socket while an independent app request still passes through the VPN. The test kills the controller, verifies new controller and engine processes, gets another application response on the authorized cached configuration and applies a new signed revision when the management endpoint returns.

- `enrolledManagementOutageRetainsTunnelThroughControllerDeath`

Independent IdP failure, a full telemetry queue and its durable accounting, and current physical pilot readback remain open.

## Diagnostic privacy

AC19 includes synthetic values in nested JSON, private URL paths and queries, VLESS transport service names and crash descriptions. The tests inspect the direct log response and open every ZIP entry to check the generated content.

- `directLogResponseAndEveryArchivedEntryOmitPrivateTransportAndCrashText`
- `nestedSecretsLabelsTargetsAndFreeTextNeverReachComponents`
- `crashesReprojectOnlyClosedKindsTimesAndStatuses`

The physical export and the complete ordinary runtime logging and remote support paths still need acceptance.

## Android owner lifecycle

AC75 includes returning from locked boot, preserving Stop across a reboot, force-stop followed by package replacement, a competing VPN, and preserving binding through package replacement while traffic works.

- `rebootBeforeUnlockDoesNotReadCredentialStateThenReconciles`
- `firstUnlockedStatusPreservesTheAlreadyRecoveredVpnPhase`
- `rebootWithOffIntentCannotStartOrSpendBudget`
- `forceStopThenPackageUpdateCannotResumeWithoutUserConnect`
- `competingVpnOwnsTunAndRevokesOriginalWithoutRetryFight`
- `enrolledVersionUpgradeRetainsBindingPolicyAndRealTun`

The combined sequence on the original enrolled device remains open.

## APK upgrade

AC79 includes [normal system installer cancellation](https://github.com/nd4y/syn443-android/actions/runs/45129470974/job/137546343272) on the enrolled emulator and an upgrade between two independently produced main builds. The [v142 to v153 historical check](https://github.com/nd4y/syn443-android/actions/runs/45142834330) verifies preserved binding and actual application payload.

- `enrolledSystemInstallerCancelKeepsBoundPolicy`
- `enrolledHistoricalUpgradeKeepsOriginalBindingAndPayload`

A counterfeit or interrupted update on device and forward recovery after an incompatible engine migration still need end-to-end evidence.

## Reviewed Android v157 and protected v156

Android v156 passed the protected matrix on API 29, 35 and 37. Each report
contained 675 checks, including actual HTTP exchanges through the recovered
tunnel after Wi-Fi loss. One API 35 job repeated the download after GitHub
returned HTTP 503 before emulator launch. The same protected build also
passed the historical v154 to v156 APK update.

The reviewed v157 source passed 676 checks on each of those APIs. With
the owner diagnostics grant active, `syn443ctl config-render` returns the
current running configuration summary and reports `unavailable` after Stop.
Ordinary applications with their own UID remain outside both ADB providers.
The configuration summary includes counts and protocol names. Full managed
export and import are still partial in AC23.

- [Protected v156 matrix](https://github.com/nd4y/syn443-android/actions/runs/45194104558)
- [Actual older-APK migration](https://github.com/nd4y/syn443-android/actions/runs/45223559650)
- [Reviewed v157 source matrix](https://github.com/nd4y/syn443-android/actions/runs/45204433857)
