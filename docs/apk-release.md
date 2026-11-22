# Issue an Android update manifest

The `apk-release-linux-amd64` Actions artifact contains the offline `apk-release` operator command, its source revision and an executable checksum. The normal Android release job supplies `inventory.json`. Sign that APK using the Android release process, then run the Android repository's `tools/verify_signed_apk.py` with the approved unsigned input digest and the independently trusted Android signing certificate. Save its JSON output as `signing-receipt.json`.

The release metadata key is a dedicated P-256 key. Configure its public anchor and the approved Android package certificate independently. Use an owner-readable PKCS#8 key file on the signing host. The verifier needs only public key material, the installed configuration and the previous release floor.

## Inputs

Keep the trust and offer files owner-only. A new installation starts with an explicit empty `floor` object. For an existing installation, supply its saved floor. The scope contains `serviceId`, `deviceId`, `channel` and `signerCertificateSha256`. The device ID is the current 32-byte registration identifier encoded in unpadded base64url. The certificate digest uses lowercase hexadecimal SHA-256.

| Trust file field | Value |
| --- | --- |
| `anchor` | Release metadata key ID, base64 DER SPKI, root epoch and last transition, in the existing SYN443 anchor format |
| `scope` | Approved service, device, channel and APK signing certificate |
| `installed` | Current `versionCode`, `sdk`, ordered `abis`, `requiredEngineCapabilities`, current `evaluator` and `schema` |
| `floor` | Last successfully accepted release journal, or `{}` at initial provisioning |

The offer contains `inventorySha256` from the reviewed Actions input, `receiptSha256` from the operator's verified signing receipt, and the addressed publication's `securityEpoch`, `revision` and `revocationFloor`. Specify `issuedAt`, `notBefore` and `expires` as Unix seconds. The validity interval can span at most seven days. Under `compatibility`, provide `minimumInstalledVersionCode` and sorted, unique lists of `engineCapabilities`, `evaluators` and `schemas` from the reviewed release.

## Sign and check

```sh
umask 077
export SYN443_APK_RELEASE_KEY_FILE=/path/to/offline-release-key.pem
apk-release sign trust.json offer.json inventory.json signing-receipt.json app-release.apk > addressed.jws
```

Both commands stream and hash the final signed APK. The signed manifest binds the package and certificate, version, byte size, SHA-256, SDK, per-ABI engine hashes, source commit, engine and contract locks, and the approved compatibility data. The signer matches the independently approved inputs before issuing the manifest.

```sh
apk-release verify trust.json addressed.jws app-release.apk > accepted-floor.json
```

Verification requires a current validity interval, a matching recipient and channel, the expected Android signer, at least one supported ABI, an eligible installed version and support for the installation's active capabilities, evaluator and schema. An identical manifest can be read again. A changed payload at the same revision, an older revision or a lower security or revocation floor fails. Retain the previous floor on error. On success, persist the returned floor and its exact manifest together before accepting another update for that installation.

Operational trust files, addressed manifests and recipient journals belong in per-device private storage. The public CI artifact contains the generic operator executable. Android delivery, system installation confirmation and preservation of the registered application state require separate device acceptance.
