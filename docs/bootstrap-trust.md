# Bootstrap trust and invitation links

`internal/bootstrap` authenticates service metadata locally before discovery or
transmitting an invitation code. The installation root is separate from online
policy keys and APK signing. An invitation contains a signed service descriptor,
an opaque32-byte code, the service ID and exact HTTPS API origin. It contains no
trusted inline replacement root. Unknown signer/key headers are rejected.

The versioned form is `syn443://enroll/v1` with exactly `service`, `origin`, `code`
and `bootstrap` query fields. Parsing rejects duplicates, fragments, unknown
versions/fields, invalid encoding and links beyond8KiB. The descriptor must bind
the same service/origin and supplies the pinned issuer/client/publication keys.
Neither a valid descriptor nor a link grants a user/admin role. Codes must be
generated with cryptographic entropy by the invitation service, stored as hashes,
used once and bound to device proof of possession and administrative confirmation.

Descriptors use a closed canonical ES256 JWS with a distinct protected type,
root epoch, per-service revision, validity and audience. The device must durably
retain its greatest service revision/hash. Same-revision replacement and rollback
are denied. Identical bytes do not extend validity. HTTPS URLs are canonical ASCII
origins/issuer paths; no credential/query/fragment/key-discovery URL is accepted.

Offline root rotation requires matching transition payloads signed by both old
and new roots, the exact next epoch and a bounded validity interval. The new
state must be durably committed before accepting fresh links. Retired roots
cannot authorize new enrollment. A repeated accepted transition is idempotent;
an expired unaccepted transition is rejected. Loss/compromise recovery uses the
separate trusted release/recovery channel, never a key from an untrusted response.

Actions enforce signature, canonical encoding, trust substitution, expiry,
revision/root replay, dual authority, malformed links and redaction tests plus
fuzzing and an85% package gate. This is the Go trust component. Shared wire vectors,
Android persistence/scanning, the one-time SQL invitation service, admin approval
and final phone acceptance remain required before the M2 flow is complete.

## HTTPS invitation landing page

An installation can publish a public invitation host and bind it to its signed
Android APK. Use `https://HOST/syn443/enroll#` followed by the full
`syn443://enroll/v1` invitation. The QR still uses the direct invitation.
The browser omits the fragment from the landing request.

`tools/build_enrollment_site.py` writes two static files to a new directory.
Pass the HTTPS download URL for the signed APK and one `--sha256` per allowed
app-signing certificate. Serve `.well-known/assetlinks.json` as
`/.well-known/assetlinks.json` over HTTPS with HTTP 200 and
`Content-Type: application/json`. Serve `enroll.html` at `/syn443/enroll`.
The landing page offers installation and asks the user to open the original
link again. It runs no script and does not recover the invitation.

Use the same public host in the Android Actions build. Certificate fingerprints
must match the distributed APK. Real association and physical opening still
require a deployed HTTPS host and a signed APK. [Android App Links verification](https://developer.android.com/training/app-links/verify-applinks)

## Installation profile for first launch

The offline `enrollment-admin bootstrap-profile` command reads the owner document
at `SYN443_BOOTSTRAP_PROFILE_SPEC` and the P-256 root key file at
`SYN443_BOOTSTRAP_ROOT_KEY`. The document contains `anchor` and `service`
objects matching the public trust anchor and service descriptor. The command
uses no database or provider connection. It writes one base64url installation
profile containing the public anchor and signed descriptor. Keep the offline
private key on its own trusted host. Only explicitly public endpoints and
public keys can be used in a distributed profile.

For a planned rotation, set `anchor` and `service.rootEpoch` to the next root
and increment `service.revision`. Add `upgrade.previousAnchor` with the exact
prior APK anchor and `upgrade.transition` with the adjacent `syn443-root-transition`
payload. Use `SYN443_BOOTSTRAP_PREVIOUS_ROOT_KEY` for the previous offline key
and `SYN443_BOOTSTRAP_ROOT_KEY` for the next offline key. The same command signs
both proofs, checks the target anchor and emits a version 2 profile. Both keys
stay on the offline signer. The APK build receives only the public profile.

Test an upgrade and a clean install before rollout. Distribute the signed APK
within the transition's validity window. Keep a fresh version 1 descriptor
signed by the new root for later APK releases. An installation that missed
the transition window needs a separate trusted recovery release. Keep the
old deployment active until the upgrade has been accepted on the pilot devices.
