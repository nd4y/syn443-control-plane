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
