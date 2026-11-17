# Actual Go operation reconciliation wire fixture

`cmd/layer-fixture --operations` is a separate synthetic wire producer for the
native editor's retained-operation reconciliation codec. The producer and its
19 source-bound cases are unchanged. This workflow revision validates the full
signed specimens in Actions, removes them, then publishes only a scanned
metadata report. Acceptance of that workflow revision remains pending Actions.
It neither proves SQL outcomes nor activates client recovery, configuration
publication or a live service.

The producer accepts no input and requires `GITHUB_ACTIONS=true`. It marshals
actual `invitation.Envelope`, configuration draft/proposal and
`ConfigurationOperationOutcome` types. The private HTTP input wrappers retain
the actual server fields and tags through AST assertions and the current
OpenAPI schema. No server DTO, route, schema, lock, SQL role or runtime trust is
changed. The existing default layer-wire and `--projection` output paths are
unchanged; an actual test compares their bytes before and after this new mode.

The temporary specimen output root has exactly these fields. This is the
in-job ABI, not the public artifact:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | `1` |
| `syntheticOnly` | `true`; never an authority signal |
| `nowMs` | Fixed synthetic verification time `1800000000000` |
| `actor` | Actual `identity.Hash` of a reserved synthetic issuer, NUL and subject |
| `apiOrigin` | `https://control.example.invalid` |
| `proposalWire` | Original actual-Go JSON bytes encoded as a JSON string |
| `previewKeyId` | `synthetic-operation-root` |
| `previewRootSpkiB64` | Standard Base64 public P-256 SPKI DER, never a private key |
| `originals` | The eight original-operation records below |

Original names are `draft-put-v1`, `draft-discard-v1`, `preview-v1`, `publish-v1`,
then their `v2` counterparts in the same order. Each record has exactly `name`,
`originalBody64`, `bodyHash`, `jobId`, `lookupWire`, `sealWire`, and `outcomes`.
`originalBody64` is canonical unpadded base64url of the original marshaled action
body. `bodyHash` is lowercase hexadecimal SHA-256 of those exact bytes, not a
reconstructed JSON value. For preview and publish, `jobId` is the actual
`identity.Hash(actor + NUL + originalRequestId)`; drafts use an empty job ID.
Each lookup/seal string retains the identical original bytes and uses a separate
outer reconciliation request ID. The envelope version remains `1` for that
reconciliation request, independently of the original action version.

Each outcome has exactly `name` and `wire`. The 36 wires are actual Go DTO JSON:

- `UNKNOWN`, `RECORDED`, and `RECORDED_RESULT_UNAVAILABLE` for all eight originals.
- `NO_EFFECT` for the four version-two originals only.
- `RECORDED_RUNNING` and `RECORDED_READY` for both preview originals.
- `RECORDED_RUNNING` and `RECORDED_PUBLISHED` for both publish originals.

The last three labels describe fixture cases; their actual wire `outcome` stays
`RECORDED`. Queued/running jobs are retained operations, not terminal success.
Nil `job`, empty `error` and absent `result` use the actual Go `omitempty`
behavior. Missing retained results remain explicitly unavailable; version-one
absence remains unknown. The producer supplies synthetic typed values rather
than querying SQL. The separate accepted PostgreSQL operation tests establish
locking, durable fences, quotas and outcome truth.

The proposal contains a minimal template plus an explicit device layer and a
direct portable plan, checked by real `configuration.Merge` and
`DecodeNetworkPlan`. It does not invoke VPN compilation, network probes, provider
resolution or publication. Dependency/effective hashes and recipient identities
are explicitly synthetic context, not assertions about a live device.

For the two publish originals the producer creates one ephemeral P-256 key in
memory, calls actual `configuration.SignPreview`, and immediately calls actual
`VerifyPreview`. Public SPKI and signed synthetic tickets enter only the owned
temporary specimen used by the in-job validation.
Tests verify the tickets, reject a 64-byte zero signature and wrong root, actor,
origin or expiry, and verify a new generation uses a different public key. The
new fixture is intentionally nondeterministic. Its private key is never
persisted, installed, imported as an application root or used to grant
publication rights. Neither tickets nor public SPKI are published in the report.

Generation marshals before writing and fails if the complete UTF-8 JSON plus
newline exceeds 65536 bytes. It fails on missing, failed or short output writes;
it does not truncate. Actual generation and this size check run in Actions only.
The complete race suite must report all 19 exact producer test roots: the six
original layer-wire roots, seven projection roots and six operation roots.
Skipped, failed, unknown, missing, repeated or late roots fail the source-bound
evidence gate, as does a missing successful package completion.

Actions creates the specimen with `mktemp` only under the job's `RUNNER_TEMP`,
with a scoped `SYN443_OPERATION_FIXTURE` path and restrictive file permissions.
The exit trap can remove only that owned file. The existing complete validation
still checks the whole bounded specimen, all eight originals, all 36 actual DTO
wires, byte hashes and derived job identities. The file is explicitly removed
before the public directory is scanned or uploaded; failure paths also execute
the cleanup trap. No signed specimen is placed in a public artifact directory.

The separate `layer-operation-evidence` artifact contains exactly three regular
files: `operation-wire-report.json`, `SOURCE.txt`, and `SHA256SUMS`. The closed
report has only `sourceCommit`, `producerTests` (19), `originals` (8), `outcomes`
(36), `fixtureBytes` (1..65536), `fixtureSHA256` (lowercase SHA-256),
`syntheticOnly:true`, and `specimensPublished:false`. It contains no JWT, public
SPKI, original action body or DTO wire. The source is the exact GitHub event
source used by the existing checkout policy (PR head, otherwise `github.sha`),
verified against checkout HEAD and repeated in `SOURCE.txt`.

The existing secret scanner rejected the signed synthetic specimen's JWT-shaped
strings. Distribution is therefore withheld. The normal public-data and secret
scanners now inspect the entire three-file report directory before upload, with
no exception, encoding workaround, detector change or scan exclusion. Any new
scanner failure still blocks publication. The report's fixture hash describes
the discarded specimen of that run; it does not make those bytes available.

Android cross-language conformance must instead pin an accepted public Go source
commit and regenerate its own ephemeral specimen in GitHub Actions, passing
those exact generated bytes to JVM conformance in the same invocation. That
downstream wiring is separate work. Its fresh key/signature/hash can differ from
the report, so there is no claim of an identical copied fixture artifact. The
original deterministic layer-wire and projection artifacts retain their existing
byte-for-byte consumer flow. No local generation, executable suite, build, live
client or physical test is claimed by this workflow revision.

Related source evidence: [original layer wire](layer-wire-fixture.md),
[projection conformance](layer-projection-fixture.md), and
[operation outcome reconciliation](operation-outcome-reconciliation.md).
