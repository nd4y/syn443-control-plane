# Public actual-Go layer projection conformance

`cmd/layer-fixture --projection` is a separate, deterministic synthetic producer
restricted to `GITHUB_ACTIONS=true`. It accepts no input file, document, key,
account, database or network address. The default producer and CP55
`layer-wire-evidence/fixture.json` format/bytes remain unchanged. The new output
is compact UTF-8 JSON, at most 65536 bytes including its final newline.

The additional `layer-projection-evidence` artifact contains only
`projection-fixture.json`, `SOURCE.txt` and `SHA256SUMS`. The existing six source
bound wire roots and seven projection roots must each have one actual run/pass,
one successful package completion, and no fail/skip/duplicate/unknown outcome
before generation. Public-data and secret scanners run before upload. The
original wire artifact remains a separate three-file payload.

## Consumer ABI

```text
{
  schemaVersion: 1,
  hashAlgorithm: "sha256-lowercase-hex",
  layers: [{name, layerWire, globalLayerHash}],
  projections: [{name, layerNames, expectedCode, effectiveWire}],
  rebases: [{name, baseLayerNames, localLayerNames, remoteLayerNames,
             chosenLayerNames, resolution, expectedCode, effectiveWire}],
  bounds: [{name, generator, groups, leavesPerGroup, extraLeaves,
            globalLayerHash, expectedCode, expectedFieldCount}]
}
```

References name entries of the single layer catalogue. `layerWire` is a JSON
string containing exact `json.Marshal(configuration.Layer)` bytes. Its hash is
the same lowercase hexadecimal SHA-256 used by the actual private publisher
call site, already protected by the original source-bound hash test. Raw layer
number spellings, string escapes and object order are not reconstructed by a
generic JSON encoder. All device/local layers identify `synthetic-device`;
templates identify `projection-template`. Other identifiers are synthetic.

For projection cases, the producer calls real `configuration.DecodeLayers` and
`configuration.Merge`. `effectiveWire` is the exact `json.Marshal(Effective)`
string containing all three fields: `document`, `fields` and `restrictions`.
It is empty on error. The only expected codes are `ok`,
`configuration_invalid`, `configuration_field_locked` and
`configuration_conflict`. The generic Merge callback accepts portable settings;
these `/app` examples are not typed VPN configurations or compilation results.

The 41 projections cover input ordering, provenance, shared nested siblings,
scalar/object/array replacement, empty-container leaves, ordered atomic arrays,
null rejection, deletion and missing deletion, absent own changes (INHERIT),
overlapping paths, raw decimal/escaped-string values, U+2028/U+2029/HTML escaping,
same-priority group claims/conflicts/ancestor overlap, explicit priorities,
locked/range/choice restrictions, permission-only narrowing and local permission
enforcement. Go's choice/group signatures preserve numeric lexemes: `1.00` and
`1` are not interchangeable there; fractional-looking numbers also fail an
integer range. This is distinct from mathematical decimal equality when
comparing three-way editing intent.

## Declared own-layer rebase expectations

The 11 rebase records are explicit synthetic expectations for choosing own
changes. There is no existing production Go three-way rebase library, and this
producer does not invent that claim. Base, local and remote snapshots are each
checked by actual Go Merge. A `merged` record supplies the declared chosen
layers; their effective output/error is then produced by actual Go Merge. A
`conflict` record deliberately supplies no chosen layer or effective document.

The examples specify disjoint own edits with a separately changed current
parent, competing values, equal numeric or escaped-string intent preserving
current raw layers, DELETE versus INHERIT, atomic array order, and current
locked/range/choice permissions. `resolution=merged` describes the own-change
selection only: `expectedCode=configuration_field_locked` still prevents it
from becoming an admissible configuration. Neither this file nor a successful
comparison is a role, MFA approval, preview ticket or publication authority.

## Generated leaf boundary

Large inputs are not included as raw layer/effective documents. The two bounded
summaries use `generator=leaf-grid-v1`, `groups=64`, `leavesPerGroup=64`, with
`extraLeaves=0` or `1`. Construct a template layer with ID
`projection-template`, priority 0, revision 1, empty permissions and one SET at
`/grid`. Its value is an object whose keys `g00` through `g63` each contain
`v00` through `v63` with integer values 0 through 63. For the second case add
`extra:1` directly inside that grid object. Use actual Go struct Marshal for
the reported input-layer hash.

The producer calls the real 4096-leaf boundary and requires success, then requires
rejection of 4097 leaves with `configuration_invalid`; expected field counts
are 4096 and 0. Their actual execution remains a mandatory Actions gate.
Only those generator parameters, input hash and actual outcome are exported,
keeping the artifact small. An independently reconstructed consumer input can
exercise its own identical bounds without importing a large fixture payload.

Only source editing and gofmt were performed locally. Actual fixture generation,
unit/race outcomes, privacy scans and artifact acceptance remain pending Actions.
No API, public schema/lock, SQL, credential, account, device or publication state
changes belong to this slice. Android UI, conflict-resolution UX, real admin
rights and physical delivery remain separate acceptance gates.
