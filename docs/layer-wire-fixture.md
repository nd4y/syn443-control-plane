# Public Go to Kotlin global-layer byte fixture

`cmd/layer-fixture` generates a deterministic synthetic interoperability document
only when `GITHUB_ACTIONS=true`. It reads no input document or private environment,
creates no key, opens no database or network connection, and has no publication
authority. Its output is bounded to 32768 bytes, including the final newline;
each stored layer and effective document is bounded to 8192 bytes.

The authoritative global-layer hash is lowercase hexadecimal SHA-256 of the
exact bytes returned by `json.Marshal(configuration.Layer)`. This is the actual
`deviceprovisioning.configurationHash` representation used by
`resolveConfigurationLayers`, not the base64url `identity.Hash` representation
used by other protocols. A source-bound Go AST test pins both the private hash
formula in `layer_store.go` and its `json.Marshal(layer)`/body/hash call site in
`layer_catalog.go`. It fails if that production relationship changes.

`Change.Value` is `json.RawMessage`. Go Marshal compacts insignificant whitespace
and applies Go JSON HTML escaping while retaining nested object order, numeric
spellings and existing string escape spellings. Decoding the whole layer to a
generic map and then encoding it again changes the authoritative byte string.
Kotlin consumers must preserve an unchanged layer's exact `layerWire` and verify
its `globalLayerHash`; an effective merged document is not a substitute.

The JSON format is:

```text
{
  schemaVersion: 1,
  hashAlgorithm: "sha256-lowercase-hex",
  layers: [{name, layerWire, globalLayerHash, knownFieldPaths}],
  scenarios: [{name, layerNames, unchangedParents, editedLayers,
               effectiveWire, knownFieldPaths}]
}
```

`layerWire` and `effectiveWire` are JSON strings containing the original Go JSON
bytes, not nested objects to reconstruct. Hashes cover decoded UTF-8 `layerWire`
bytes, without the outer string quotes or a trailing newline. `name` and the
scenario references are fixed synthetic labels. The five layer samples are
`template-parent`, `device-before`, `device-after`, `local-before`, `local-after`.
Device and local samples use the same synthetic device ID and separate kinds;
their before/after revision advances from1 to2. The four scenarios are
`before-device-edit`, `after-device-edit`, `before-local-edit`, `after-local-edit`.
They explicitly identify byte-preserved parents and edited layers.

The parent includes unsorted nested objects, `1.00`, `1e0`, a finite fractional
number, an escaped ASCII character, input whitespace, HTML characters, UTF-8 and
U+2028/U+2029. These are valid layer values. Device overrides supply actual
integer schema/timeout values and a supported DNS strategy before final settings
validation. Leaving the fractional timeout unoverridden is explicitly rejected.
Every scenario uses real `configuration.Merge`, `DecodeNetworkPlan` and
`CompileNetworkPlan`. The final graph is direct-only; any profile resolution
attempt fails generation. This is compiler evidence and sends no traffic.

The known scalar paths are `/activation/timeoutSeconds`, `/graph/final`,
`/network/dnsFinal`, `/network/dnsStrategy`. A layer lists only those paths
represented by its changes, including nested object changes. A scenario lists
all four effective paths. The device edit changes the DNS strategy; the local
edit changes the timeout. These fixture paths do not grant editing rights.

The existing complete Actions race suite retains six exact wire fixture methods;
the separate [projection fixture](layer-projection-fixture.md) adds seven more.
The generation step requires all thirteen actual run/pass outcomes and one
successful package completion, rejecting skips, failures, duplicates, renamed
roots and missing outcomes. Only then does Actions generate
`dist/layer-wire/fixture.json`, record exact checkout `SOURCE.txt`, and hash both
files into `SHA256SUMS`. Public-data and secret scanners must pass before the
separate `layer-wire-evidence` artifact is uploaded. Existing bootstrap evidence
and runtime artifacts are unchanged.

The generated artifact must be taken from a fully accepted Actions run and copied
byte-for-byte into the Android test resources with its provenance. This source
change has not been built, tested or generated locally. It does not establish
an installed Android editor, server ACL/MFA access, publication, live device
configuration, or physical acceptance. No API, schema, contract lock, key or SQL
role changes are part of this fixture.
