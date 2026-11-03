# Saved private draft discovery

The authenticated `configuration.layers.drafts.list` action accepts an exact
`targetKind/targetId`. It returns that scope and at most64 actor-private live
copies, each with its ID, revision and save timestamp. The response contains no
proposal body, secret, preview, approval or publication ticket. Saved metadata
does not establish that the encrypted proposal is readable or valid: opening it
still uses the existing authenticated get/decrypt/integrity path.

Fresh control-audience identity/MFA, current target read permission, the actor
binding and final authorization/expiry checks are required. A valid empty list is
distinct from unavailable storage. Results have deterministic newest-first/ID
ordering. Malformed metadata and quota contamination fail closed; rows from a
different actor, target or expired storage are excluded. No new SQL privilege is
granted, and the publisher still cannot read mutable private drafts.

The mobile-width browser panel lists copies for the current proposal's target,
or for the selected device before editing. Listing keeps unsaved text intact;
opening a selected copy is explicit and checks scope and revision again. Neither
step saves, previews or publishes. Logout and authorization withdrawal clear
the list along with the existing private editor. Browser storage is not used.

Actions adds actual SQL/HTTP scope, expiry, bounds, storage-fault and delayed
authorization cases, a separate80% inventory coverage gate and four required
browser cases (minimum28). Acceptance requires the complete exact-source matrix
and independently checked browser artifact.
All eight jobs passed at5960a071afb8863f5196663857e1204aaffcb8d3
(run41612379303); independent archive SHA/CRC/XML verification found all28
required browser cases with no errors, failures or skips.

## Explicit discard

`configuration.layers.draft.discard` requires the exact saved ID/revision/target,
current actor-scoped write permission and fresh administrative assurance. The
transaction serializes against saves and repeats authority after waits. It replaces
the encrypted proposal with an encrypted minimal receipt and a30day tombstone.
The ID cannot be reused during that interval. A prior save request cannot return
its obsolete content after discard. Existing encrypted operation receipts retain
their maximum24h lifetime. Tombstones do not consume the64 live-copy allowance;
the existing256-per24h operation bound also bounds tombstone accumulation.

Lost discard replies retry the same operation/body. A changed body or version
conflicts. SQL prevents reversing or editing a committed tombstone. Expiry does
not become publication, and even the largest valid draft revision can be discarded.
No approved preview, configuration head, assignment or active VPN changes.

The responsive editor requires explicit confirmation, retains unsaved text and
checks the exact receipt before clearing saved-copy state. An uncertain discard
cannot be abandoned as if it were known not to have happened. Creating a new copy
requires a new ID. Logout or loss of authority still clears private editor state.
Actions adds actual PostgreSQL CAS/replay/rights/expiry/quota/concurrency and
receipt-integrity checks, an independent80% discard gate and three required
browser scenarios (minimum31). Broader application/mobile administration remains
open. All eight jobs passed at4561f62ad259aacbc73c6fe81130cbb31edfd5d3
([Actions41621330379](https://github.com/nd4y/syn443-control-plane/actions/runs/41621330379)).
Independent archive SHA/CRC/XML verification found all31 required browser cases
without errors, failures or skips; the independent discard coverage was88.6%.
This accepts the bounded SQL/HTTP/browser component, not a physical mobile editor
or the complete administration milestone.
