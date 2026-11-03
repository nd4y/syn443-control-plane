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
browser cases (minimum28). The implementation remains unaccepted until the
complete exact-source matrix and independently checked browser artifact pass.
Explicit server-side discard and broader application/mobile administration
remain separate M3 work.
