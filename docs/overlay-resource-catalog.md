# Encrypted NetBird resource history

The overlay worker can resolve an exact immutable `resourceId/revision` from
SQL instead of receiving all provider PATs in its bootstrap file. This is a
separate catalog from provider subscriptions: source workers, the control API,
identity API and identity publisher cannot read its ciphertext. A separate
32-byte encryption key is required, distinct by decoded bytes from the broker
identity/credential encryption key. Default diagnostics redact both objects.

Owner migration/roles install `identity_overlay_resource_versions`. Runtime
processes do not migrate. Only the isolated overlay worker receives SELECT;
its startup and resolution checks reject owner credentials, role membership,
identity/session access and additional resource mutation/TRUNCATE privileges.
Each encrypted body binds resource ID and revision as AEAD associated data and
has an independent body hash. Unknown, unreadable or mismatched versions fail
closed. Decryption repeats the existing provider-origin, account, network,
group, CA and allowed-egress validation.

The owner runs `enrollment-admin overlay-resource-put`, with the ordinary owner
`SYN443_ENROLLMENT_CONFIG` and a private0600 `SYN443_OVERLAY_RESOURCE` file:

```json
{
  "encryptionKey": "<separate canonical base64 key for 32 random bytes>",
  "previousRevision": 0,
  "resource": {
    "resourceId": "netbird-cloud",
    "revision": 1,
    "accountId": "<approved account ID>",
    "apiOrigin": "https://api.netbird.io",
    "managementOrigin": "https://api.netbird.io",
    "networkId": "<approved network ID>",
    "groups": ["<approved group ID>"],
    "token": "<private management PAT>"
  }
}
```

This example is a shape, not a usable configuration or credential. Input is
bounded and closed; the CLI emits no resource/PAT body. Initial revision is1;
later inserts require the exact previous highest revision. An identical retry
of an existing version succeeds, including after later versions were inserted.
Changing that version or skipping the head conflicts. SQL rejects updates and
deletes, including no-op updates. The CLI requires the table-owning session.

In the worker's private configuration set `resourceCatalog:true`, omit
`resources`, and supply `resourceEncryptionKey`. Database and the existing
broker `encryptionKey` remain required. Inline resources and SQL mode cannot be
combined. The legacy owner-file resolver remains available for migration.

Existing immutable broker scopes already pin resource revision. New owner
assignments can select a new version; outstanding operations retain the prior
version for inspection, compensation and verified peer/key retirement. Merely
inserting a new resource does not create a Cloud key, alter a group, assign a
policy, revoke a PAT or switch an existing device. Keep prior management access
usable until its operations are retired; the catalog does not rotate external
Cloud tokens itself. Historical resource credentials are retained at this stage.

SQL tests add immutable revision/CAS/replay, old-version resolution after a
replacement, ciphertext, wrong key/scope, restricted roles, cancellation and
destructive privilege contamination. Runtime parsing tests include equivalent
base64 spellings of the same forbidden shared key. New source is pending Actions
acceptance. Authenticated web/mobile resource editing, audited retirement and
bounded secret retention, plus actual Cloud integration through this SQL path,
remain required work; this component does not complete M2/M3.
