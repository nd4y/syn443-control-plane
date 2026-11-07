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
Changing that version or skipping the head conflicts. SQL rejects arbitrary
updates and deletes. The CLI requires the table-owning session.

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
Cloud tokens itself.

## Retire a superseded credential

The owner can run `enrollment-admin overlay-resource-retire` with the same
owner connection and a private `SYN443_OVERLAY_RESOURCE` document containing
`resourceId`, `revision` and `expectedHeadRevision`. The expected head must be
a newer revision. For example, `{"resourceId":"example-overlay","revision":1,"expectedHeadRevision":2}`
addresses revision 1 after revision 2 has been imported. This operation requires
the updated owner schema and no provider token in its input.

The transaction checks the exact current head and refuses erasure while any
broker operation still pins the old version. The broker must reach its terminal
`retired` state with its credential removed. An uncertain, blocked, established
or merely key-cleared operation still pins the version. A database fence orders
new reservations against retirement. An earlier reservation prevents erasure,
and a later reservation of the retired revision fails before its transaction
can commit. Neither the publisher nor API can read the credential catalog.

Retirement removes the ciphertext from the current row and retains its resource
ID, revision, hash and creation and retirement timestamps. A repeated retirement
of the same version returns its existing outcome. Importing that revision again
cannot revive it. If a retired version is needed later, import a new authorized
version and publish its scope through the normal workflow. PostgreSQL storage
history, WAL and backups follow their own retention policy. This operation also
leaves the provider's external PAT lifecycle with the operator.

The PostgreSQL checks cover owner-only execution, current-head protection,
pending pin protection, terminal retirement, preserved audit metadata, rejected
reimport, stale new reservations and the shared lock held by the publisher.
Scheduling retirement and granting it through the administration API remain
separate requirements.

SQL tests add immutable revision/CAS/replay, old-version resolution after a
replacement, ciphertext, wrong key/scope, restricted roles, cancellation and
destructive privilege contamination. Runtime parsing tests include equivalent
base64 spellings of the same forbidden shared key. Source5e816cc9e65548b68b6e1d3c1166b01c6212c2e7 passed all8 mandatory jobs in
[Actions41562534053](https://github.com/nd4y/syn443-control-plane/actions/runs/41562534053). Authenticated web/mobile resource editing, audited retirement and
bounded secret retention and complete Cloud data-plane acceptance remain required
work; this component does not complete M2/M3.

A bounded physical test with server source4f1adc26f42420ea54a5a91ccc9e7b4ccfd03fd1
and Android v35 exercised actual Cloud registration through this SQL path. The
owner imported one encrypted resource version; the worker had no inline PAT.
The signed invitation/policy flow reached direct management and signal. After
the peer diagnostic failed to report a fresh terminal result within its deadline,
the test stopped and logged out. Automatic retirement deleted the one used key
and enrolled peer using durable native evidence; independent provider HTTP404 and
complete pre/post inventory comparisons passed. Original phone configuration,
SDK identities, settings and temporary forwards were restored. Required internal
peer reachability remains unverified; this observation does not establish a
successful tunnel-health or full M2/M3 gate.
