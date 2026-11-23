# NekoBox pilot migration

1. Keep a private checkpoint of the current app and its complete configuration.
   Store the restorable export inside access-controlled storage. It can contain
   subscription credentials, private network identifiers and access keys.
2. Create a separate redacted full export for planning. On the workstation with
   the device already authorized, use the existing NekoBox tools.
   
   ```sh
   python tools/nekoctl/nekoctl.py --output export-review.json export --full
   ```
3. From the SYN443 Control Plane checkout, review the local export.
   
   ```sh
   python tools/nekobox_migration_preview.py /private/export-review.json
   ```

The preview counts subscription groups, supported protocol families including
VLESS xHTTP, selector groups, chain links, rule actions and special settings.
Check missing references first. Review NekoBox direct rules and assign intended
SYN443 RU, NON_RU and INTERNAL routes explicitly. Recreate subscriptions
as individually authorized Control Plane sources. Reissue NetBird access for
the SYN443 device and verify private DNS and home-network proof on the device.

The command reads exactly one local file or stdin and returns aggregate counts.
It requires no connection to a phone, the network or a server. The operator
still needs a separate enrollment, live route checks and a rollback decision.
Keep the previous client and its private checkpoint available during the pilot.
