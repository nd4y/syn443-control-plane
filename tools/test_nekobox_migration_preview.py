import json
from pathlib import Path
import subprocess
import sys
import unittest

import nekobox_migration_preview as migration


def export_fixture():
    def profile(id, protocol, values, group=11):
        return {"id": id, "groupId": group, "userOrder": 0, "protocol": protocol, "values": values}
    def rule(id, target, **values):
        return {"id": id, "outbound": target, "enabled": True, **values}
    return {"schema": "nekobox.full-config", "schemaVersion": 1, "revision": "private-revision",
            "config": {
                "groups": [
                    {"id": 11, "type": 1, "subscription": {"link": "https://feeds.example.invalid/private"}},
                    {"id": 12, "type": 1, "isSelector": True, "frontProxy": 21, "landingProxy": 999},
                    {"id": 13, "type": 0}],
                "profiles": [
                    profile(21, "vless", {"type": "xhttp", "serverAddress": "egress.example.invalid"}),
                    profile(22, "vless", {"type": "tcp"}),
                    profile(23, "chain", {"proxies": [21, 999, 22]}),
                    profile(24, "netbird", {"setupKey": "synthetic-confidential-marker"}),
                    profile(25, "future_provider", {}, 99),
                    profile(26, "proxyset", {}),
                    profile(27, "http", {"password": "synthetic-confidential-marker"}),
                    profile(28, "socks", {}),
                    profile(29, "ssh", {})],
                "rules": [
                    rule(31, 0), rule(32, -1, wifiSsid="private-network", wifiBssid="private-bssid"),
                    rule(33, -2, ruleset="private-rule-set"), rule(34, 21, packages=["private-app"]),
                    rule(35, 999, config="private-custom-rule"), rule(36, -50),
                    {"id": 37, "outbound": 11, "enabled": False, "ruleset": "disabled-only"}],
                "preferences": {"secret-preference-name": {"type": "string", "value": "synthetic-confidential-marker"}},
                "selectedProfile": 21}}


class MigrationPreviewTest(unittest.TestCase):
    def command(self, payload):
        return subprocess.run([sys.executable, str(Path(migration.__file__)), "-"], input=payload,
                              capture_output=True, check=False)

    def test_full_export_covers_profiles_subscriptions_and_route_destinations(self):
        report = migration.preview(json.dumps(export_fixture()).encode())
        self.assertEqual(report["status"], "review_required")
        self.assertEqual(report["groups"], {"total": 3, "subscription_groups": 2, "missing_subscription_details": 1,
            "selector_groups": 1, "group_proxy_links": 2, "missing_group_proxy_links": 1, "profiles_without_group": 1})
        self.assertEqual(report["profiles"]["by_kind"], dict.fromkeys(migration.PROFILES, 1))
        self.assertEqual(report["profiles"]["missing_chain_hops"], 1)
        self.assertTrue(report["profiles"]["active_profile_present"])
        self.assertEqual(report["rules"]["by_destination"], dict.fromkeys(migration.DESTINATIONS, 1))
        self.assertEqual(report["rules"]["enabled_with_features"], {"wifi_identity": 1, "rule_set": 1, "custom_rule": 1, "application": 1})
        self.assertEqual(report["rules"]["enabled"], 6)
        self.assertEqual(report["rules"]["disabled"], 1)
        self.assertEqual(report["preferences_require_review"], 1)

    def test_cli_never_prints_input_values_and_accepts_redacted_export(self):
        payload = json.dumps(export_fixture()).encode()
        first = self.command(payload)
        redacted = self.command(payload.replace(b"synthetic-confidential-marker", b"<redacted>"))
        self.assertEqual(first.returncode, 0)
        self.assertEqual((first.stdout, first.stderr), (redacted.stdout, redacted.stderr))
        self.assertFalse(first.stderr)
        for raw_value in (b"feeds.example.invalid", b"egress.example.invalid", b"private-", b"future_provider",
                          b"synthetic-confidential-marker", b"secret-preference-name"):
            self.assertNotIn(raw_value, first.stdout)

    def test_invalid_and_oversized_inputs_fail_with_only_fixed_text(self):
        duplicate = b'{"schema":"private-marker","schema":"nekobox.full-config"}'
        bad_schema = json.dumps({**export_fixture(), "schemaVersion": True}).encode()
        duplicate_profile = export_fixture()
        duplicate_profile["config"]["profiles"].append(duplicate_profile["config"]["profiles"][0])
        for payload in (duplicate, bad_schema, b'"private-marker"', bytes([255]),
                        json.dumps(duplicate_profile).encode(), b" " * (migration.MAX_EXPORT_BYTES + 1)):
            with self.subTest(size=len(payload)):
                result = self.command(payload)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(result.stdout)
                self.assertEqual(result.stderr.splitlines(), [b"Expected a bounded nekoctl full export, schema version 1."])


if __name__ == "__main__":
    unittest.main()
