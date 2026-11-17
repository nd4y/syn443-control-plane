import json
import unittest
from summarize_secret_findings import summarize


class SecretFindingsSummaryTest(unittest.TestCase):
    def test_private_values_paths_and_context_never_reach_diagnostic_output(self):
        secret = 'SYNTHETIC_DO_NOT_ECHO_VALUE'
        rows = [{'RuleID': 'generic-api-key', 'Match': 'keyThumbprint: "' + secret + '"',
                 'Secret': secret, 'File': '/private/' + secret, 'Line': secret},
                {'RuleID': 'jwt', 'Match': secret, 'Secret': secret}]
        result = summarize(rows)
        self.assertEqual([{'rule': 'generic-api-key', 'knownFieldHint': 'keyThumbprint', 'count': 1},
                          {'rule': 'jwt', 'knownFieldHint': 'unclassified', 'count': 1}], result)
        encoded = json.dumps(result)
        for value in (secret, '/private/', 'Secret', 'Match', 'Line'):
            self.assertNotIn(value, encoded)

    def test_rule_and_shape_bounds_do_not_echo_untrusted_finding_metadata(self):
        secret = 'SYNTHETIC_PRIVATE_METADATA'
        self.assertEqual([{'rule': 'invalid-rule', 'knownFieldHint': 'unclassified', 'count': 2}],
                         summarize([{'RuleID': secret, 'Match': secret}, {'RuleID': 'a' * 65, 'Match': {secret: secret}}]))
        for value in ({secret: secret}, [None], [{}] * 10001):
            with self.assertRaises(AssertionError):
                summarize(value)
