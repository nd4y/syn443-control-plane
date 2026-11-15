import json
import unittest
from check_adaptive_snapshot_evidence import PACKAGE, REQUIRED, verify


class SnapshotEvidenceTest(unittest.TestCase):
    def rows(self, names=REQUIRED, package=PACKAGE):
        return [json.dumps({'Package': package, 'Test': name, 'Action': action})
                for name in sorted(names) for action in ('run', 'pass')]

    def test_actual_roots_required_and_output_records_do_not_count(self):
        rows = self.rows()
        rows.append(json.dumps({'Package': PACKAGE, 'Action': 'output', 'Output': 'ordinary output'}))
        self.assertEqual(4, verify(rows))

    def test_missing_substituted_repeated_failed_skipped_or_malformed_rejected(self):
        for rows in [[], self.rows(sorted(REQUIRED)[:-1]), self.rows(package='other/package'),
                     self.rows() + self.rows(), ['null'], ['not-json']]:
            with self.assertRaises((AssertionError, ValueError)):
                verify(rows)
        for action in ('fail', 'skip'):
            with self.assertRaises(AssertionError):
                verify(self.rows() + [json.dumps({'Package': PACKAGE, 'Test': 'nested/case', 'Action': action})])
