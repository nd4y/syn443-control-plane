import json
from pathlib import Path
import re
import unittest

from check_enrollment_queue_evidence import PACKAGE, REQUIRED, verify


class EnrollmentQueueEvidenceTest(unittest.TestCase):
    def rows(self):
        return [dict(Action=action, Package=PACKAGE, Test=name)
                for name in sorted(REQUIRED) for action in ('run', 'pass')] + [dict(Action='pass', Package=PACKAGE)]

    def run_rows(self, rows):
        return verify([json.dumps(row) for row in rows])

    def test_all_actual_roots_and_package_completion_are_mandatory(self):
        self.assertEqual(8, self.run_rows(self.rows()))
        rows = self.rows()
        for bad in (rows[1:], rows[:-1], rows+[rows[0]], rows+[rows[-1]],
                    [dict(row, Action='skip') if i == 1 else row for i, row in enumerate(rows)],
                    rows+[dict(Action='fail', Package=PACKAGE)],
                    [dict(row, Package='foreign/package') if i == 0 else row for i, row in enumerate(rows)]):
            with self.assertRaises(AssertionError):
                self.run_rows(bad)

    def test_invalid_or_unbound_metadata_cannot_substitute_for_execution(self):
        for bad in ('[]', '{}', 'null', json.dumps(dict(Action='pass', Package=PACKAGE, Test=[]))):
            with self.assertRaises(AssertionError):
                verify([bad])

    def test_required_roots_cover_every_new_go_queue_mode_case(self):
        root = Path(__file__).resolve().parent.parent
        source = (root/'cmd/enrollment-worker/configuration_startup_test.go').read_text()
        actual = re.findall(r'^func (TestConfigurationQueue\w+)\(t \*testing\.T\)', source, re.M)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(REQUIRED, set(actual))
