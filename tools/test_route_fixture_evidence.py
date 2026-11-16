import json
import unittest
from check_route_fixture_evidence import PACKAGE, REQUIRED, verify

class RouteFixtureEvidenceTest(unittest.TestCase):
    def rows(self):
        return [dict(Action=a, Package=PACKAGE, Test=n) for n in sorted(REQUIRED) for a in ('run', 'pass')] + [dict(Action='pass', Package=PACKAGE)]
    def run_rows(self, rows): return verify([json.dumps(r) for r in rows])
    def test_every_actual_fixture_case_and_completion_are_required(self):
        self.assertEqual(17, self.run_rows(self.rows()))
    def test_missing_repeated_skipped_failed_or_foreign_case_cannot_pass(self):
        rows=self.rows()
        variants=[rows[1:],rows[:-1],rows+[rows[0]],rows+[rows[-1]],
            [dict(r, Action='skip') if i==1 else r for i,r in enumerate(rows)],
            rows+[dict(Action='fail', Package=PACKAGE)],
            [dict(r, Package='foreign/package') if i==0 else r for i,r in enumerate(rows)]]
        for bad in variants:
            with self.assertRaises(AssertionError): self.run_rows(bad)
    def test_invalid_metadata_is_not_counted(self):
        for bad in ('[]','{}','null',json.dumps(dict(Action='pass',Package=PACKAGE,Test=[]))):
            with self.assertRaises(AssertionError):verify([bad])
