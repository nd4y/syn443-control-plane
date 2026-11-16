import unittest
from check_adaptive_runtime_evidence import REQUIRED, verify
import json

class AdaptiveEvidenceTest(unittest.TestCase):
    def rows(self,stage):
        rows=[]
        for name,package in REQUIRED[stage].items():
            rows += [dict(Action=a,Package=package,Test=name)for a in ('run','pass')]
        rows += [dict(Action='pass',Package=p)for p in set(REQUIRED[stage].values())]
        return rows
    def check(self,rows,stage):return verify([json.dumps(r)for r in rows],stage)
    def test_all_stages_require_every_actual_package_bound_outcome(self):
        for stage in REQUIRED:self.assertEqual(len(REQUIRED[stage]),self.check(self.rows(stage),stage))
    def test_missing_skipped_duplicate_or_foreign_cases_cannot_be_green(self):
        for stage in REQUIRED:
            original=self.rows(stage)
            for rows in (original[1:],original+[original[0]],
                [dict(r,Action='skip')if i==1 else r for i,r in enumerate(original)],
                [dict(r,Package='foreign/package')if i==0 else r for i,r in enumerate(original)]):
                with self.assertRaises(AssertionError):self.check(rows,stage)
    def test_package_failure_or_missing_completion_cannot_be_green(self):
        for stage in REQUIRED:
            rows=self.rows(stage)
            for bad in (rows[:-1],rows+[dict(Action='fail',Package=next(iter(REQUIRED[stage].values())))]):
                with self.assertRaises(AssertionError):self.check(bad,stage)
