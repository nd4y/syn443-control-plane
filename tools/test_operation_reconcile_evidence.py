import json
from pathlib import Path
import tempfile
import unittest

from check_operation_reconcile_evidence import PREFIX, REQUIRED, SOURCES, SOURCE_REQUIRED, verify, verify_source_names


class OperationReconcileEvidenceTest(unittest.TestCase):
    def rows(self, stage):
        rows = [dict(Action=action, Package=package, Test=name)
                for name, package in sorted(REQUIRED[stage].items()) for action in ('run', 'pass')]
        return rows+[dict(Action='pass', Package=package) for package in sorted(set(REQUIRED[stage].values()))]

    def run_rows(self, rows, stage):
        return verify([json.dumps(row) for row in rows], stage)

    def test_all_twenty_eight_actual_roots_need_exact_run_pass_and_one_completion(self):
        self.assertEqual({'catalog': 5, 'provisioning': 23}, {stage: len(names) for stage, names in REQUIRED.items()})
        for stage in REQUIRED:
            original = self.rows(stage)
            self.assertEqual(len(REQUIRED[stage]), self.run_rows(original, stage))
            for row in original:
                with self.assertRaises(AssertionError):
                    self.run_rows([other for other in original if other != row], stage)
                with self.assertRaises(AssertionError):
                    self.run_rows(original+[row], stage)

    def test_foreign_package_renamed_roots_and_unrelated_success_cannot_substitute(self):
        for stage in REQUIRED:
            original = self.rows(stage)
            for name, package in REQUIRED[stage].items():
                for action in ('run', 'pass'):
                    wanted = dict(Action=action, Package=package, Test=name)
                    for changed in (dict(wanted, Package=PREFIX+'foreign'), dict(wanted, Test='TestUnrelatedRoot')):
                        with self.assertRaises(AssertionError):
                            self.run_rows([changed if row == wanted else row for row in original], stage)
                    with self.assertRaises(AssertionError):
                        self.run_rows(original+[dict(wanted, Package=PREFIX+'foreign')], stage)
            with self.assertRaises(AssertionError):
                self.run_rows([row for row in original if 'Test' not in row], stage)

    def test_package_fail_skip_error_and_no_tests_never_look_like_execution(self):
        for stage in REQUIRED:
            package = next(iter(REQUIRED[stage].values()))
            for action in ('fail', 'skip', 'error'):
                for name in (None, next(iter(REQUIRED[stage])), 'TestUnrelatedInRequiredPackage'):
                    extra = dict(Action=action, Package=package)
                    if name is not None:
                        extra['Test'] = name
                    with self.assertRaises(AssertionError):
                        self.run_rows(self.rows(stage)+[extra], stage)
            with self.assertRaises(AssertionError):
                self.run_rows([], stage)
            unrelated = [dict(Action='pass', Package=PREFIX+'foreign')]
            self.assertEqual(len(REQUIRED[stage]), self.run_rows(unrelated+self.rows(stage), stage))

    def test_pass_before_run_early_completion_and_late_repeated_outcomes_fail(self):
        for stage in REQUIRED:
            original = self.rows(stage)
            swapped = original.copy();swapped[0], swapped[1] = swapped[1], swapped[0]
            package = next(iter(REQUIRED[stage].values()))
            completion = dict(Action='pass', Package=package)
            for changed in (swapped, [completion]+original,
                            [completion]+[row for row in original if row != completion],
                            original+[original[0]], original+[original[1]]):
                with self.assertRaises(AssertionError):
                    self.run_rows(changed, stage)

    def test_malformed_unbound_duplicate_and_wrong_stage_metadata_are_not_evidence(self):
        for stage in REQUIRED:
            package = next(iter(REQUIRED[stage].values()))
            invalid = ('[]', '{}', 'null', 'not JSON',
                       json.dumps(dict(Action=1, Package=package)),
                       json.dumps(dict(Action='pass', Package=[])),
                       json.dumps(dict(Action='pass', Package='')),
                       json.dumps(dict(Action='pass', Package=package, Test=None)),
                       json.dumps(dict(Action='pass', Package=package, Test=[])),
                       json.dumps(dict(Action='pass', Package=package, Test='')),
                       '{"Action":"run","Action":"pass","Package":'+json.dumps(package)+'}',
                       '{"Action":"pass","Package":'+json.dumps(package)+',"Pack\\u0061ge":'+json.dumps(package)+'}')
            for raw in invalid:
                with self.assertRaises((AssertionError, ValueError)):
                    verify([raw], stage)
            output = dict(Action='output', Package=package, Output='synthetic public output')
            self.assertEqual(len(REQUIRED[stage]), self.run_rows([output]+self.rows(stage), stage))
        with self.assertRaises(AssertionError):
            verify([], 'unknown')
        with self.assertRaises(AssertionError):
            verify_source_names(Path(__file__).resolve().parent.parent, 'unknown')

    def test_every_new_go_file_has_exact_source_names_without_missing_extra_or_duplicate(self):
        actual = Path(__file__).resolve().parent.parent
        for stage in REQUIRED:
            verify_source_names(actual, stage)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, names in SOURCE_REQUIRED.items():
                target = root/relative;target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('\n'.join(f'func {name}(t *testing.T) {{}}' for name in sorted(names)), encoding='utf-8')
            for stage in REQUIRED:
                verify_source_names(root, stage)
                for relative in SOURCES[stage]:
                    target = root/relative;original = target.read_text(encoding='utf-8')
                    for changed in (original.replace('func Test', 'func TestRenamed', 1),
                                    '\n'.join(original.splitlines()[1:]),
                                    original+'\n'+original.splitlines()[0],
                                    original+'\nfunc TestUnregisteredNewRoot(t *testing.T) {}'):
                        target.write_text(changed, encoding='utf-8')
                        with self.assertRaises(AssertionError):
                            verify_source_names(root, stage)
                    target.write_text(original, encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
