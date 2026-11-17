import json
from pathlib import Path
import tempfile
import unittest

from check_session_boundary_evidence import PACKAGE, REQUIRED, SOURCE, verify, verify_source_names


class SessionBoundaryEvidenceTest(unittest.TestCase):
    def rows(self):
        return [dict(Action=action, Package=PACKAGE, Test=name)
                for name in sorted(REQUIRED) for action in ('run', 'pass')] + [dict(Action='pass', Package=PACKAGE)]

    def run_rows(self, rows):
        return verify([json.dumps(row) for row in rows])

    def test_all_six_exact_roots_need_run_pass_and_one_complete_enrollment_package(self):
        self.assertEqual(6, self.run_rows(self.rows()))
        for name in REQUIRED:
            for action in ('run', 'pass'):
                event = dict(Action=action, Package=PACKAGE, Test=name)
                with self.subTest(name=name, action=action), self.assertRaises(AssertionError):
                    self.run_rows([row for row in self.rows() if row != event])
        completion = dict(Action='pass', Package=PACKAGE)
        for rows in ([], [completion], self.rows()[:-1], self.rows()+[completion], [completion]+self.rows()[:-1]):
            with self.assertRaises(AssertionError):
                self.run_rows(rows)

    def test_foreign_package_subtest_failure_skip_and_error_cannot_establish_acceptance(self):
        for name in REQUIRED:
            for action in ('run', 'pass'):
                replaced = [dict(row, Package=PACKAGE+'/foreign')
                            if row == dict(Action=action, Package=PACKAGE, Test=name) else row
                            for row in self.rows()]
                with self.assertRaises(AssertionError):
                    self.run_rows(replaced)
        for package in (PACKAGE, 'github.com/nd4y/syn443-control-plane/internal/supportchat'):
            for action in ('fail', 'skip', 'error', 'build-fail'):
                for name in (None, sorted(REQUIRED)[0], sorted(REQUIRED)[0]+'/late_boundary', 'TestExistingEnrollmentCase'):
                    event = dict(Action=action, Package=package)
                    if name is not None:
                        event['Test'] = name
                    with self.assertRaises(AssertionError):
                        self.run_rows(self.rows()+[event])
        with self.assertRaises(AssertionError):
            self.run_rows(self.rows()+[dict(Action='output', Package=PACKAGE, Error='synthetic fixture error')])

    def test_repeated_reversed_late_and_unregistered_roots_never_replace_actual_execution(self):
        for name in REQUIRED:
            for action in ('run', 'pass'):
                event = dict(Action=action, Package=PACKAGE, Test=name)
                for rows in (self.rows()[:-1]+[event]+self.rows()[-1:], self.rows()+[event]):
                    with self.assertRaises(AssertionError):
                        self.run_rows(rows)
            reversed_root = [dict(row, Action='pass' if row['Action'] == 'run' else 'run')
                             if row.get('Test') == name else row for row in self.rows()]
            with self.assertRaises(AssertionError):
                self.run_rows(reversed_root)
        with self.assertRaises(AssertionError):
            self.run_rows(self.rows()+[dict(Action='run', Package=PACKAGE, Test='TestRefreshBoundaryUnregistered')])
        name = sorted(REQUIRED)[0]
        harmless = [dict(Action='output', Package=PACKAGE, Output='synthetic public output'),
                    dict(Action='run', Package=PACKAGE, Test=name+'/remaining_1_seconds'),
                    dict(Action='pass', Package=PACKAGE, Test=name+'/remaining_1_seconds')]
        self.assertEqual(6, self.run_rows(harmless+self.rows()))

    def test_malformed_duplicate_unbound_and_non_json_metadata_is_rejected(self):
        for raw in ('[]', 'null', '{}', 'not JSON',
                    '{"Action":"run","Action":"pass","Package":"synthetic"}',
                    '{"Action":"output","Package":"synthetic","Elapsed":NaN}',
                    json.dumps(dict(Action=1, Package=PACKAGE)),
                    json.dumps(dict(Action='pass', Package=[])),
                    json.dumps(dict(Action='pass', Package=PACKAGE, Test=None)),
                    json.dumps(dict(Action='pass', Package=PACKAGE, Test=[])),
                    json.dumps(dict(Action='pass', Package=PACKAGE, Test=''))):
            with self.assertRaises((AssertionError, ValueError)):
                verify([raw])

    def test_actual_postgres_source_names_cannot_be_missing_renamed_duplicated_or_added(self):
        verify_source_names(Path(__file__).resolve().parent.parent)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/SOURCE
            target.parent.mkdir(parents=True)
            original = '//go:build postgres\n\npackage enrollment\n\n' + '\n'.join(
                f'func {name}(t *testing.T) {{}}' for name in sorted(REQUIRED))
            target.write_text(original, encoding='utf-8')
            verify_source_names(root)
            first = sorted(REQUIRED)[0]
            for changed in (original.replace(first, 'TestRenamedBoundary', 1),
                            original.replace(f'func {first}(t *testing.T) {{}}', '', 1),
                            original+f'\nfunc {first}(t *testing.T) {{}}',
                            original+'\nfunc TestRefreshBoundaryAdded(t *testing.T) {}',
                            original.replace('package enrollment', 'package foreign'),
                            original.replace('//go:build postgres', '//go:build unrelated')):
                target.write_text(changed, encoding='utf-8')
                with self.assertRaises(AssertionError):
                    verify_source_names(root)


if __name__ == '__main__':
    unittest.main()
