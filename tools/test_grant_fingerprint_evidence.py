import json
from pathlib import Path
import tempfile
import unittest

from check_grant_fingerprint_evidence import PACKAGE, REQUIRED, SOURCE, verify, verify_source_names


class GrantFingerprintEvidenceTest(unittest.TestCase):
    def rows(self):
        return [dict(Action=action, Package=PACKAGE, Test=name)
                for name in sorted(REQUIRED) for action in ('run', 'pass')] + [dict(Action='pass', Package=PACKAGE)]

    def run_rows(self, rows):
        return verify([json.dumps(row) for row in rows])

    def test_all_six_native_roots_require_run_pass_and_one_complete_cli_package(self):
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

    def test_wrong_package_and_any_cli_failure_skip_or_error_cannot_substitute_for_execution(self):
        for name in REQUIRED:
            for action in ('run', 'pass'):
                rows = [dict(row, Package=PACKAGE+'/foreign')
                        if row == dict(Action=action, Package=PACKAGE, Test=name) else row for row in self.rows()]
                with self.assertRaises(AssertionError):
                    self.run_rows(rows)
        for action in ('fail', 'skip', 'error', 'build-fail'):
            for name in (None, sorted(REQUIRED)[0], sorted(REQUIRED)[0]+'/boundary', 'TestInstallationProfile'):
                event = dict(Action=action, Package=PACKAGE)
                if name is not None:
                    event['Test'] = name
                with self.assertRaises(AssertionError):
                    self.run_rows(self.rows()+[event])
        with self.assertRaises(AssertionError):
            self.run_rows(self.rows()+[dict(Action='output', Package=PACKAGE, Error='synthetic fixture error')])

    def test_repeated_reversed_late_or_unregistered_roots_never_count_as_a_valid_run(self):
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
            self.run_rows(self.rows()+[dict(Action='run', Package=PACKAGE, Test='TestGrantFingerprintUnregistered')])
        output = dict(Action='output', Package=PACKAGE, Output='synthetic public output')
        self.assertEqual(6, self.run_rows([output]+self.rows()))

    def test_invalid_duplicate_non_json_and_unbound_metadata_are_not_test_evidence(self):
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

    def test_source_names_cannot_be_missing_renamed_duplicated_added_or_move_package(self):
        verify_source_names(Path(__file__).resolve().parent.parent)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/SOURCE
            target.parent.mkdir(parents=True)
            original = 'package main\n\n'+'\n'.join(f'func {name}(t *testing.T) {{}}' for name in sorted(REQUIRED))
            target.write_text(original, encoding='utf-8')
            verify_source_names(root)
            first = sorted(REQUIRED)[0]
            for changed in (original.replace(first, 'TestRenamedFingerprint', 1),
                            original.replace(f'func {first}(t *testing.T) {{}}', '', 1),
                            original+f'\nfunc {first}(t *testing.T) {{}}',
                            original+'\nfunc TestGrantFingerprintAdded(t *testing.T) {}',
                            original.replace('package main', 'package foreign')):
                target.write_text(changed, encoding='utf-8')
                with self.assertRaises(AssertionError):
                    verify_source_names(root)


if __name__ == '__main__':
    unittest.main()
