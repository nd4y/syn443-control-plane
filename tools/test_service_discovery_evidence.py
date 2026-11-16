import json
from pathlib import Path
import tempfile
import unittest

from check_service_discovery_evidence import PREFIX, REQUIRED, SOURCES, verify, verify_source_names


class ServiceDiscoveryEvidenceTest(unittest.TestCase):
    def rows(self):
        result = []
        for package, names in REQUIRED.items():
            result += [dict(Action=action, Package=package, Test=name)
                       for name in sorted(names) for action in ('run', 'pass')]
            result.append(dict(Action='pass', Package=package))
        return result

    def run_rows(self, rows):
        return verify([json.dumps(row) for row in rows])

    def test_all_seven_actual_roots_and_both_package_completions_are_mandatory(self):
        self.assertEqual(7, self.run_rows(self.rows()))
        for package in REQUIRED:
            for name in REQUIRED[package]:
                for action in ('run', 'pass'):
                    rows = self.rows()
                    missing = [row for row in rows if row != dict(Action=action, Package=package, Test=name)]
                    with self.assertRaises(AssertionError):
                        self.run_rows(missing)
                    with self.assertRaises(AssertionError):
                        self.run_rows(rows+[dict(Action=action, Package=package, Test=name)])
            completion = dict(Action='pass', Package=package)
            with self.assertRaises(AssertionError):
                self.run_rows([row for row in self.rows() if row != completion])
            with self.assertRaises(AssertionError):
                self.run_rows(self.rows()+[completion])
            with self.assertRaises(AssertionError):
                self.run_rows([completion]+[row for row in self.rows() if row != completion])

    def test_foreign_package_failure_skip_or_no_tests_cannot_substitute_for_execution(self):
        for package, names in REQUIRED.items():
            for action in ('fail', 'skip'):
                for name in (None, sorted(names)[0], 'TestUnrelatedCaseInRequiredPackage'):
                    extra = dict(Action=action, Package=package)
                    if name is not None:
                        extra['Test'] = name
                    with self.assertRaises(AssertionError):
                        self.run_rows(self.rows()+[extra])
            for name in names:
                for action in ('run', 'pass'):
                    foreign = [dict(row, Package=PREFIX+'foreign')
                               if row == dict(Action=action, Package=package, Test=name) else row
                               for row in self.rows()]
                    with self.assertRaises(AssertionError):
                        self.run_rows(foreign)
        with self.assertRaises(AssertionError):
            self.run_rows([dict(Action='pass', Package=package) for package in REQUIRED])
        with self.assertRaises(AssertionError):
            self.run_rows([])

    def test_invalid_or_unbound_json_metadata_is_never_execution_evidence(self):
        for raw in ('[]', '{}', 'null', 'not JSON',
                    json.dumps(dict(Action='pass', Package=[], Test='TestAny')),
                    json.dumps(dict(Action=1, Package=PREFIX+'internal/bootstrap')),
                    json.dumps(dict(Action='pass', Package=PREFIX+'internal/bootstrap', Test=None)),
                    json.dumps(dict(Action='pass', Package=PREFIX+'internal/bootstrap', Test=[])),
                    json.dumps(dict(Action='pass', Package=PREFIX+'internal/bootstrap', Test=''))):
            with self.assertRaises((AssertionError, ValueError)):
                verify([raw])
        rows = [dict(Action='output', Package=PREFIX+'internal/bootstrap', Output='synthetic public output')]+self.rows()
        self.assertEqual(7, self.run_rows(rows))

    def test_required_name_sets_cover_every_new_go_root_in_its_actual_source_package(self):
        verify_source_names(Path(__file__).resolve().parent.parent)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for package, relative in SOURCES.items():
                target = root/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('\n'.join(f'func {name}(t *testing.T) {{}}' for name in sorted(REQUIRED[package])), encoding='utf-8')
            verify_source_names(root)
            target = root/SOURCES[PREFIX+'internal/bootstrap']
            original = target.read_text(encoding='utf-8')
            for changed in (original.replace('TestServiceDiscovery', 'TestRenamedDiscovery', 1),
                            original+'\n'+original.splitlines()[0],
                            '\n'.join(original.splitlines()[1:])):
                target.write_text(changed, encoding='utf-8')
                with self.assertRaises(AssertionError):
                    verify_source_names(root)


if __name__ == '__main__':
    unittest.main()
