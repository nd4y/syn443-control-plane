import json
from itertools import chain
from pathlib import Path
import re
import tempfile
import unittest

from check_check_plan_evidence import (
    COMMON_ROOT, MAX_FILE, MAX_LINE, PG_ROOT, PREFIX, REQUIRED, SOURCES,
    SOURCE_REQUIRED, VECTOR_PATH, expected_cases, verify, verify_source_names,
)

ROOT = Path(__file__).resolve().parent.parent


class CheckPlanEvidenceTest(unittest.TestCase):
    def rows(self, stage):
        expected = expected_cases(ROOT, stage)
        rows = []
        for package in sorted(set(REQUIRED[stage].values())):
            rows.append(dict(Action='start', Package=package))
            for root, owner in sorted(REQUIRED[stage].items()):
                if owner != package:
                    continue
                rows.append(dict(Action='run', Package=package, Test=root))
                for child in sorted(name for name in expected if name.startswith(root + '/')):
                    rows += [dict(Action=action, Package=package, Test=child) for action in ('run', 'pass')]
                rows.append(dict(Action='pass', Package=package, Test=root))
            rows.append(dict(Action='pass', Package=package))
        return rows

    def run_rows(self, rows, stage, root=ROOT):
        return verify((json.dumps(row) for row in rows), stage, root)

    def copy_sources(self, directory):
        root = Path(directory)
        for relative in (*SOURCE_REQUIRED, VECTOR_PATH):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        return root

    def test_twenty_five_roots_and_fifty_six_named_subcases_need_actual_complete_packages(self):
        for stage, counts in {'core': dict(roots=22, subcases=52, outcomes=74, packages=4),
                              'postgres': dict(roots=4, subcases=4, outcomes=8, packages=1)}.items():
            self.assertEqual(counts, self.run_rows(self.rows(stage), stage))
            self.assertEqual(counts['outcomes'], len(expected_cases(ROOT, stage)))
            frames = []
            for row in self.rows(stage):
                frames.append(row)
                if row['Action'] == 'run':
                    for kind in ('frame', 'error'):
                        frames.append(dict(Action='output', Package=row['Package'], Test=row['Test'],
                                           Output='synthetic public test output', OutputType=kind))
            self.assertEqual(counts, self.run_rows(frames, stage))
        self.assertEqual(26, sum(len(names) for names in REQUIRED.values()))

    def test_every_required_root_child_run_pass_and_package_start_completion_is_mandatory(self):
        for stage in REQUIRED:
            original = self.rows(stage)
            for index, row in enumerate(original):
                with self.subTest(stage=stage, index=index, action=row['Action']):
                    with self.assertRaises(AssertionError):
                        self.run_rows(original[:index] + original[index + 1:], stage)
                    with self.assertRaises(AssertionError):
                        self.run_rows(original[:index] + [row] + original[index:], stage)
            with self.assertRaises(AssertionError):
                self.run_rows([], stage)

    def test_foreign_or_renamed_roots_and_vector_children_cannot_substitute_for_own_execution(self):
        for stage in REQUIRED:
            original = self.rows(stage)
            for name, package in expected_cases(ROOT, stage).items():
                for action in ('run', 'pass'):
                    wanted = dict(Action=action, Package=package, Test=name)
                    for changed in (dict(wanted, Package=PREFIX + 'foreign'),
                                    dict(wanted, Test=name + '-renamed')):
                        rows = [changed if row == wanted else row for row in original]
                        with self.assertRaises(AssertionError):
                            self.run_rows(rows, stage)
                    with self.assertRaises(AssertionError):
                        self.run_rows(original + [dict(wanted, Package=PREFIX + 'foreign')], stage)
            with self.assertRaises(AssertionError):
                self.run_rows([row for row in original if 'Test' not in row], stage)

    def test_parent_package_order_and_duplicate_lifetimes_cannot_fabricate_success(self):
        for stage in REQUIRED:
            original = self.rows(stage)
            for index, row in enumerate(original):
                if row['Action'] != 'run':
                    continue
                passed = dict(row, Action='pass')
                before_run = original[:index] + [passed] + original[index:]
                with self.assertRaises(AssertionError):
                    self.run_rows(before_run, stage)
            package = next(iter(REQUIRED[stage].values()))
            for action in ('start', 'pass', 'output'):
                extra = dict(Action=action, Package=package)
                with self.assertRaises(AssertionError):
                    self.run_rows([extra] + original, stage)
                with self.assertRaises(AssertionError):
                    self.run_rows(original + [extra], stage)
            parent = COMMON_ROOT if stage == 'core' else PG_ROOT
            position = next(i for i, row in enumerate(original) if row.get('Test') == parent and row['Action'] == 'run')
            owner = REQUIRED[stage][parent]
            with self.assertRaises(AssertionError):
                self.run_rows(original[:position + 1] + [dict(Action='pass', Package=owner, Test=parent)] + original[position + 1:], stage)

    def test_required_skip_fail_error_and_unfinished_children_fail_but_unrelated_pg_skips_remain_legal(self):
        for stage in REQUIRED:
            original = self.rows(stage)
            for name, package in expected_cases(ROOT, stage).items():
                position = next(i for i, row in enumerate(original) if row.get('Test') == name and row['Action'] == 'run')
                for action in ('fail', 'skip', 'error', 'build-fail'):
                    with self.assertRaises(AssertionError):
                        self.run_rows(original[:position + 1] + [dict(Action=action, Package=package, Test=name)] + original[position + 1:], stage)
            owner = next(iter(REQUIRED[stage].values()))
            index = next(i for i, row in enumerate(original) if row == dict(Action='start', Package=owner)) + 1
            unrelated = [dict(Action='run', Package=owner, Test='TestLegacyPostgresFixtureRequiresDatabase'),
                         dict(Action='skip', Package=owner, Test='TestLegacyPostgresFixtureRequiresDatabase')]
            self.assertEqual(len(REQUIRED[stage]), self.run_rows(original[:index] + unrelated + original[index:], stage)['roots'])
            self.assertEqual(len(REQUIRED[stage]), self.run_rows([dict(Action='skip', Package=PREFIX + 'unrelated')] + original, stage)['roots'])
            for action in ('fail', 'error', 'build-fail'):
                with self.assertRaises(AssertionError):
                    self.run_rows(original[:index] + [dict(Action=action, Package=owner)] + original[index:], stage)
            parent = next(name for name, package in REQUIRED[stage].items() if package == owner)
            parent_index = next(i for i, row in enumerate(original) if row == dict(Action='run', Package=owner, Test=parent)) + 1
            child = dict(Action='run', Package=owner, Test=parent + '/uncompleted')
            with self.assertRaises(AssertionError):
                self.run_rows(original[:parent_index] + [child] + original[parent_index:], stage)

    def test_malformed_duplicate_nonfinite_oversize_and_unbound_json_never_counts(self):
        package = PREFIX + 'internal/routecheck'
        malformed = ('[]', '{}', 'null', 'not JSON',
                     json.dumps(dict(Action=1, Package=package)),
                     json.dumps(dict(Action='unknown', Package=package)),
                     json.dumps(dict(Action='output', Package=[])),
                     json.dumps(dict(Action='output', Package='')),
                     json.dumps(dict(Action='output', Package=package, Test=None)),
                     json.dumps(dict(Action='output', Package=package, Test=[])),
                     json.dumps(dict(Action='output', Package=package, Test='')),
                     json.dumps(dict(Action='output', Package=package, Output={})),
                     json.dumps(dict(Action='output', Package=package, Time=[])),
                     json.dumps(dict(Action='output', Package=package, Elapsed=True)),
                     json.dumps(dict(Action='output', Package=package, Elapsed=-1)),
                     json.dumps(dict(Action='output', Package=package, Elapsed=10**400)),
                     json.dumps(dict(Action='output', Package=package, Output='synthetic', OutputType=[])),
                     json.dumps(dict(Action='output', Package=package, Output='synthetic', OutputType=None)),
                     json.dumps(dict(Action='output', Package=package, Output='synthetic', OutputType=True)),
                     json.dumps(dict(Action='output', Package=package, Output='synthetic', OutputType='stdout')),
                     json.dumps(dict(Action='output', Package=package, Output='synthetic', OutputType='')),
                     json.dumps(dict(Action='output', Package=package, OutputType='frame')),
                     json.dumps(dict(Action='run', Package=package, Test=COMMON_ROOT, Output='synthetic', OutputType='frame')),
                     json.dumps(dict(Action='output', Package=package, Extra='unknown')),
                     '{"Action":"output","Action":"output","Package":' + json.dumps(package) + '}',
                     '{"Action":"output","Package":' + json.dumps(package) + ',"Pack\\u0061ge":' + json.dumps(package) + '}',
                     '{"Action":"output","Package":' + json.dumps(package) + ',"Elapsed":NaN}',
                     '{"Action":"output","Package":' + json.dumps(package) + ',"Elapsed":1e999}',
                     '{"Action":"pass","Package":' + json.dumps(package) + '}{}')
        rows = self.rows('core')
        index = next(i for i, row in enumerate(rows) if row == dict(Action='start', Package=package)) + 1
        before, after = [json.dumps(row) for row in rows[:index]], [json.dumps(row) for row in rows[index:]]
        for raw in malformed:
            with self.assertRaises(AssertionError):
                verify(before + [raw] + after, 'core')
        with self.assertRaises(AssertionError):
            verify([' ' * (MAX_LINE + 1)] + [json.dumps(row) for row in rows], 'core')
        with self.assertRaises(AssertionError):
            verify(chain((' ' * MAX_LINE for _ in range(MAX_FILE // MAX_LINE + 1)), (json.dumps(row) for row in rows)), 'core')
        with self.assertRaises(AssertionError):
            verify([], 'unknown')
        # Successful build diagnostics are neither starts nor test outcomes.
        build = dict(Action='build-output', ImportPath=package, Output='synthetic public build output')
        self.assertEqual(22, self.run_rows([build] + self.rows('core'), 'core')['roots'])
        for action in ('run', 'pass'):
            wanted = dict(Action=action, Package=package, Test=COMMON_ROOT)
            frame = dict(wanted, Action='output', Output='synthetic public frame', OutputType='frame')
            with self.assertRaises(AssertionError):
                self.run_rows([frame if row == wanted else row for row in rows], 'core')

    def test_source_names_package_declarations_build_tags_and_vector_emission_are_locked(self):
        for stage in REQUIRED:
            verify_source_names(ROOT, stage)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_sources(directory)
            for stage, paths in SOURCES.items():
                for relative in paths:
                    path = root / relative
                    original = path.read_text(encoding='utf-8')
                    first = sorted(SOURCE_REQUIRED[relative])[0]
                    changed_sources = (original.replace('func ' + first, 'func Renamed' + first, 1),
                                       original + '\nfunc TestUnregisteredNewRoot(t *testing.T) {}\n',
                                       original + '\nfunc ' + first + '(t *testing.T) {}\n',
                                       re.sub(r'^package \w+', 'package foreign', original, count=1, flags=re.M),
                                       original.replace('//go:build postgres', '//go:build ignored', 1) if stage == 'postgres' else '//go:build postgres\n\n' + original)
                    for changed in changed_sources:
                        path.write_text(changed, encoding='utf-8')
                        with self.assertRaises(AssertionError):
                            verify_source_names(root, stage)
                    path.write_text(original, encoding='utf-8')
            path = root / 'internal/routecheck/plan_test.go'
            original = path.read_text(encoding='utf-8')
            for marker in ('t.Run(v.Name,', 't.Run("invalid/"+v.Name,', 't.Run("raw/"+v.Name,'):
                path.write_text(original.replace(marker, 'removed_vector_emission(', 1), encoding='utf-8')
                with self.assertRaises(AssertionError):
                    verify_source_names(root, 'core')
            path.write_text(original, encoding='utf-8')
        with self.assertRaises(AssertionError):
            verify_source_names(ROOT, 'unknown')

    def test_closed_shared_vector_names_counts_and_payloads_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_sources(directory)
            path = root / VECTOR_PATH
            original = path.read_text(encoding='utf-8')
            for change in ('missing', 'duplicate', 'renamed', 'shape', 'payload', 'hash', 'version', 'unknown'):
                data = json.loads(original)
                if change == 'missing':
                    data['validCases'].pop()
                elif change == 'duplicate':
                    data['invalidCases'][0]['name'] = data['invalidCases'][1]['name']
                elif change == 'renamed':
                    data['validCases'][0]['name'] += '-changed'
                elif change == 'shape':
                    data['invalidRawCases'][0]['unknown'] = False
                elif change == 'payload':
                    data['validCases'][0]['profile'] = None
                elif change == 'hash':
                    data['validCases'][0]['sha256'] = 'invalid'
                elif change == 'version':
                    data['schemaVersion'] = True
                else:
                    data['unknown'] = []
                path.write_text(json.dumps(data), encoding='utf-8')
                with self.assertRaises(AssertionError):
                    self.run_rows(self.rows('core'), 'core', root)
            path.write_text(original, encoding='utf-8')
            self.assertEqual(74, self.run_rows(self.rows('core'), 'core', root)['outcomes'])

    def test_existing_workflow_runs_one_documents_gate_and_both_existing_json_stages(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        for command in ("python3 -m unittest discover -s tools -p 'test_check_plan_evidence.py'",
                        'python3 tools/check_check_plan_evidence.py exit-country-core-tests.jsonl --stage core',
                        'python3 tools/check_check_plan_evidence.py exit-country-postgres-tests.jsonl --stage postgres'):
            self.assertEqual(1, workflow.count(command))
        for command in ('go test -race -count=1 -json -coverprofile=coverage.out ./... | tee exit-country-core-tests.jsonl',
                        'GOFLAGS=-json bash tools/test_invitations.sh | tee exit-country-postgres-tests.jsonl'):
            self.assertEqual(1, workflow.count(command))


if __name__ == '__main__':
    unittest.main()
