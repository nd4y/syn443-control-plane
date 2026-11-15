import json
import unittest
from check_exit_country_evidence import PREFIX, REQUIRED, verify


class ExitCountryEvidenceTest(unittest.TestCase):
    def rows(self, stage, names=None):
        required = REQUIRED[stage]
        names = sorted(required) if names is None else names
        rows = [json.dumps({'Package': required[name], 'Test': name, 'Action': action})
                for name in names for action in ('run', 'pass')]
        return rows + [json.dumps({'Package': package, 'Action': 'pass'})
                       for package in sorted(set(required.values()))]

    def test_actual_core_and_postgres_roots_bound_to_their_packages(self):
        self.assertEqual(8, verify(self.rows('core'), 'core'))
        self.assertEqual(1, verify(self.rows('postgres'), 'postgres'))

    def test_other_package_outputs_and_subtests_cannot_substitute_a_root(self):
        for stage in REQUIRED:
            name = sorted(REQUIRED[stage])[0]
            package = REQUIRED[stage][name]
            rows = self.rows(stage, sorted(REQUIRED[stage])[1:])
            for extra in [
                [{'Package': package, 'Test': name, 'Action': 'output', 'Output': '--- PASS: ' + name}],
                [{'Package': package, 'Test': name + '/nested', 'Action': action} for action in ('run', 'pass')],
                [{'Package': PREFIX + 'other', 'Test': name, 'Action': action} for action in ('run', 'pass')],
            ]:
                with self.subTest(stage=stage, extra=extra), self.assertRaises(AssertionError):
                    verify(rows + [json.dumps(row) for row in extra], stage)

    def test_failure_skip_duplicate_reverse_and_truncated_completion_rejected(self):
        for stage in REQUIRED:
            good = self.rows(stage)
            name = sorted(REQUIRED[stage])[0]
            package = REQUIRED[stage][name]
            reverse = good.copy()
            reverse[0], reverse[1] = reverse[1], reverse[0]
            bad = [[], good + good, reverse, good[:-1], self.rows(stage, sorted(REQUIRED[stage])[1:])]
            for action in ('fail', 'skip'):
                for test in (name, name + '/nested', None):
                    bad.append(good + [json.dumps({'Package': package, 'Test': test, 'Action': action})])
            for rows in bad:
                with self.subTest(stage=stage, rows=rows), self.assertRaises(AssertionError):
                    verify(rows, stage)

    def test_malformed_unbound_and_wrong_stage_evidence_rejected(self):
        for stage in REQUIRED:
            for row in ('null', '[]', 'not-json', '{}', '{"Action":"pass"}',
                        '{"Package":"other","Action":"pass","Test":[]}'):
                with self.subTest(stage=stage, row=row), self.assertRaises((AssertionError, ValueError)):
                    verify(self.rows(stage) + [row], stage)
        with self.assertRaises(AssertionError):
            verify(self.rows('core'), 'postgres')
        with self.assertRaises(AssertionError):
            verify(self.rows('postgres'), 'core')
        with self.assertRaises(AssertionError):
            verify([], 'other')

    def test_plain_output_and_other_packages_are_not_authority(self):
        rows = self.rows('core')
        rows += [json.dumps({'Package': PREFIX + 'configuration', 'Action': 'output', 'Output': 'ordinary fixture output'}),
                 json.dumps({'Package': PREFIX + 'unrelated', 'Action': 'pass'}), '  ']
        self.assertEqual(8, verify(rows, 'core'))
