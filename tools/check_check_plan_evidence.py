"""Require actual package-bound check-plan roots and closed shared-vector cases."""
import argparse
import json
import math
from pathlib import Path
import re

PREFIX = 'github.com/nd4y/syn443-control-plane/'
MAX_FILE = 64 * 1024 * 1024
MAX_LINE = 1024 * 1024
SOURCE_REQUIRED = {
    'internal/routecheck/plan_test.go': {
        'TestCheckPlanV2SharedContractValidInvalidAndRawVectors',
        'TestCheckPlanV2ClosedXorNullCaseAndDuplicateRows',
        'TestCheckPlanV2SecurityLeavesMustBeUnconditionalMatchingGates',
        'TestCheckPlanV2IntegerDeadlineLeafAndProgramBoundaries',
        'TestCheckPlanV2CanonicalLeafOrderDoesNotRewriteBranchOrderOrLegacy',
        'TestCheckPlanV2DeclaredLeavesAreOwnedAndNeverDiscountShortCircuitCost',
        'TestCheckPlanV2MetadataBytePlanBoundsAndDiagnosticsStayRedacted',
    },
    'internal/configuration/check_plan_test.go': {
        'TestCheckPlanV2ActualNetworkCompilerPreservesProgramAndLegacyBytes',
        'TestCheckPlanV2CompilerAndIndependentIssuerRejectVariablePaths',
        'TestCheckPlanV2DirectTerminalFourNodeLimitAndNetBirdBoundary',
        'TestCheckPlanV2AdaptiveCompilerAndIndependentIssuerRequireUnconditionalCountryGate',
        'TestCheckPlanV2WholeNetworkDecodeRejectsNullBothAndExactNumbers',
        'TestCheckPlanV2ActualPlanOwnsProfileBeforeSourceResolverMutation',
        'TestCheckPlanV2MetadataBudgetCountsEveryDeclaredLeafAndAllRows',
        'TestCheckPlanV2DoesNotOptLegacySelectorFailoverIntoMixedObservations',
    },
    'internal/policy/check_plan_test.go': {
        'TestCheckPlanV2PolicyRequiresIffCapabilityKeyBoundConfigureAndHealth',
        'TestCheckPlanV2PolicyScansAllLeavesAndDoesNotSubstituteExitCapabilities',
        'TestCheckPlanV2SignedBoundPolicyCannotLoseKeyOrMutateClosedProgram',
    },
    'internal/enrollment/check_plan_test.go': {
        'TestPreparedCheckPlanV2RequiresAddressedAvailabilityWithoutGrantInference',
        'TestPreparedCheckPlanV2IffCapabilityCannotBeForgedByCallback',
        'TestPreparedCheckPlanV2IndependentRawValidationRejectsNullAlternativesAndVariablePaths',
    },
    'internal/deviceprovisioning/check_plan_postgres_test.go': {
        'TestSQLCheckPlanV2ActualPublisherSignsOnlyAddressedApprovedCapabilityAndOwnedProgram',
        'TestSQLCheckPlanV2OldAndDowngradedCapabilityTargetsCannotFlattenOrFallBack',
        'TestSQLCheckPlanV2FinalSourceLayerExpiryAndCancellationFencesPreserveBaseline',
        'TestSQLCheckPlanV2PublisherWaitsForConcurrentSourceRevokeWithoutIssuingProgram',
    },
}
SOURCES = {
    'core': tuple(path for path in SOURCE_REQUIRED if not path.endswith('_postgres_test.go')),
    'postgres': ('internal/deviceprovisioning/check_plan_postgres_test.go',),
}
REQUIRED = {stage: {name: PREFIX + Path(path).parent.as_posix()
                    for path in paths for name in SOURCE_REQUIRED[path]}
            for stage, paths in SOURCES.items()}
assert {stage: len(names) for stage, names in REQUIRED.items()} == {'core': 21, 'postgres': 4}
COMMON_ROOT = 'TestCheckPlanV2SharedContractValidInvalidAndRawVectors'
PG_ROOT = 'TestSQLCheckPlanV2FinalSourceLayerExpiryAndCancellationFencesPreserveBaseline'
VECTOR_PATH = 'contracts/v1/route-check-profile-v2-vectors.json'
VECTOR_COUNTS = {'validCases': 9, 'invalidCases': 37, 'invalidRawCases': 6,
                 'truthCases': 51, 'legacyCases': 1}
PG_CHILDREN = ('source', 'layer', 'expiry', 'cancel')
ROW_FIELDS = {'Time', 'Action', 'Package', 'ImportPath', 'Test', 'Elapsed', 'Output', 'FailedBuild'}
ACTIONS = {'start', 'run', 'pause', 'cont', 'pass', 'fail', 'skip', 'output',
           'bench', 'build-output', 'build-fail', 'error'}


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'Duplicate check-plan evidence JSON key'
        result[key] = value
    return result


def invalid_constant(_value):
    raise AssertionError('Nonfinite check-plan evidence value')


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=closed_pairs, parse_constant=invalid_constant)
    except (ValueError, RecursionError):
        raise AssertionError('Malformed check-plan JSON') from None


def bounded_source(root, relative):
    path = Path(root) / relative
    assert path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 131072, 'Invalid check-plan source file'
    return path.read_text(encoding='utf-8')


def verify_source_names(root, stage):
    assert stage in SOURCES, 'Unknown check-plan evidence stage'
    for relative in SOURCES[stage]:
        source = bounded_source(root, relative)
        names = re.findall(r'^func (Test[A-Za-z0-9_]+)\([A-Za-z_][A-Za-z0-9_]* \*testing\.T\) \{', source, re.M)
        assert len(names) == len(set(names)) and set(names) == SOURCE_REQUIRED[relative], 'Check-plan source/evidence root mismatch'
        package = Path(relative).parent.name
        declarations = re.findall(r'^package ([A-Za-z_][A-Za-z0-9_]*)\s*$', source, re.M)
        assert len(declarations) == 1 and declarations[0] in (package, package + '_test'), 'Check-plan source package mismatch'
        tagged = re.findall(r'^//go:build (.+)$', source, re.M)
        assert tagged == (['postgres'] if stage == 'postgres' else []), 'Check-plan source stage mismatch'
    if stage == 'core':
        source = bounded_source(root, 'internal/routecheck/plan_test.go')
        for marker in ('contracts.Files.ReadFile("v1/route-check-profile-v2-vectors.json")',
                       't.Run(v.Name,', 't.Run("invalid/"+v.Name,', 't.Run("raw/"+v.Name,'):
            assert marker in source, 'Shared check-plan source no longer executes named vectors'
    else:
        source = bounded_source(root, SOURCES['postgres'][0])
        assert '[]string{"source", "layer", "expiry", "cancel"}' in source and 't.Run(change,' in source, 'Check-plan PostgreSQL fence cases changed'


def expected_cases(root, stage):
    assert stage in REQUIRED, 'Unknown check-plan evidence stage'
    result = dict(REQUIRED[stage])
    if stage == 'postgres':
        result.update({PG_ROOT + '/' + child: REQUIRED[stage][PG_ROOT] for child in PG_CHILDREN})
        return result
    path = Path(root) / VECTOR_PATH
    assert path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 2 * 1024 * 1024, 'Invalid shared check-plan fixture'
    vectors = parse_json(path.read_text(encoding='utf-8'))
    assert type(vectors) is dict and set(vectors) == {'schemaVersion', *VECTOR_COUNTS}, 'Shared check-plan fixture shape changed'
    assert type(vectors['schemaVersion']) is int and vectors['schemaVersion'] == 1, 'Unknown shared check-plan fixture version'
    for key, count in VECTOR_COUNTS.items():
        assert type(vectors[key]) is list and len(vectors[key]) == count, 'Shared check-plan collection changed'
    # Truth profiles are syntax-checked by the Go root; this gate deliberately
    # does not claim CP executes the native truth/visit interpreter.
    for collection, prefix in (('validCases', ''), ('invalidCases', 'invalid/'), ('invalidRawCases', 'raw/')):
        names = set()
        for case in vectors[collection]:
            fields = {'name', 'raw'} if collection == 'invalidRawCases' else {'name', 'profile', 'sha256'} if collection == 'validCases' else {'name', 'profile'}
            assert type(case) is dict and set(case) == fields, 'Invalid shared check-plan case shape'
            name = case['name']
            assert isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9._-]{0,95}', name) and name not in names, 'Invalid/repeated shared check-plan case'
            names.add(name)
            if collection == 'validCases':
                assert isinstance(case['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', case['sha256']), 'Invalid shared profile hash'
            if collection == 'invalidRawCases':
                assert isinstance(case['raw'], str), 'Invalid shared raw profile payload'
            else:
                assert type(case['profile']) is dict, 'Invalid shared profile payload'
            result[COMMON_ROOT + '/' + prefix + name] = REQUIRED[stage][COMMON_ROOT]
    assert len(result) == 73, 'Missing shared check-plan execution identities'
    return result


def verify(lines, stage, root=None):
    assert stage in REQUIRED, 'Unknown check-plan evidence stage'
    root = Path(root) if root is not None else Path(__file__).resolve().parent.parent
    expected = expected_cases(root, stage)
    roots = {name: package for names in REQUIRED.values() for name, package in names.items()}
    owners = {**roots, **expected}
    packages = {package: 'new' for package in REQUIRED[stage].values()}
    states = {}
    total_bytes = 0
    for index, line in enumerate(lines):
        assert index < 1000000 and isinstance(line, str), 'Unbounded check-plan evidence rows'
        size = len(line.encode('utf-8'))
        total_bytes += size
        assert size <= MAX_LINE and total_bytes <= MAX_FILE, 'Unbounded check-plan evidence bytes'
        if not line.strip():
            continue
        row = parse_json(line)
        assert type(row) is dict and set(row) <= ROW_FIELDS, 'Invalid check-plan outcome fields'
        action, package, imported, name = (row.get(key) for key in ('Action', 'Package', 'ImportPath', 'Test'))
        assert isinstance(action, str) and action in ACTIONS, 'Invalid check-plan action'
        for key, maximum in (('Package', 512), ('ImportPath', 512), ('Test', 512), ('Time', 128), ('FailedBuild', 512), ('Output', MAX_LINE)):
            assert key not in row or isinstance(row[key], str) and (key == 'Output' or row[key]) and len(row[key]) <= maximum, 'Malformed check-plan outcome metadata'
        if 'Elapsed' in row:
            elapsed = row['Elapsed']
            assert type(elapsed) in (int, float) and 0 <= elapsed <= 9007199254740991 and (type(elapsed) is int or math.isfinite(elapsed)), 'Malformed check-plan elapsed value'
        assert action not in {'fail', 'error', 'build-fail'} and not row.get('FailedBuild'), 'Failed check-plan suite outcome'
        if action == 'build-output':
            assert imported and name is None and package in (None, imported), 'Unbound Go build output'
            continue
        assert package and re.fullmatch(r'[A-Za-z0-9._/-]{1,512}', package), 'Unbound check-plan package'
        assert imported in (None, package), 'Ambiguous check-plan package identity'
        test_root = name.split('/')[0] if name else None
        if name in owners:
            assert package == owners[name], 'Foreign check-plan test package'
        if test_root in roots:
            assert package == roots[test_root], 'Foreign check-plan descendant package'
        if package not in packages:
            continue
        if action == 'start':
            assert name is None and packages[package] == 'new', 'Repeated check-plan package start'
            packages[package] = 'running'
            continue
        assert packages[package] == 'running', 'Check-plan outcome outside package lifetime'
        tracked = test_root in REQUIRED[stage]
        if tracked:
            assert action in {'run', 'pass', 'pause', 'cont', 'output'}, 'Skipped/invalid required check-plan case'
            if action == 'run':
                assert name not in states and len(states) < 4096, 'Repeated check-plan test start'
                if '/' in name:
                    parent = name.rsplit('/', 1)[0]
                    # Go permits slash-separated subtest names without an
                    # intermediate t.Run; use the nearest actual parent.
                    while parent not in states and '/' in parent:
                        parent = parent.rsplit('/', 1)[0]
                    assert states.get(parent) == 'running', 'Check-plan child outside active parent'
                states[name] = 'running'
            elif action == 'pass':
                assert states.get(name) == 'running', 'Check-plan pass without one active run'
                assert all(value == 'passed' for child, value in states.items() if child.startswith(name + '/')), 'Check-plan parent passed before children'
                assert all(states.get(child) == 'passed' for child in expected if child.startswith(name + '/')), 'Missing mandatory check-plan child'
                states[name] = 'passed'
            elif action in {'pause', 'cont'}:
                assert states.get(name) == ('running' if action == 'pause' else 'paused'), 'Invalid check-plan parallel lifecycle'
                states[name] = 'paused' if action == 'pause' else 'running'
            else:
                assert name in states, 'Check-plan output before actual run'
        elif name is None:
            if action == 'pass':
                assert all(states.get(test) == 'passed' for test, owner in expected.items() if owner == package), 'Incomplete check-plan package'
                packages[package] = 'passed'
            else:
                assert action == 'output', 'Skipped/invalid check-plan package'
        # A skip for an unrelated legacy/PG fixture is not evidence for this
        # stage and must not be confused with a skipped new root/descendant.
    assert all(states.get(name) == 'passed' for name in expected), 'Missing/repeated check-plan outcome'
    assert all(value == 'passed' for value in packages.values()), 'Check-plan package did not complete exactly once'
    return {'roots': len(REQUIRED[stage]), 'subcases': len(expected) - len(REQUIRED[stage]), 'outcomes': len(expected), 'packages': len(packages)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--stage', required=True, choices=tuple(REQUIRED))
    args = parser.parse_args()
    assert args.path.is_file() and not args.path.is_symlink() and 0 < args.path.stat().st_size <= MAX_FILE, 'Invalid check-plan evidence file'
    source_root = Path(__file__).resolve().parent.parent
    verify_source_names(source_root, args.stage)
    with args.path.open(encoding='utf-8') as evidence:
        result = verify(evidence, args.stage, source_root)
    print(f"{result['roots']} actual check-plan {args.stage} roots and {result['subcases']} named subcases passed in {result['packages']} packages")
