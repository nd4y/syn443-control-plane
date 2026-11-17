"""Require fourteen actual source/package-bound protocol eligibility outcomes."""
import argparse
import json
from pathlib import Path
import re

PREFIX = 'github.com/nd4y/syn443-control-plane/'
SOURCE_REQUIRED = {
    'internal/deviceprovisioning/operation_version_test.go': {
        'TestOperationVersionOwnerDefaultsStayOneAndTwoRequiresExplicitDeclaration',
        'TestOperationVersionOwnerDeclarationRejectsNullCoercionCaseDuplicatesAndOutOfRangeIntegers',
        'TestOperationVersionReplyIsClosedNonsecretRedactedEligibilityWithoutGrantFields',
        'TestOperationVersionReadPayloadRemainsEmptyClosedAndVersionOneOnly',
        'TestOperationVersionReadRechecksOriginalDeadlineAndCancellationBeforeReturning',
        'TestOperationVersionBoundProofAndCurrentControlScopeRemainRequiredWithoutFreshMfaPromotion',
        'TestOperationVersionOwnerFileAndActualApiWiringCannotInferOrOverrideEligibility',
    },
    'internal/deviceprovisioning/operation_version_postgres_test.go': {
        'TestSQLOperationVersionReadUsesCurrentProofAndOwnerDeclarationWithoutTargetAclOrFreshMfa',
        'TestSQLOperationVersionReadRejectsInvalidExpiredForeignProofScopeRoleAndCancellation',
        'TestSQLOperationVersionDeclarationNeverGrantsMutationAclMfaOrChangesExistingV2Acceptance',
        'TestSQLOperationVersionMalformedPayloadAndVersionTwoReadCannotCreateBusinessRows',
    },
    'internal/catalog/http_operation_version_test.go': {
        'TestSQLConfigurationProtocolHttpUsesExistingBoundProofRouteWithoutTargetAclOrFreshMfa',
        'TestSQLConfigurationProtocolHttpMalformedOrForeignRequestsNeverInvokeTheService',
        'TestSQLConfigurationProtocolHttpDoesNotBroadenV2ActionsOrTreatFeatureDenialAsUnsupported',
    },
}
SOURCES = {
    'core': ('internal/deviceprovisioning/operation_version_test.go',),
    'provisioning': ('internal/deviceprovisioning/operation_version_postgres_test.go',),
    'catalog': ('internal/catalog/http_operation_version_test.go',),
}
REQUIRED = {stage: {name: PREFIX+str(Path(relative).parent).replace('\\', '/')
                    for relative in paths for name in SOURCE_REQUIRED[relative]}
            for stage, paths in SOURCES.items()}
assert {stage: len(names) for stage, names in REQUIRED.items()} == {'core': 7, 'provisioning': 4, 'catalog': 3}


def verify_source_names(root, stage):
    assert stage in SOURCES, 'Unknown operation-version evidence stage'
    for relative in SOURCES[stage]:
        source = (Path(root)/relative).read_text(encoding='utf-8')
        names = re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{', source, re.M)
        assert len(names) == len(set(names)), 'Repeated operation-version source root'
        assert set(names) == SOURCE_REQUIRED[relative], 'Operation-version source/evidence name mismatch'


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'Repeated operation-version evidence JSON key'
        result[key] = value
    return result


def verify(lines, stage):
    assert stage in REQUIRED, 'Unknown operation-version evidence stage'
    required = REQUIRED[stage]
    states = {name: [] for name in required}
    completed = {package: [] for package in required.values()}
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line, object_pairs_hook=closed_pairs)
        assert isinstance(row, dict), 'Invalid operation-version outcome'
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        assert isinstance(action, str) and action and isinstance(package, str) and package, 'Unbound operation-version outcome'
        assert 'Test' not in row or isinstance(name, str) and name, 'Invalid operation-version test identity'
        if name in required:
            assert package == required[name], 'Substituted operation-version package'
        if package not in completed:
            continue
        assert action not in ('fail', 'skip', 'error'), 'Failed/skipped/error operation-version package outcome'
        if name in states and action in ('run', 'pass'):
            assert not completed[package], 'Operation-version root after package completion'
            states[name].append(action)
        elif name is None and action == 'pass':
            assert all(states[test] == ['run', 'pass'] for test, owner in required.items() if owner == package), 'Incomplete operation-version package'
            completed[package].append(action)
    assert all(value == ['run', 'pass'] for value in states.values()), 'Missing/repeated/out-of-order operation-version root'
    assert all(value == ['pass'] for value in completed.values()), 'Operation-version package did not complete exactly once'
    return len(states)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--stage', required=True, choices=tuple(REQUIRED))
    args = parser.parse_args()
    assert args.path.is_file() and 0 < args.path.stat().st_size <= 64*1024*1024, 'Invalid operation-version evidence file'
    verify_source_names(Path(__file__).resolve().parent.parent, args.stage)
    print(f'{verify(args.path.read_text(encoding="utf-8").splitlines(), args.stage)} actual operation-version {args.stage} roots passed')
