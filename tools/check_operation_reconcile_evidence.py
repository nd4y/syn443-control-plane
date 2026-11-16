"""Require actual package-bound PostgreSQL operation-ledger and HTTP outcomes."""
import argparse
import json
from pathlib import Path
import re

PREFIX = 'github.com/nd4y/syn443-control-plane/'
SOURCE_REQUIRED = {
    'internal/deviceprovisioning/operation_ledger_postgres_test.go': {
        'TestSQLOperationV1AndV2SuccessfulWritesRecordExactIdentityBeforeEffectCommit',
        'TestSQLOperationRecordedWithoutActualNativeEffectCannotCommit',
        'TestSQLOperationOldWriterWithoutSameTransactionLedgerRollsBackItsDraft',
        'TestSQLOperationNativeGatewayRejectsForeignBodyAndTransactionIdentity',
        'TestSQLOperationRuntimeRolesCannotEditEraseOrResetAdmissionCounters',
        'TestSQLOperationNormalQuotaRejectsBeforeEffectAndRollsBackAllCounterCharges',
        'TestSQLOperationActorGlobalDayAndHardCapsAreDistinctAtomicLimits',
        'TestSQLOperationExpiryWhileWaitingForFamilyLockDoesNotCommitLedgerOrEffect',
        'TestSQLOperationRejectedFinalAclRollsBackLedgerAlongWithDraft',
        'TestSQLOperationCounterHardBoundsAndDiagnosticFormattingContainNoProposal',
    },
    'internal/deviceprovisioning/operation_reconcile_postgres_test.go': {
        'TestSQLOperationReconcileVersionOneAbsenceStaysUnknownWithoutFencingOrQuota',
        'TestSQLOperationReconcileVersionTwoLookupIsNotNoEffectUntilAtomicSeal',
        'TestSQLOperationReconcileSealFirstFencesActuallyBlockedOldSqlWriter',
        'TestSQLOperationReconcileOriginalFirstSeesCommitAfterActualActorLockWait',
        'TestSQLOperationReconcileCommittedLostReplyRemainsRecordedAfterRejectedReplay',
        'TestSQLOperationReconcilePrunedPayloadKeepsRecordedFenceAndNeverInventsProposal',
        'TestSQLOperationReconcileCheckedLegacyBackfillUsesSeparateReserve',
        'TestSQLOperationReconcileExhaustedAdmissionCannotStarveExistingRecordedLookup',
        'TestSQLOperationReconcileForeignBodyAclAndExpiredMfaCannotReadOrSeal',
        'TestSQLOperationReconcileExistingQueueRemainsRecordedWithoutCancellationOrActivation',
        'TestSQLOperationReconcileCodecRejectsNoncanonicalBase64ClosedShapeAndNestedOperations',
        'TestSQLOperationReconcileCodecOwnsExactOriginalAndScopedRequestBounds',
        'TestSQLOperationReconcileRecordedPublishDoesNotRequireReauthorizingExpiredPreviewTicket',
    },
    'internal/catalog/http_configuration_reconcile_test.go': {
        'TestSQLConfigurationReconcileHttpBindsActualFixedUriBodyTokenKeyAndFreshProof',
        'TestSQLConfigurationReconcileHttpHasItsOwnExact512KiBBoundWithoutOrdinaryRouteWidening',
        'TestSQLConfigurationReconcileHttpRejectsQueriesEncodedPathsOriginAndDuplicateHeaders',
        'TestSQLConfigurationReconcileHttpReservesOneOfOriginalFourSlotsDuringThreeActualOrdinaryCallbacks',
        'TestSQLConfigurationReconcileHttpCancellationRetainsDebtUntilActualCallbackExit',
    },
}
SOURCES = {
    'catalog': ('internal/catalog/http_configuration_reconcile_test.go',),
    'provisioning': ('internal/deviceprovisioning/operation_ledger_postgres_test.go',
                     'internal/deviceprovisioning/operation_reconcile_postgres_test.go'),
}
REQUIRED = {stage: {name: PREFIX+str(Path(relative).parent).replace('\\', '/')
                    for relative in paths for name in SOURCE_REQUIRED[relative]}
            for stage, paths in SOURCES.items()}


def verify_source_names(root, stage):
    assert stage in SOURCES, 'Unknown operation evidence stage'
    for relative in SOURCES[stage]:
        source = (Path(root)/relative).read_text(encoding='utf-8')
        names = re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{', source, re.M)
        assert len(names) == len(set(names)), 'Repeated operation source root'
        assert set(names) == SOURCE_REQUIRED[relative], 'Operation source/evidence name mismatch'


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'Repeated operation evidence JSON key'
        result[key] = value
    return result


def verify(lines, stage):
    assert stage in REQUIRED, 'Unknown operation evidence stage'
    required = REQUIRED[stage]
    states = {name: [] for name in required}
    completed = {package: [] for package in required.values()}
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line, object_pairs_hook=closed_pairs)
        assert isinstance(row, dict), 'Invalid operation outcome'
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        assert isinstance(action, str) and action and isinstance(package, str) and package, 'Unbound operation outcome'
        assert 'Test' not in row or isinstance(name, str) and name, 'Invalid operation test identity'
        if name in required:
            assert package == required[name], 'Substituted operation package'
        if package not in completed:
            continue
        assert action not in ('fail', 'skip', 'error'), 'Failed/skipped/error operation package outcome'
        if name in states and action in ('run', 'pass'):
            assert not completed[package], 'Operation outcome after package completion'
            states[name].append(action)
        elif name is None and action == 'pass':
            assert all(states[test] == ['run', 'pass'] for test, owner in required.items() if owner == package), 'Incomplete operation package'
            completed[package].append(action)
    assert all(value == ['run', 'pass'] for value in states.values()), 'Missing/repeated/out-of-order operation root'
    assert all(value == ['pass'] for value in completed.values()), 'Operation package did not complete exactly once'
    return len(states)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--stage', required=True, choices=tuple(REQUIRED))
    args = parser.parse_args()
    assert args.path.is_file() and 0 < args.path.stat().st_size <= 64*1024*1024, 'Invalid operation evidence file'
    verify_source_names(Path(__file__).resolve().parent.parent, args.stage)
    print(f'{verify(args.path.read_text(encoding="utf-8").splitlines(), args.stage)} actual operation-reconcile {args.stage} roots passed')
