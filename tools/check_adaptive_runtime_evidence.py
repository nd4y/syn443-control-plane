"""Require package-bound actual managed adaptive outcomes from full CI suites."""
import argparse
import json
from pathlib import Path

REQUIRED = {'core': {'TestAdaptiveCompilerEmitsRealOwnedClosedWireAndResolvesSharedSourcesOnce': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveCompilerSamePublicCandidateCanServeTwoMatchingExitClasses': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveCompilerKeepsAllNormalizedProtocolTLSAndTransportRequirements': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveCompilerRejectsMissingCrossBoundUnsupportedAndConflictingChecks': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveCompilerRejectsNativeInvalidProfilesAndPreservesOwnedCancellation': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveCompilerRetains500CandidatesAndRejectsWireAndWholeEngineOverflow': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveGraphKeepsOwnedPrefixesHopNodeAndNetBirdUnderlayBoundaries': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveIssuedVerifierAcceptsActualCompilerAndAllFiveHundredBindings': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveIssuedVerifierRejectsClosedWireAndUnsafeProfileForgeries': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveIssuedVerifierFencesActualGroupsChecksAndDependencies': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveIssuedVerifierEnforcesIndependentByteAndParserLimits': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptivePlanOwns500BindingsWithoutWideningOrdinaryJSONLimits': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptivePlanRequiresCanonicalBase64AndExactBoundedBindingJSON': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptivePlanRequiresClosedMetadataExactGroupMappingAndStaticTagIsolation': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveDraftLayersRemainClosedAndRequireManagedCheckBindings': 'github.com/nd4y/syn443-control-plane/internal/configuration', 'TestAdaptiveSelectionBoundsKeepOrdinary64AndUnion532Distinct': 'github.com/nd4y/syn443-control-plane/internal/catalog', 'TestAdaptiveSelectionRetainsSourceIdentityModeExpiryAndDuplicateFences': 'github.com/nd4y/syn443-control-plane/internal/catalog', 'TestAdaptiveNetworkReferenceUnionOwnsSortsAndDeduplicates500Plus32': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestAdaptiveNetworkRequiresActualPrimitiveDecisionKeyAndProbeAvailability': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestLayerPublisherDependencyFingerprintBindsAlgorithmWithEqualEngineBytes': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestPreparedAdaptiveConfigurationUsesActualCompilerAndPreservesDeviceKeyAndLease': 'github.com/nd4y/syn443-control-plane/internal/enrollment', 'TestPreparedAdaptiveConfigurationCannotBypassIndependentWireAndSourceFences': 'github.com/nd4y/syn443-control-plane/internal/enrollment', 'TestPreparedAdaptiveConfigurationNeedsNegotiationAndCannotBecomeSharedGrant': 'github.com/nd4y/syn443-control-plane/internal/enrollment', 'TestAdaptivePolicyBindsActualCompilerAlgorithmCapabilityAndDeviceKey': 'github.com/nd4y/syn443-control-plane/internal/policy', 'TestAdaptivePolicyRequiresExactEnvelopeCapabilitySchemaAndConfigureScope': 'github.com/nd4y/syn443-control-plane/internal/policy', 'TestPublicCandidateSeparatesDeclaredExitFromGroupIntent': 'github.com/nd4y/syn443-control-plane/internal/routegraph'}, 'postgres': {'TestSQLAdaptiveAuthoritySignsActualDeviceWithIndependentAvailabilityAndBothFences': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestSQLAdaptiveAuthoritySelectsTheEntire500Plus32UnionWithoutFallback': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestSQLAdaptiveAuthorityRejectsDowngradesForeignKeysAndLateSourceChanges': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestSQLAdaptivePublisherWaitsForSourceLockAndCannotPublishAfterConcurrentRevoke': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestSQLAdaptiveLayerPreviewPublishAndRefreshBindTheRealAlgorithmAndDevice': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning'}, 'catalog': {'TestSQLAdaptiveSelectionOwns500Plus32AndPreservesOrdinaryLimit': 'github.com/nd4y/syn443-control-plane/internal/catalog', 'TestSQLAdaptiveSelectionRepeatsSharesModeExpiryAndRevocationAtFinalFence': 'github.com/nd4y/syn443-control-plane/internal/catalog'}}


REQUIRED['core']['TestConfigurationAdminVerifierPinsIndependentTLSIssuer'] = 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning'
REQUIRED['postgres']['TestConfigurationPublisherCrossRealmAdminPreservesDeviceIdentity'] = 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning'


# Independent administrative bootstrap worker keeps ordinary renewal separate.
REQUIRED['core'].update({'TestConfigurationWorkerLoopUsesOnlyBoundedDatabaseClockAndSerialTicks': 'github.com/nd4y/syn443-control-plane/cmd/configuration-worker', 'TestConfigurationWorkerClockAndPublicationFailuresStayFiniteAndNeverFallBack': 'github.com/nd4y/syn443-control-plane/cmd/configuration-worker', 'TestConfigurationWorkerLoopCancellationJoinsActualStepAndWait': 'github.com/nd4y/syn443-control-plane/cmd/configuration-worker', 'TestConfigurationWorkerCLIReadsNoEnrollmentOrFallbackInputs': 'github.com/nd4y/syn443-control-plane/cmd/configuration-worker', 'TestConfigurationWorkerRuntimeClosedKeysAndExistingDSNGuards': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestConfigurationWorkerRuntimeOwnerOnlyFileAndSigningKeyMatch': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestConfigurationWorkerRuntimeRejectsWrongRoleAndCancellationBeforeAdminDiscovery': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestConfigurationWorkerRuntimeUsesLayerOnlyStoreAndPinnedAdminTLSProvider': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning'})
REQUIRED['postgres'].update({'TestConfigurationWorkerPostgresActualQueueAndUnassignedRenewalRemainIndependent': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning', 'TestConfigurationWorkerPostgresOriginalReceiptsRequireLiveSourceACLAndMFA': 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning'})


for name in (
    'TestConfigurationWorkerClockPreservesSubsecondWallAndRapidPreviewOrdering',
    'TestConfigurationWorkerClockAnchorsFutureFloorAndContinuesAcrossWallAndDBRollback',
    'TestConfigurationWorkerClockNegativeElapsedSealsAndCancelledDBNowDoesNotUpdate',
):
    REQUIRED['core'][name] = 'github.com/nd4y/syn443-control-plane/internal/deviceprovisioning'


def verify(lines, stage):
    assert stage in REQUIRED, 'Unknown evidence stage'
    required = REQUIRED[stage]
    states = {name: [] for name in required}
    packages = {package: [] for package in required.values()}
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        assert isinstance(row, dict), 'Invalid test record'
        action, name, package = row.get('Action'), row.get('Test'), row.get('Package')
        assert isinstance(action, str) and isinstance(package, str), 'Unbound test record'
        assert name is None or isinstance(name, str), 'Invalid test identity'
        if name in required:
            assert package == required[name], 'Substituted test package'
        if package not in packages:
            continue
        assert action not in ('fail', 'skip'), 'Failed or skipped adaptive package outcome'
        if name in states and action in ('run', 'pass'):
            states[name].append(action)
        elif not name and action == 'pass':
            packages[package].append(action)
    assert all(state == ['run', 'pass'] for state in states.values()), 'Missing, repeated or out-of-order adaptive outcome'
    assert all(state == ['pass'] for state in packages.values()), 'Missing or repeated successful package completion'
    return len(states)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--stage', required=True, choices=tuple(REQUIRED))
    args = parser.parse_args()
    print(f'{verify(args.path.read_text().splitlines(), args.stage)} required adaptive runtime {args.stage} cases passed')
