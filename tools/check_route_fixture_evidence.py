"""Require all actual Linux LAN fixture outcomes, not just a compiled binary."""
import json
from pathlib import Path
import sys

PACKAGE = 'github.com/nd4y/syn443-control-plane/cmd/route-fixture'
REQUIRED = {'TestRouteFixtureConfigClosedShapeBoundsAndNoProductionLoopbackBypass', 'TestRouteFixtureConfigFileMustBeOwnedRegularExact0600AndBounded', 'TestRouteFixtureRealTwoHopTCPAuthExactDestinationsAndPrefetchedNonce', 'TestRouteFixtureTwoConcurrentNonceFlowsCompleteWithinStrictEightReservations', 'TestRouteFixtureWrongSourceAndSOCKSNoAuthCannotReachExit', 'TestRouteFixtureWrongSOCKSCredentialsCommandsTypesAndDestinationCannotDial', 'TestRouteFixtureHTTPConnectRejectsAmbiguousInjectedUnauthorizedAndUnboundedHeaders', 'TestRouteFixtureTargetOnlyEchoesExactNonceAndSupportsEmptyTCPHealth', 'TestRouteFixtureBranchDisableClosesOwnedTrafficReopensSameAddressAndFencesOldGeneration', 'TestRouteFixtureInternalAcceptRequiresPairedDialAndRejectsQueuedOldGeneration', 'TestRouteFixtureDialLinkRemovedBeforeDescriptorReleaseAndOldCleanupCannotEraseReplacement', 'TestRouteFixtureGlobalEightAcceptedSlotsIncludeUnauthenticatedAndInternalStages', 'TestRouteFixtureRelayJoinsBothCopyWorkersBeforeReturningOnCancellation', 'TestRouteFixtureAggregateTrafficBudgetClosesActualTCPConnection', 'TestRouteFixtureTTLClosesAllListenersConnectionsAndRejectsReenable', 'TestRouteFixtureUnauthenticatedReadDeadlineClosesBeforeIndependentTTL', 'TestRouteFixtureStatusAndRejectedCLIOnlyExposeFixedCounters'}

def verify(lines):
    states = {name: [] for name in REQUIRED}
    completed = []
    for line in lines:
        if not line.strip(): continue
        row = json.loads(line)
        assert isinstance(row, dict), 'Invalid fixture outcome'
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        assert isinstance(action, str) and isinstance(package, str), 'Unbound fixture outcome'
        assert name is None or isinstance(name, str), 'Invalid fixture case'
        if name in REQUIRED:
            assert package == PACKAGE, 'Substituted fixture package'
        if package != PACKAGE: continue
        assert action not in ('fail', 'skip'), 'Failed/skipped fixture outcome'
        if name in REQUIRED and action in ('run', 'pass'): states[name].append(action)
        elif name is None and action == 'pass': completed.append(action)
    assert all(v == ['run', 'pass'] for v in states.values()), 'Missing/repeated fixture case'
    assert completed == ['pass'], 'Fixture package did not finish once'
    return len(states)

if __name__ == '__main__':
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= 64*1024*1024
    print(f'{verify(path.read_text().splitlines())} actual route fixture cases passed')
