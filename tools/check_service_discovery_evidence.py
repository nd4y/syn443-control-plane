"""Bind actual ordinary/race discovery outcomes to both exact Go packages."""
import json
from pathlib import Path
import re
import sys

PREFIX = 'github.com/nd4y/syn443-control-plane/'
REQUIRED = {
    PREFIX+'internal/bootstrap': {
        'TestServiceDiscoveryServesExactSignedPublicManifestAndPreservesOtherHandlers',
        'TestServiceDiscoveryRejectsMalformedRequestsUnknownAndExpiredServices',
        'TestServiceDiscoveryOwnerDocumentIsClosedBoundedAndOwnsSignedInputs',
        'TestServiceDiscoveryRateClockAndCancellationRemainBounded',
        'TestServiceDiscoveryNormalizesWallInstantsBeforeHighWaterAdmission',
    },
    PREFIX+'cmd/enrollment-api': {
        'TestServiceDiscoveryStartupAbsentPreservesOriginalAndRequiresNoOtherDependency',
        'TestServiceDiscoveryStartupRejectsExplicitConfigurationBeforeOrdinaryInitialization',
    },
}
SOURCES = {
    PREFIX+'internal/bootstrap': 'internal/bootstrap/service_discovery_test.go',
    PREFIX+'cmd/enrollment-api': 'cmd/enrollment-api/service_discovery_startup_test.go',
}


def verify_source_names(root):
    for package, relative in SOURCES.items():
        source = (Path(root)/relative).read_text(encoding='utf-8')
        names = re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{', source, re.M)
        assert len(names) == len(set(names)), 'Repeated discovery source test'
        assert set(names) == REQUIRED[package], 'Discovery source/evidence name mismatch'


def verify(lines):
    owners = {name: package for package, names in REQUIRED.items() for name in names}
    states = {name: [] for name in owners}
    completed = {package: [] for package in REQUIRED}
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        assert isinstance(row, dict), 'Invalid discovery outcome'
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        assert isinstance(action, str) and action and isinstance(package, str) and package, 'Unbound discovery outcome'
        assert 'Test' not in row or isinstance(name, str) and name, 'Invalid discovery test identity'
        if name in owners:
            assert package == owners[name], 'Substituted discovery package'
        if package not in REQUIRED:
            continue
        assert action not in ('fail', 'skip'), 'Failed/skipped discovery package outcome'
        if name in states and action in ('run', 'pass'):
            assert not completed[package], 'Discovery outcome after package completion'
            states[name].append(action)
        elif name is None and action == 'pass':
            assert all(states[required] == ['run', 'pass'] for required in REQUIRED[package]), 'Incomplete discovery package'
            completed[package].append(action)
    assert all(value == ['run', 'pass'] for value in states.values()), 'Missing/repeated discovery case'
    assert all(value == ['pass'] for value in completed.values()), 'Discovery package did not complete exactly once'
    return len(states)


if __name__ == '__main__':
    assert len(sys.argv) == 2, 'One actual Go JSON evidence file is required'
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= 64*1024*1024, 'Invalid discovery evidence file'
    verify_source_names(Path(__file__).resolve().parent.parent)
    print(f'{verify(path.read_text(encoding="utf-8").splitlines())} actual signed-service discovery cases passed in both packages')
