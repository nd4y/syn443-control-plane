"""Require the six actual PostgreSQL refresh-boundary outcomes and completion."""
import json
from pathlib import Path
import re
import sys

PACKAGE = 'github.com/nd4y/syn443-control-plane/internal/enrollment'
SOURCE = 'internal/enrollment/session_boundary_postgres_test.go'
REQUIRED = frozenset({
    'TestRefreshBoundaryLastTenMinutesCapsAccessAtAbsoluteFamilyDeadline',
    'TestRefreshBoundaryUsesCurrentLockedDeadlineAfterLookupSnapshotBecomesStale',
    'TestRefreshBoundaryShorterCurrentAccountStillCapsAccessWithoutRenewingFamily',
    'TestRefreshBoundaryAtOrPastRefreshOrAccountDeadlineDeniesWithoutRotation',
    'TestRefreshBoundaryEarlyAndLateCachedReplaysKeepExactSessionAndGeneration',
    'TestRefreshBoundaryRepeatedFreshRotationsNeverExtendAbsoluteFamily',
})


def verify_source_names(root):
    source = (Path(root)/SOURCE).read_text(encoding='utf-8')
    assert re.search(r'^//go:build postgres$', source, re.M), 'PostgreSQL source guard missing'
    assert re.search(r'^package enrollment$', source, re.M), 'Substituted refresh-boundary source package'
    names = re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{', source, re.M)
    assert len(names) == len(set(names)), 'Repeated refresh-boundary source root'
    assert len(names) == 6 and set(names) == REQUIRED, 'Refresh-boundary source/evidence name mismatch'


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'Duplicate evidence field'
        result[key] = value
    return result


def invalid_constant(_value):
    raise AssertionError('Non-JSON evidence number')


def verify(lines):
    states = {name: [] for name in REQUIRED}
    completed = []
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line, object_pairs_hook=closed_pairs, parse_constant=invalid_constant)
        assert isinstance(row, dict), 'Invalid refresh-boundary outcome'
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        assert isinstance(action, str) and action and isinstance(package, str) and package, 'Unbound refresh-boundary outcome'
        assert 'Test' not in row or isinstance(name, str) and name, 'Invalid refresh-boundary test identity'
        assert action not in ('fail', 'skip', 'error', 'build-fail'), 'Failed/skipped/error enrollment evidence'
        assert row.get('Error') in (None, ''), 'Error in enrollment evidence'
        if name in REQUIRED:
            assert package == PACKAGE, 'Substituted refresh-boundary package'
        if package != PACKAGE:
            continue
        if isinstance(name, str) and name.startswith('TestRefreshBoundary') and '/' not in name:
            assert name in REQUIRED, 'Unregistered refresh-boundary root'
        if name in states and action in ('run', 'pass'):
            assert not completed, 'Refresh-boundary outcome after package completion'
            states[name].append(action)
        elif name is None and action == 'pass':
            assert all(value == ['run', 'pass'] for value in states.values()), 'Incomplete enrollment package'
            completed.append(action)
    assert all(value == ['run', 'pass'] for value in states.values()), 'Missing/repeated/out-of-order refresh-boundary root'
    assert completed == ['pass'], 'Enrollment package did not complete exactly once'
    return len(states)


if __name__ == '__main__':
    assert len(sys.argv) == 2, 'One actual Go JSON evidence file is required'
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= 64*1024*1024, 'Invalid refresh-boundary evidence file'
    verify_source_names(Path(__file__).resolve().parent.parent)
    print(f'{verify(path.read_text(encoding="utf-8").splitlines())} actual PostgreSQL refresh-boundary roots passed')
