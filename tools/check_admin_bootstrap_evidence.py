"""Require actual signed admin metadata outcomes in the complete Go suite."""
import json
from pathlib import Path
import sys

PACKAGE = 'github.com/nd4y/syn443-control-plane/internal/bootstrap'
REQUIRED = {
    'TestAdminBootstrapSchemaClosesFieldsAndPreservesManifestBudgets',
    'TestSharedAdminBootstrapVectorsRequireClosedObjectAndKeepLegacySignedBytes',
    'TestSignedAdminBootstrapKeepsDeviceProjectionAndRequiresRevisionAdvance',
    'TestSignedAdminBootstrapTamperRemovalAndRevisionFences',
}


def verify(lines):
    states = {name: [] for name in REQUIRED}
    completed = []
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        assert isinstance(row, dict), 'Invalid admin-bootstrap outcome'
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        assert isinstance(action, str) and isinstance(package, str), 'Unbound admin-bootstrap outcome'
        assert name is None or isinstance(name, str), 'Invalid admin-bootstrap case'
        if name in REQUIRED:
            assert package == PACKAGE, 'Substituted admin-bootstrap package'
        if package != PACKAGE:
            continue
        assert action not in ('fail', 'skip'), 'Failed/skipped admin-bootstrap outcome'
        if name in REQUIRED and action in ('run', 'pass'):
            states[name].append(action)
        elif name is None and action == 'pass':
            completed.append(action)
    assert all(value == ['run', 'pass'] for value in states.values()), 'Missing/repeated admin-bootstrap case'
    assert completed == ['pass'], 'Queue-mode package did not finish once'
    return len(states)


if __name__ == '__main__':
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= 64*1024*1024
    print(f'{verify(path.read_text().splitlines())} actual enrollment admin-bootstrap cases passed')
