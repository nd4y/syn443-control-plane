"""Require actual snapshot outcomes, not a successful 'no tests to run'."""
import json
from pathlib import Path
import sys

REQUIRED = {
    'TestAdaptiveSnapshotOwnsGraphCatalogueAndDeterministicSourceBinding',
    'TestAdaptiveSnapshotRejectsUnboundAliasesInvalidProfilesAndClosedGraph',
    'TestAdaptiveSnapshotLimitsRevocationCancellationAndContentIdentity',
    'TestAdaptiveSnapshotCopiesBeforeFurtherResolutionAndCannotPublishBlockedWork',
}
PACKAGE = 'github.com/nd4y/syn443-control-plane/internal/configuration'


def verify(lines):
    states = {name: [] for name in REQUIRED}
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        assert isinstance(row, dict), 'Invalid test record'
        if row.get('Package') != PACKAGE:
            continue
        assert row.get('Action') not in ('fail', 'skip'), 'Failed or skipped snapshot outcome'
        if row.get('Test') in states and row.get('Action') in ('run', 'pass'):
            states[row['Test']].append(row['Action'])
    assert all(state == ['run', 'pass'] for state in states.values()), 'Missing or repeated snapshot outcome'
    return len(states)


if __name__ == '__main__':
    print(f'{verify(Path(sys.argv[1]).read_text().splitlines())} required adaptive snapshot cases passed')
