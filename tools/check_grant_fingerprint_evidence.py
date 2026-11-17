"""Require exact native grant-fingerprint CLI outcomes in the complete Go log."""
import json
from pathlib import Path
import re
import sys

PACKAGE = 'github.com/nd4y/syn443-control-plane/cmd/enrollment-admin'
SOURCE = 'cmd/enrollment-admin/grant_fingerprint_test.go'
REQUIRED = frozenset({
    'TestGrantFingerprintMatchesNativeOwnerHashAndExactClosedMetadata',
    'TestGrantFingerprintRejectsUnknownDuplicateExpiredAndInvalidNativeTemplates',
    'TestGrantFingerprintBoundsFullStdinDocumentCountTrailingBytesAndPostReadClock',
    'TestGrantFingerprintRejectsDuplicateOwnersEvenWhenTheirGrantHashesDiffer',
    'TestGrantFingerprintValidatesEveryGrantBeforeOneWriteAndKeepsErrorsFinite',
    'TestGrantFingerprintActualEarlyCommandNeedsNoConfigEnvironmentOrDatabase',
})


def verify_source_names(root):
    source = (Path(root)/SOURCE).read_text(encoding='utf-8')
    assert re.search(r'^package main$', source, re.M), 'Substituted fingerprint source package'
    names = re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{', source, re.M)
    assert len(names) == len(set(names)), 'Repeated fingerprint source root'
    assert len(names) == 6 and set(names) == REQUIRED, 'Fingerprint source/evidence name mismatch'


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'Duplicate fingerprint evidence field'
        result[key] = value
    return result


def invalid_constant(_value):
    raise AssertionError('Non-JSON fingerprint evidence number')


def verify(lines):
    states = {name: [] for name in REQUIRED}
    completed = []
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line, object_pairs_hook=closed_pairs, parse_constant=invalid_constant)
        assert isinstance(row, dict), 'Invalid fingerprint outcome'
        action, package, name = row.get('Action'), row.get('Package'), row.get('Test')
        assert isinstance(action, str) and action and isinstance(package, str) and package, 'Unbound fingerprint outcome'
        assert 'Test' not in row or isinstance(name, str) and name, 'Invalid fingerprint test identity'
        if name in REQUIRED:
            assert package == PACKAGE, 'Substituted fingerprint package'
        if package != PACKAGE:
            continue
        assert action not in ('fail', 'skip', 'error', 'build-fail'), 'Failed/skipped/error fingerprint package'
        assert row.get('Error') in (None, ''), 'Error in fingerprint package'
        if isinstance(name, str) and name.startswith('TestGrantFingerprint') and '/' not in name:
            assert name in REQUIRED, 'Unregistered fingerprint root'
        if name in states and action in ('run', 'pass'):
            assert not completed, 'Fingerprint outcome after package completion'
            states[name].append(action)
        elif name is None and action == 'pass':
            assert all(value == ['run', 'pass'] for value in states.values()), 'Incomplete fingerprint package'
            completed.append(action)
    assert all(value == ['run', 'pass'] for value in states.values()), 'Missing/repeated/out-of-order fingerprint root'
    assert completed == ['pass'], 'Fingerprint package did not complete exactly once'
    return len(states)


if __name__ == '__main__':
    assert len(sys.argv) == 2, 'One actual Go JSON evidence file is required'
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= 64*1024*1024, 'Invalid fingerprint evidence file'
    verify_source_names(Path(__file__).resolve().parent.parent)
    print(f'{verify(path.read_text(encoding="utf-8").splitlines())} actual native grant-fingerprint CLI roots passed')
