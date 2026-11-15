"""Require package-bound actual country-check outcomes from full CI suites."""
import argparse
import json
from pathlib import Path

PREFIX = 'github.com/nd4y/syn443-control-plane/internal/'
REQUIRED = {
    'core': {
        'TestExitCountryNetworkCompilerKeepsExplicitExpectedClass': PREFIX + 'configuration',
        'TestExitCountryNetworkCompilerRejectsAmbiguousTargetsAndPredicates': PREFIX + 'configuration',
        'TestExitCountryDecoderDoesNotDiscardCrossMethodNullOrEmptyFields': PREFIX + 'configuration',
        'TestInternalFailoverCannotUsePublicExitCountryAsInternalEvidence': PREFIX + 'configuration',
        'TestExitCountryOpenAPIClosesMethodSpecificPredicateFields': PREFIX + 'configuration',
        'TestExitCountryRequiresExactCapabilityAndKeyBoundHealthConfiguration': PREFIX + 'policy',
        'TestExitCountryPolicySchemaRequiresKeyBoundHealthConfigure': PREFIX + 'policy',
        'TestExitCountryCannotBypassAddressedDeviceApprovalOrNegotiation': PREFIX + 'enrollment',
    },
    'postgres': {
        'TestSQLExitCountryRequiresNegotiatedPrimitiveAndPreservesBothPredicates': PREFIX + 'deviceprovisioning',
    },
}


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
        assert action not in ('fail', 'skip'), 'Failed or skipped country package outcome'
        if name in states and action in ('run', 'pass'):
            states[name].append(action)
        elif not name and action == 'pass':
            packages[package].append(action)
    assert all(state == ['run', 'pass'] for state in states.values()), 'Missing, repeated or out-of-order country outcome'
    assert all(state == ['pass'] for state in packages.values()), 'Missing or repeated successful package completion'
    return len(states)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--stage', required=True, choices=tuple(REQUIRED))
    args = parser.parse_args()
    print(f'{verify(args.path.read_text().splitlines(), args.stage)} required exit-country {args.stage} cases passed')
