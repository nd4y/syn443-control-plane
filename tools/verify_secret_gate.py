"""Exercise the real pinned scanner without printing any synthetic secret values."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

root = Path(__file__).resolve().parent.parent
scanner = str(Path(sys.argv[1]).resolve())
config = root / '.gitleaks.toml'
digest = json.loads((root / 'contracts/lock.json').read_text())['files']['openapi.json']
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    subprocess.run(['git', 'init', '-q', str(work)], check=True)
    (work / 'contracts').mkdir()
    target = work / 'contracts/lock.json'
    def scan(expected):
        subprocess.run(['git', '-C', str(work), 'add', '.'], check=True)
        result = subprocess.run([scanner, 'git', '.', '--pre-commit', '--staged',
                                 '--config', str(config), '--redact=100', '--no-banner'],
                                cwd=work, capture_output=True)
        assert result.returncode == expected, 'Secret gate test outcome mismatch'
    target.write_text(json.dumps({'openapi.json': digest}, indent=2))
    scan(0)
    # Changing one byte must remove the narrowly reviewed exemption.
    target.write_text(json.dumps({'openapi.json': ('0' if digest[0] != '0' else '1') + digest[1:]}, indent=2))
    scan(1)
    target.unlink()
    (work / 'unreviewed.json').write_text(json.dumps({'openapi.json': digest}, indent=2))
    scan(1)
    policy_digest = json.loads((root / 'contracts/lock.json').read_text())['files']['policy-openapi.json']
    (work / 'unreviewed.json').unlink()
    target.write_text(json.dumps({'policy-openapi.json': policy_digest}, indent=2))
    scan(0)
    target.write_text(json.dumps({'policy-openapi.json': ('0' if policy_digest[0] != '0' else '1') + policy_digest[1:]}, indent=2))
    scan(1)
    target.unlink()
    (work / 'unreviewed.json').write_text(json.dumps({'policy-openapi.json': policy_digest}, indent=2))
    scan(1)
    enrollment_digest = json.loads((root / 'contracts/lock.json').read_text())['files']['enrollment-openapi.json']
    (work / 'unreviewed.json').unlink()
    target.write_text(json.dumps({'enrollment-openapi.json': enrollment_digest}, indent=2))
    scan(0)
    target.write_text(json.dumps({'enrollment-openapi.json': ('0' if enrollment_digest[0] != '0' else '1') + enrollment_digest[1:]}, indent=2))
    scan(1)
    target.unlink()
    (work / 'unreviewed.json').write_text(json.dumps({'enrollment-openapi.json': enrollment_digest}, indent=2))
    scan(1)
    (work / 'unreviewed.json').unlink()
    # The signature fixture has a public RFC7638 hash, not an API credential.
    # Exercise the actual recursive-hex decoder; changed value/other path still fail.
    fixture = json.loads((root / 'contracts/v1/policy-device-signature.json').read_text())
    fixture_path = work / 'contracts/v1/policy-device-signature.json'
    fixture_path.parent.mkdir()
    fixture_path.write_text(json.dumps(fixture, indent=2))
    scan(0)
    payload = json.loads(bytes.fromhex(fixture['payloadHex']))
    digest_value = payload['keyThumbprint']
    payload['keyThumbprint'] = ('A' if digest_value[0] != 'A' else 'B') + digest_value[1:]
    changed = dict(fixture)
    changed['payloadHex'] = json.dumps(payload, separators=(',', ':')).encode().hex()
    fixture_path.write_text(json.dumps(changed, indent=2))
    scan(1)
    fixture_path.unlink()
    (work / 'unreviewed.json').write_text(json.dumps(fixture, indent=2))
    scan(1)
    # A detector must inspect APK assets rather than silently skip the binary container.
    for suffix in ('apk', 'aar'):
        apk = work / ('synthetic.' + suffix)
        for payload, expected in (({'safe': 'synthetic'}, 0), ({'openapi.json': digest}, 1)):
            with zipfile.ZipFile(apk, 'w') as z:
                z.writestr('assets/synthetic.json', json.dumps(payload, indent=2))
            result = subprocess.run([sys.executable, str(root / 'tools/check_apk_secrets.py'), scanner, str(apk)],
                                    capture_output=True)
            assert (result.returncode != 0) == bool(expected), suffix + ' asset scanner test outcome mismatch'
print('Secret scanner: exact digest exception and APK/AAR asset detection verified')
