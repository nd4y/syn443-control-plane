"""Exercise the real pinned scanner without printing any synthetic secret values."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

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
print('Secret scanner: reviewed digest accepted; modified value and wrong path rejected')
