"""Make APK ZIP containers visible to Gitleaks, which skips .apk files as binary."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    scanner = str(Path(sys.argv[1]).resolve())
    apks = []
    for value in sys.argv[2:]:
        path = Path(value)
        apks += list(path.rglob('*.apk')) if path.is_dir() else ([path] if path.suffix == '.apk' else [])
    if not apks:
        return
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory)
        for index, apk in enumerate(sorted(set(apks))):
            # Scan identical bytes as ZIP; archive recursion inspects embedded assets.
            shutil.copyfile(apk, target / f'payload-{index}.zip')
        subprocess.run([scanner, 'dir', str(target), '--config', str(root / '.gitleaks.toml'),
                        '--redact=100', '--no-banner', '--max-archive-depth=3'], check=True)


if __name__ == '__main__':
    main()
