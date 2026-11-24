"""Check the release inventory against the pinned Android source inputs."""

import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REVISION = re.compile(r"[a-f0-9]{40}")


def exact_field(source, pattern):
    values = re.findall(pattern, source, re.MULTILINE)
    if len(values) != 1:
        raise ValueError("Android package metadata must contain one literal per field")
    return values[0]


def catalogue(android, revision):
    if not REVISION.fullmatch(revision):
        raise ValueError("Invalid pinned Android revision")
    gradle = (android / "app/build.gradle.kts").read_text(encoding="utf-8")
    code = int(exact_field(gradle, r"^\s*versionCode[ \t]*=[ \t]*([1-9][0-9]{0,9})[ \t]*$"))
    if code > 2_100_000_000:
        raise ValueError("Android version code out of range")
    name = exact_field(gradle, r'^\s*versionName[ \t]*=[ \t]*"([A-Za-z0-9][A-Za-z0-9._-]{0,79})"[ \t]*$')
    locks = json.loads((android / "native/engine-lock.json").read_bytes())["sources"]
    engines = {}
    for lock_name, label in (("sing-box", "sing-box"), ("netbird", "NetBird")):
        pinned = locks[lock_name]["revision"]
        if not isinstance(pinned, str) or not REVISION.fullmatch(pinned):
            raise ValueError("Invalid engine source revision")
        engines[label] = pinned
    return json.dumps(dict(androidRevision=revision, versionCode=code, versionName=name,
                           engines=engines), indent=2) + "\n"


def check_inventory(path, expected):
    if path.read_text(encoding="utf-8") != expected:
        raise ValueError("Console engine inventory differs from the pinned Android build")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("android", type=Path, help="Checkout of the pinned Android revision")
    parser.add_argument("--write", action="store_true", help="Regenerate the console inventory")
    args = parser.parse_args()
    pin = (ROOT / "docs/android-register-revision.txt").read_text(encoding="ascii").strip()
    path = ROOT / "console-ui/android-engine-build.json"
    try:
        expected = catalogue(args.android, pin)
        if args.write:
            path.write_bytes(expected.encode("utf-8"))
        else:
            check_inventory(path, expected)
    except (ValueError, OSError, KeyError, TypeError) as err:
        parser.exit(1, f"Android engine inventory: {err}\n")
    print("Console engine inventory matches the pinned Android build.")


if __name__ == "__main__":
    main()
