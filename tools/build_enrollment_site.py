"""Generate a static invitation fallback and Android Digital Asset Links."""
import argparse
from html import escape
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


FINGERPRINT = re.compile(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}")
DNS_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
PACKAGE = "io.syn443.android"


def build_site(destination: Path, apk_url: str, fingerprints: list[str]) -> None:
    if not 1 <= len(apk_url) <= 2048 or not all(33 <= ord(char) <= 126 for char in apk_url):
        raise ValueError("invalid install URL")
    url = urlsplit(apk_url)
    host = url.hostname or ""
    if (url.scheme != "https" or url.netloc != host or len(host) > 253 or not DNS_HOST.fullmatch(host)
            or not url.path.startswith("/") or url.path == "/"
            or "?" in apk_url or "#" in apk_url or "\\" in apk_url):
        raise ValueError("invalid install URL")
    if (not 1 <= len(fingerprints) <= 8 or len(set(fingerprints)) != len(fingerprints)
            or any(not FINGERPRINT.fullmatch(value) for value in fingerprints)):
        raise ValueError("invalid app signing fingerprints")

    association = [{
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {
            "namespace": "android_app",
            "package_name": PACKAGE,
            "sha256_cert_fingerprints": sorted(fingerprints),
        },
    }]
    landing = f"""<!doctype html>
<html lang="ru">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Приглашение SYN443</title>
<main>
  <h1>Приглашение SYN443</h1>
  <p>Установите приложение и снова откройте исходную ссылку с приглашением.</p>
  <p><a href="{escape(apk_url, quote=True)}" rel="noreferrer">Установить SYN443 для Android</a></p>
</main>
</html>
"""
    destination.mkdir(exist_ok=False)
    (destination / ".well-known").mkdir()
    (destination / ".well-known/assetlinks.json").write_text(
        json.dumps(association, indent=2) + "\n", encoding="utf-8")
    (destination / "enroll.html").write_text(landing, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--apk-url", required=True)
    parser.add_argument("--sha256", required=True, action="append")
    args = parser.parse_args()
    try:
        build_site(args.destination, args.apk_url, args.sha256)
    except (OSError, ValueError):
        parser.exit(2, "Could not generate enrollment site assets.\n")


if __name__ == "__main__":
    main()
