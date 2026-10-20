"""Conservative privacy gate. Findings contain locations/rule names, never values.

This supplements secret scanning and human review; it cannot prove absence of PII.
Run before committing and before every public artifact upload.
"""
import argparse
import ipaddress
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = {
    "private-domain": re.compile(r"\b(?:[\w-]+\.)+(?:local|lan|internal)(?![\w.-])", re.I),
    "personal-path": re.compile(r"(?:[A-Z]:[\\/](?:Users|SynologyDrive)[\\/]|/home/(?!runner(?:/|\b))[a-z][\w-]+/)", re.I),
    "credential-url": re.compile(r"[a-z][a-z0-9+.-]*://[^\s/\"<>]+:[^\s/\"<>]+@", re.I),
}
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
TEST_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
FORBIDDEN = re.compile(r"(?:^|/)(?:\.env(?:\..*)?|local\.properties|[^/]*\.(?:jks|keystore|pem|key)|(?:bugreport|logcat|backup|diagnostic-bundle)[^/]*)$", re.I)


def findings(data):
    text = data.decode("utf-8", errors="replace")
    result = {name for name, pattern in PATTERNS.items() if pattern.search(text)}
    for match in IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match[0])
        except ValueError:
            continue
        if (address.is_private or address in ipaddress.ip_network("100.64.0.0/10")) and not (
            address.is_loopback or address.is_unspecified or any(address in net for net in TEST_NETS)
        ):
            result.add("private-address")
    return result


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def scan_history():
    problems = []
    # Every reachable blob, including deleted files and other fetched branches.
    for row in git("rev-list", "--objects", "--all").decode().splitlines():
        oid, _, name = row.partition(" ")
        if git("cat-file", "-t", oid).strip() != b"blob":
            continue
        data = git("cat-file", "blob", oid)
        rules = findings(data)
        if FORBIDDEN.search(name) and name != ".env.example":
            rules.add("private-file")
        if b"\0" in data and name != "gradle/wrapper/gradle-wrapper.jar":
            rules.add("unreviewed-binary")
        problems.extend((oid[:12] + ":" + name, rule) for rule in sorted(rules))
    for email in git("log", "--all", "--format=%ae%n%ce").decode().splitlines():
        if email and email != "noreply@github.com" and not email.endswith("@users.noreply.github.com"):
            problems.append(("commit-metadata", "personal-email"))
    problems.extend(("commit-message", rule) for rule in sorted(findings(git("log", "--all", "--format=%B"))))
    return problems


def scan_files(paths):
    problems = []
    for path in paths:
        files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for file in files:
            data = file.read_bytes()
            problems.extend((file.name, rule) for rule in sorted(findings(data)))
            if file.suffix in {".apk", ".zip"}:
                with zipfile.ZipFile(file) as archive:
                    for member in archive.infolist():
                        if not member.is_dir():
                            problems.extend((file.name + ":" + member.filename, rule)
                                            for rule in sorted(findings(archive.read(member))))
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    if not args.history and not args.paths:
        parser.error("select history or files to scan")
    problems = scan_history() if args.history else []
    problems += scan_files(args.paths)
    for location, rule in problems:
        print(f"Privacy gate: {rule}: {location}")
    if problems:
        raise SystemExit(1)
    print("Public data privacy gate passed (supplemental heuristic, not a confidentiality guarantee)")


if __name__ == "__main__":
    main()
