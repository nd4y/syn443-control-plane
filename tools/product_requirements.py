"""Compare the two component registers against the same normative inventory."""

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATUSES = {"planned", "partial", "implemented", "verified"}
COLUMNS = ("both", "android", "control", "neither")


def index(items, text_key):
    result = {}
    for item in items:
        item_id = item["id"]
        if item_id in result:
            raise ValueError(f"duplicate item {item_id}")
        status = item["status"]
        if status not in STATUSES or (status != "planned" and not item["evidence"]):
            raise ValueError(f"invalid evidence status for {item_id}")
        if not item[text_key].strip():
            raise ValueError(f"missing normative text for {item_id}")
        result[item_id] = item
    return result


def compare(android, control):
    if android["specVersion"] != control["specVersion"]:
        raise ValueError("different specification versions")
    rows = []
    for section, text_key in (("requirements", "text"), ("acceptanceCases", "specRow")):
        left = index(android[section], text_key)
        right = index(control[section], text_key)
        if left.keys() != right.keys():
            raise ValueError(f"different item IDs in {section}")
        for item_id, server in right.items():
            phone = left[item_id]
            if phone[text_key] != server[text_key]:
                raise ValueError(f"different normative text for {item_id}")
            a, c = phone["status"], server["status"]
            evidence = {(True, True): "both", (True, False): "android",
                        (False, True): "control", (False, False): "neither"}
            rows.append((section, item_id, a, c, evidence[a != "planned", c != "planned"]))
    return rows


def table_row(label, counts):
    return "| " + " | ".join([label, str(sum(counts.values())),
                               *(str(counts[column]) for column in COLUMNS)]) + " |"


def markdown(version, revision, rows):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("pin an immutable Android Git revision")
    totals = defaultdict(Counter)
    areas = defaultdict(Counter)
    for section, item_id, _, _, coverage in rows:
        totals[section][coverage] += 1
        if section == "requirements":
            areas[item_id.split("-")[0]][coverage] += 1
    header = "| Scope | Total | Both | Android only | Control Plane only | Neither |"
    rule = "| --- | ---: | ---: | ---: | ---: | ---: |"
    lines = [
        "# SYN443 product requirements", "",
        f"Specification {version}. Each item appears once. The columns show which component registers link evidence for a status above `planned`. A partial implementation counts in its component. Product acceptance requires the checks specified for that item.", "",
        header, rule, table_row("Requirements", totals["requirements"]),
        table_row("Acceptance scenarios", totals["acceptanceCases"]), "",
        "## Requirement families", "", header, rule,
        *(table_row(area, counts) for area, counts in areas.items()), "",
        "## Trace an item", "",
        "Download `product-requirements` from the CI run for this Control Plane revision. The CSV lists every requirement and acceptance scenario with both original status values. Look up the item ID in its component register for evidence and remaining scope.", "",
        "- [Control Plane register](requirements-register.json)",
        f"- [Android register at {revision[:12]}](https://github.com/nd4y/syn443-android/blob/{revision}/docs/requirements-register.json)",
        "- [Technical specification](spec/TECHNICAL_SPEC_RU.md)",
        "- [Live and release acceptance records](implementation-status.md)", "",
        "To refresh Android coverage, update `docs/android-register-revision.txt` to a reviewed revision. Regenerate this page with `python3 tools/product_requirements.py /path/to/android/docs/requirements-register.json --write`. The documents job compares it with the pinned source on every run.", "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("android_register", type=Path)
    parser.add_argument("--write", action="store_true", help="update the Markdown snapshot")
    parser.add_argument("--csv", type=Path, help="write the item-level CI artifact")
    args = parser.parse_args()
    control = json.loads((ROOT / "docs/requirements-register.json").read_text(encoding="utf-8"))
    android = json.loads(args.android_register.read_text(encoding="utf-8"))
    rows = compare(android, control)
    revision = (ROOT / "docs/android-register-revision.txt").read_text().strip()
    report = markdown(control["specVersion"], revision, rows)
    snapshot = ROOT / "docs/product-requirements.md"
    if args.write:
        snapshot.write_bytes(report.encode("utf-8"))
    elif snapshot.read_text(encoding="utf-8") != report:
        parser.exit(1, "Product requirements snapshot is stale. Regenerate with --write.\n")
    if args.csv:
        with args.csv.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(("section", "id", "android_status", "control_plane_status", "component_evidence"))
            writer.writerows(rows)


if __name__ == "__main__":
    main()
