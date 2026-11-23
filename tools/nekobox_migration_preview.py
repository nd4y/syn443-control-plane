"""Summarize a local nekoctl full export before provisioning in SYN443."""

import json
from pathlib import Path
import sys


MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 20_000
PROFILES = ("http", "socks", "vless", "vless_xhttp", "ssh", "netbird", "chain", "proxyset", "other")
DESTINATIONS = ("active_profile", "direct", "block", "profile_reference", "missing_reference", "unknown")


class InvalidExport(ValueError):
    pass


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidExport()
        result[key] = value
    return result


def invalid_number(_):
    raise InvalidExport()


def integer(value):
    return type(value) is int and -(2**63) <= value < 2**63


def rows(config, name):
    value = config.get(name)
    if not isinstance(value, list) or len(value) > MAX_ROWS:
        raise InvalidExport()
    seen = set()
    for row in value:
        if not isinstance(row, dict) or not integer(row.get("id")) or row["id"] <= 0 or row["id"] in seen:
            raise InvalidExport()
        seen.add(row["id"])
    return value, seen


def summarize_groups(groups, group_ids, profiles, profile_ids):
    counts = {"total": len(groups), "subscription_groups": 0, "missing_subscription_details": 0,
              "selector_groups": 0, "group_proxy_links": 0, "missing_group_proxy_links": 0}
    for group in groups:
        if not integer(group.get("type")) or type(group.get("isSelector", False)) is not bool:
            raise InvalidExport()
        counts["subscription_groups"] += group["type"] == 1
        counts["missing_subscription_details"] += group["type"] == 1 and not isinstance(group.get("subscription"), dict)
        counts["selector_groups"] += group.get("isSelector", False)
        for key in ("frontProxy", "landingProxy"):
            link = group.get(key, -1)
            if not integer(link):
                raise InvalidExport()
            counts["group_proxy_links"] += link > 0
            counts["missing_group_proxy_links"] += link > 0 and link not in profile_ids
    counts["profiles_without_group"] = sum(p["groupId"] not in group_ids for p in profiles)
    return counts


def summarize_profiles(profiles, known, selected_profile):
    counts = dict.fromkeys(PROFILES, 0)
    missing_chain_hops = 0
    for profile in profiles:
        group, protocol, values = profile.get("groupId"), profile.get("protocol"), profile.get("values")
        if not integer(group) or not isinstance(protocol, str) or not protocol or not isinstance(values, dict):
            raise InvalidExport()
        category = protocol if protocol in PROFILES and protocol != "vless_xhttp" else "other"
        if protocol == "vless" and values.get("type") in ("xhttp", "splithttp"):
            category = "vless_xhttp"
        counts[category] += 1
        if category == "chain":
            links = values.get("proxies", [])
            if not isinstance(links, list) or len(links) > MAX_ROWS or not all(integer(link) for link in links):
                raise InvalidExport()
            missing_chain_hops += sum(link not in known for link in links)
    return {"by_kind": counts, "missing_chain_hops": missing_chain_hops,
            "active_profile_present": selected_profile in known}


def summarize_rules(rules, known):
    destinations = dict.fromkeys(DESTINATIONS, 0)
    special = {"wifi_identity": 0, "rule_set": 0, "custom_rule": 0, "application": 0}
    named_outbound = {0:"active_profile", -1:"direct", -2:"block"}
    enabled = 0
    for rule in rules:
        if type(rule.get("enabled")) is not bool or not integer(rule.get("outbound")):
            raise InvalidExport()
        if not rule["enabled"]:
            continue
        enabled += 1
        outbound = rule["outbound"]
        if outbound > 0:
            destinations["profile_reference" if outbound in known else "missing_reference"] += 1
        else:
            destinations[named_outbound.get(outbound, "unknown")] += 1
        special["wifi_identity"] += bool(rule.get("wifiSsid") or rule.get("wifiBssid"))
        special["rule_set"] += bool(rule.get("ruleset"))
        special["custom_rule"] += bool(rule.get("config"))
        special["application"] += bool(rule.get("packages"))
    return {"enabled": enabled, "disabled": len(rules) - enabled, "by_destination": destinations,
            "enabled_with_features": special}


def preview(raw):
    if not 1 <= len(raw) <= MAX_EXPORT_BYTES:
        raise InvalidExport()
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields, parse_constant=invalid_number)
    if (not isinstance(doc, dict) or set(doc) != {"schema", "schemaVersion", "revision", "config"}
            or doc["schema"] != "nekobox.full-config" or type(doc["schemaVersion"]) is not int
            or doc["schemaVersion"] != 1 or not isinstance(doc["revision"], str)
            or not isinstance(doc["config"], dict)):
        raise InvalidExport()
    config = doc["config"]
    if (set(config) != {"groups", "profiles", "rules", "preferences", "selectedProfile"}
            or not isinstance(config["preferences"], dict) or not integer(config["selectedProfile"])):
        raise InvalidExport()
    groups, group_ids = rows(config, "groups")
    profiles, profile_ids = rows(config, "profiles")
    rules, _ = rows(config, "rules")
    profiles_summary = summarize_profiles(profiles, profile_ids, config["selectedProfile"])
    return {"schema_version": 1, "status": "review_required", "groups": summarize_groups(groups, group_ids, profiles, profile_ids),
            "profiles": profiles_summary, "rules": summarize_rules(rules, profile_ids),
            "preferences_require_review": len(config["preferences"])}


def main(args):
    if len(args) != 1:
        print("Usage: python tools/nekobox_migration_preview.py EXPORT.json (or - for stdin).", file=sys.stderr)
        return 2
    try:
        if args[0] == "-":
            raw = sys.stdin.buffer.read(MAX_EXPORT_BYTES + 1)
        else:
            with Path(args[0]).open("rb") as source:
                raw = source.read(MAX_EXPORT_BYTES + 1)
        result = preview(raw)
    except (OSError, ValueError, RecursionError):
        print("Expected a bounded nekoctl full export, schema version 1.", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
