"""Retain only the named successful outcomes from the disposable Keycloak realm."""
import json
import re
from pathlib import Path
import sys

PACKAGE = "github.com/nd4y/syn443-control-plane/integration/keycloak"
ROOTS = (
    "TestSupportWebBFFWithActualKeycloakPKCEAndDPoP",
    "TestControlWebReauthenticationWithActualKeycloakOTPAndAssuranceClaims",
)
REQUIRED = [name for root in ROOTS for name in (root, root + "/packaged_web_readiness_and_embedded_assets")]
REQUIRED += ["TestTwoOwnersReceiveOnlyTheirAssignedDevicePolicies",
             "TestTwoOwnersReceiveOnlyTheirAssignedDevicePolicies/key_bound_publications",
             "TestTwoOwnersReceiveOnlyTheirAssignedDevicePolicies/other_device_keys_denied"]


def report(lines):
    events = {name: [] for name in REQUIRED}
    package = []
    locations = {}
    # Retain public test source locations and status codes only. Go test output
    # can otherwise include a fixture token, response body or provider URL.
    source_line = re.compile(r"^\s*((?:keycloak|personal_issuance|chat_web|packaged_web|control_reauthentication)_test\.go:[0-9]{1,5}):")
    for line in lines:
        if not line.startswith("{"):
            continue
        event = json.loads(line)
        if event.get("Package") != PACKAGE:
            continue
        action = event.get("Action")
        name = event.get("Test")
        if action == "output":
            output = event.get("Output", "")
            frame = source_line.match(output)
            if frame:
                location = frame[1]
                http_status = re.search(r"HTTP status ([0-9]{3}), expected ([0-9]{3})", output)
                sql_state = re.search(r"SQLSTATE ([A-Z0-9]{5})", output)
                if http_status:
                    location += f" (HTTP {http_status[1]}, expected {http_status[2]})"
                elif sql_state:
                    location += f" (SQLSTATE {sql_state[1]})"
                locations[name] = location
        if action == "fail" or action == "skip" and name in events:
            safe_name = name if name in events else "Keycloak fixture"
            raise ValueError(f"{safe_name} {action} at {locations.get(name, 'unspecified source')}")
        if name in events and action in ("run", "pass"):
            events[name].append(action)
        if name is None and action in ("start", "pass"):
            package.append(action)
    if package != ["start", "pass"] or any(outcome != ["run", "pass"] for outcome in events.values()):
        raise ValueError("packaged Keycloak outcomes missing or duplicated")
    return {"schemaVersion": 1, "package": PACKAGE, "passed": REQUIRED}


if __name__ == "__main__":
    result = report(sys.stdin)
    with Path(sys.argv[1]).open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
    print("Verified packaged web, real Keycloak flows and personal policy issuance")
