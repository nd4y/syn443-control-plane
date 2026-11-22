"""Retain only the named successful outcomes from the disposable Keycloak realm."""
import json
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
    for line in lines:
        if not line.startswith("{"):
            continue
        event = json.loads(line)
        if event.get("Package") != PACKAGE:
            continue
        action = event.get("Action")
        name = event.get("Test")
        if action == "fail" or action == "skip" and name in events:
            raise ValueError("required Keycloak outcome failed or skipped")
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
