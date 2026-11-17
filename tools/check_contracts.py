from pathlib import Path
import hashlib,json,re
root=Path(__file__).resolve().parent.parent
lock=json.loads((root/"contracts/lock.json").read_text())
assert lock["version"]=="0.1.0"
for name,digest in lock["files"].items():
    assert re.fullmatch(r"[a-z0-9.-]+\.json",name)
    assert hashlib.sha256((root/"contracts/v1"/name).read_bytes()).hexdigest()==digest,name
data=json.loads((root/"contracts/v1/decision-vectors.json").read_text())
names=[c["name"] for c in data["cases"]+data["invalidCases"]]
assert len(names)==len(set(names))
for case in data["cases"]:
    ids={c["id"] for c in case["input"]["candidates"]}
    result=case["expected"]; order=result["orderedPathIds"]
    assert len(order)==len(set(order)) and set(order)<=ids
    assert result["selectedPathId"]==(order[0] if order else None)
    assert {r["pathId"] for r in result["rejected"]}==ids-set(order)
print(f'Contract {lock["version"]}: hashes, {len(data["cases"])} valid and {len(data["invalidCases"])} invalid fixtures verified')


route_graph=json.loads((root/"contracts/v1/route-graph-vectors.json").read_text())
assert route_graph["schemaVersion"]==1
route_names=[c["name"] for c in route_graph["validCases"]+route_graph["invalidCases"]]
assert len(route_names)==len(set(route_names)) and len(route_graph["invalidCases"])>=60
assert {"route-graph.schema.json","route-graph-vectors.json"} <= lock["files"].keys()
print("Closed route graph: shared positive/negative contract fixtures locked")

profile_name="route-check-profile-v2"
assert {profile_name+".schema.json",profile_name+"-vectors.json"} <= lock["files"].keys()
profiles=json.loads((root/"contracts/v1"/(profile_name+"-vectors.json")).read_text())
assert profiles["schemaVersion"]==1
groups=("validCases","invalidCases","invalidRawCases","truthCases","legacyCases")
profile_names=[case["name"] for group in groups for case in profiles[group]]
assert len(profile_names)==len(set(profile_names))
assert all(re.fullmatch(r"[A-Za-z0-9-]{1,100}",name) for name in profile_names)
assert len(profiles["validCases"])>=9 and len(profiles["invalidCases"])>=37
assert len(profiles["invalidRawCases"])>=6 and len(profiles["truthCases"])>=51
assert {"any-two","all-two","quorum-two-of-three","sequential-stages",
        "unconditional-security-gates","unordered-leaves-ordered-branches",
        "html-escape-canonical-hash"} <= {case["name"] for case in profiles["validCases"]}
for case in profiles["validCases"]+profiles["legacyCases"]:
    assert re.fullmatch(r"[0-9a-f]{64}",case["sha256"])
for case in profiles["invalidRawCases"]:
    assert isinstance(case["raw"],str) and 0<len(case["raw"].encode())<=24000
for case in profiles["truthCases"]:
    leaves={leaf["id"] for leaf in case["profile"]["leaves"]}
    assert set(case["results"])==set(case["leafStates"])==leaves
    assert len(case["visited"])==len(set(case["visited"]))
    assert set(case["visited"])<=leaves and case["expected"] in {"TRUE","FALSE","UNKNOWN"}
    assert set(case["results"].values())<={"TRUE","FALSE","UNKNOWN"}
    assert set(case["leafStates"].values())<={"TRUE","FALSE","UNKNOWN","SKIPPED"}
    assert {key for key,value in case["leafStates"].items() if value!="SKIPPED"}==set(case["visited"])
print("Bounded route check profile: common syntax, truth and legacy-hash fixtures locked")

# Keep the actual authenticated HTTP Action schema in sync without external refs.
profile_schema=json.loads((root/"contracts/v1/route-check-profile-v2.schema.json").read_text())
profile_api=json.loads((root/"contracts/v1/control-openapi.json").read_text())["components"]["schemas"]
profile_refs={"check":"RouteCheckProfileV2Check","leaf":"RouteCheckProfileV2Leaf","expr":"RouteCheckProfileV2Expr"}
def profile_api_value(value):
    if isinstance(value,dict):return {key:profile_api_value(item) for key,item in value.items()}
    if isinstance(value,list):return [profile_api_value(item) for item in value]
    if isinstance(value,str) and value.startswith("#/$defs/"):
        return "#/components/schemas/"+profile_refs[value.removeprefix("#/$defs/")]
    return value
assert profile_api["RouteCheckProfileV2"]==profile_api_value({key:value for key,value in profile_schema.items() if key not in {"$schema","$id","$defs"}})
for key,value in profile_schema["$defs"].items():
    assert profile_api[profile_refs[key]]==profile_api_value(value)
profile_row=profile_api["PlanOutboundChecks"]
assert profile_row["additionalProperties"] is False and profile_row["required"]==["outbound","required"]
assert profile_row["properties"]["profile"]=={"$ref":"#/components/schemas/RouteCheckProfileV2"}
assert profile_row["oneOf"]==[{"required":["checks"],"not":{"required":["profile"]}},{"required":["profile"],"not":{"required":["checks"]}}]
print("HTTP control Action uses the same closed check profile and exact XOR row")
