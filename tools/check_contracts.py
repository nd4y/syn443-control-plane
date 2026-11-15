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
