from pathlib import Path
import hashlib,json,re
root=Path(__file__).resolve().parent.parent
spec=(root/"docs/spec/TECHNICAL_SPEC_RU.md").read_text(encoding="utf-8")
manifest=json.loads((root/"docs/spec/source-manifest.json").read_text())
for name,digest in manifest["files"].items():
    assert hashlib.sha256((root/"docs/spec"/name).read_bytes()).hexdigest()==digest, name
assert manifest["specVersion"] == "0.8"
assert "Версия 0.8 от 21 октября 2026 года." in spec
ids=re.findall(r"^([A-Z]+-\d{2})\.",spec,re.M)
cases=re.findall(r"^\| AC(\d+) \|",spec,re.M)
assert len(ids)==len(set(ids))==277
assert list(map(int,cases))==list(range(1,91))
assert "managedvpn://" not in spec and "marshrut://" not in spec
register=json.loads((root/"docs/requirements-register.json").read_text(encoding="utf-8"))
assert [r["id"] for r in register["requirements"]]==ids
assert [r["id"] for r in register["acceptanceCases"]]==["AC"+n for n in cases]
assert register["specVersion"] == manifest["specVersion"]
assert [(r["id"], r["text"]) for r in register["requirements"]] == re.findall(r"^([A-Z]+-\d{2})\. (.*)$", spec, re.M)
assert [(r["id"], r["specRow"]) for r in register["acceptanceCases"]] == re.findall(r"^\| (AC\d+) \|(.*)$", spec, re.M)
for row in register["requirements"]+register["acceptanceCases"]:
    assert row["status"] in {"planned","partial","implemented","verified"}
    if row["status"]!="planned": assert row["evidence"], row["id"]
    for evidence in row["evidence"]:
        assert (root/evidence.split("#")[0]).is_file(), (row["id"],evidence)
print("Spec v0.8: 277 unique requirements, 90 scenarios, source hashes and evidence links valid")
