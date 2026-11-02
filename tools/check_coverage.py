from pathlib import Path
totals={}
for line in Path("coverage.out").read_text().splitlines()[1:]:
    location,statements,hits=line.split()
    package=location.rsplit("/",1)[0]
    total,covered=totals.get(package,(0,0))
    totals[package]=(total+int(statements),covered+(int(statements) if int(hits)>0 else 0))
for suffix,minimum in (("/internal/decision",90),("/internal/preview",85),("/internal/policy",80),("/internal/identity",80),("/internal/resources",80),("/internal/remnawave",80),("/internal/netbirdapi",80),("/cmd/resource-inspect",75),("/internal/subscriptions",80),("/internal/egress",80),("/internal/configuration",85),("/internal/bootstrap",85),("/internal/overlay",90)):
    package=next(p for p in totals if p.endswith(suffix))
    total,covered=totals[package];percentage=100*covered/total
    print(f"{package}: {percentage:.1f}% (minimum {minimum}%)")
    assert percentage>=minimum

