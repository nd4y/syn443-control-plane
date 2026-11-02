from pathlib import Path

# Multiple binaries exercise the same package; count each source block once.
blocks={}
for name in ('invitation-coverage.out','provisioning-coverage.out'):
    for line in Path(name).read_text().splitlines()[1:]:
        location,count,hits=line.split()
        blocks[location]=(int(count),max(int(hits),blocks.get(location,(0,0))[1]))
for package,label in (('/internal/invitation/','Invitation SQL and role'),('/internal/deviceprovisioning/','Independent invitation publisher')):
    selected=[(count,hits) for location,(count,hits) in blocks.items() if package in location]
    assert selected,label
    value=100*sum(count for count,hits in selected if hits)/sum(count for count,_ in selected)
    print(f'{label} coverage: {value:.1f}% (minimum80%)')
    assert value>=80

# A larger established bridge must not hide an untested approved-layer reader.
selected=[(count,hits) for location,(count,hits) in blocks.items() if '/internal/deviceprovisioning/layer_store.go:' in location]
assert selected,'Persistent approved layers'
value=100*sum(count for count,hits in selected if hits)/sum(count for count,_ in selected)
print(f'Persistent approved layers coverage: {value:.1f}% (minimum80%)')
assert value>=80

selected=[(count,hits) for location,(count,hits) in blocks.items() if '/internal/deviceprovisioning/layer_requests.go:' in location]
assert selected,'Original configuration request authority'
value=100*sum(count for count,hits in selected if hits)/sum(count for count,_ in selected)
print(f'Original configuration request authority coverage: {value:.1f}% (minimum80%)')
assert value>=80
