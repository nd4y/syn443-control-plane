from pathlib import Path
total=covered=0
for line in Path('invitation-coverage.out').read_text().splitlines()[1:]:
    location,count,hits=line.split()
    assert '/internal/invitation/' in location
    total+=int(count)
    if int(hits):covered+=int(count)
assert total>0
value=100*covered/total
print(f'Invitation SQL and role coverage: {value:.1f}% (minimum80%)')
assert value>=80
