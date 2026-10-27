from pathlib import Path
import sys

# -coverpkg emits each package's blocks once for each test binary. A block is
# covered if any binary hit it; counting duplicate zero blocks halves coverage.
blocks = {}
for row in Path(sys.argv[1]).read_text().splitlines()[1:]:
    location, count, hits = row.split()
    blocks[location] = (int(count), max(int(hits), blocks.get(location, (0, 0))[1]))
covered = total = 0
for location, (count, hits) in blocks.items():
    if '/internal/enrollment/' in location and location.rsplit('/', 1)[-1].split(':')[0] in ('store.go', 'http.go', 'publisher.go', 'cleanup.go'):
        total += int(count)
        covered += int(count) if int(hits) else 0
assert total > 0
value = 100 * covered / total
print(f'Enrollment transaction/API/publisher coverage: {value:.1f}% (minimum 80%)')
assert value >= 80

# Separate gates prevent the larger identity suite from hiding untested chat ACL
# or SQL paths. Merge duplicate package coverage blocks by source location.
for label, marker in (('Chat SQL/store', '/internal/supportchat/'), ('Chat authenticated HTTP', '/internal/enrollment/chat.go')):
    selected = [(count, hits) for location, (count, hits) in blocks.items() if marker in location]
    assert selected, label
    value = 100 * sum(count for count, hits in selected if hits) / sum(count for count, _ in selected)
    print(f'{label} coverage: {value:.1f}% (minimum 80%)')
    assert value >= 80
