from pathlib import Path
import sys

covered = total = 0
for row in Path(sys.argv[1]).read_text().splitlines()[1:]:
    location, count, hits = row.split()
    if '/internal/enrollment/' in location and location.rsplit('/', 1)[-1].split(':')[0] in ('store.go', 'http.go', 'publisher.go'):
        total += int(count)
        covered += int(count) if int(hits) else 0
assert total > 0
value = 100 * covered / total
print(f'Enrollment transaction/API/publisher coverage: {value:.1f}% (minimum 80%)')
assert value >= 80
