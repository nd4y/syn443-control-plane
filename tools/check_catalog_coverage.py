"""Catalog acceptance is measured with real PostgreSQL roles and transactions."""
from pathlib import Path
totals = [0, 0]
for line in Path("catalog-coverage.out").read_text().splitlines()[1:]:
    location, count, hits = line.split()
    assert "/internal/catalog/" in location
    totals[0] += int(count)
    if int(hits):
        totals[1] += int(count)
assert totals[0] > 0
percentage = 100 * totals[1] / totals[0]
print(f"Catalog with actual PostgreSQL role/concurrency tests: {percentage:.1f}% (minimum80%)")
assert percentage >= 80
