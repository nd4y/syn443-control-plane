"""Do not silently ship replacement characters from a mixed source encoding."""
from pathlib import Path

root = Path(__file__).resolve().parent.parent / 'internal/chatweb/assets'
for name in ('app.js', 'index.html', 'style.css'):
    data = (root / name).read_bytes()
    assert 0 < len(data) < 1024 * 1024, name
    data.decode('utf-8', errors='strict')
print('Support frontend sources are valid UTF-8')
