"""Do not silently ship replacement characters from a mixed source encoding."""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
for name in (
    *(f'internal/chatweb/assets/{name}' for name in (
        'app.js', 'index.html', 'style.css', 'control/app.js', 'control/index.html',
        'control/style.css', 'control/layer-merge.js',
    )),
    'console-ui/main.jsx', 'console-ui/workspace.jsx', 'console-ui/build.mjs',
):
    data = (root / name).read_bytes()
    assert 0 < len(data) < 1024 * 1024, name
    data.decode('utf-8', errors='strict')
print('Support and control frontend sources are valid UTF-8')
