"""Report structural scanner diagnostics only, never possible credential values."""
from pathlib import Path
import re,sys
old=re.compile(rb'[a-z][a-z0-9+.-]*://[^\s/"<>]+:[^\s/"<>]+@',re.I)
for path in sorted(Path(sys.argv[1]).iterdir()):
    data=path.read_bytes()
    if not data.startswith(bytes([127])+b'ELF'):continue
    matches=list(old.finditer(data))
    controls=sum(any(c<32 or c==127 for c in match[0]) for match in matches)
    print(f'{path.name}: legacy-userinfo-sequences={len(matches)}, impossible-control-separated={controls}')
