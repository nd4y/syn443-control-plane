"""Report structural scanner diagnostics only, never possible credential values."""
from pathlib import Path
import re,sys
old=re.compile(rb'[a-z][a-z0-9+.-]*://[^\s/"<>]+:[^\s/"<>]+@',re.I)

def shape(value):
    return ''.join(chr(c) if chr(c) in ':@{}[]()?%-.!$&*+,;=~^' else 'A' if 65<=c<=90 or 97<=c<=122 else '0' if 48<=c<=57 else '?' for c in value[:160])

for path in sorted(Path(sys.argv[1]).iterdir()):
    data=path.read_bytes()
    if not data.startswith(bytes([127])+b'ELF'):continue
    matches=list(old.finditer(data))
    controls=sum(any(c<32 or c==127 for c in match[0]) for match in matches)
    print(f'{path.name}: legacy-userinfo-sequences={len(matches)}, impossible-control-separated={controls}')

    for index,match in enumerate(matches):
        value=match[0]
        scheme,rest=value.split(b'://',1)
        safe_scheme=scheme.decode() if scheme in (b'http',b'https',b'postgres',b'syn443',b'socks',b'ftp') else 'other'
        # Keep the masks separate. Even a masked composite URL can trigger the
        # public log's secret redaction and hide the structural evidence.
        first, _, last=rest[:-1].rpartition(b':')
        formatting=bool(re.search(rb"%[0-9.*+#-]*[sdvqwx]",value))
        regexp_suffix=value.endswith(b':['+b'^@]+@')
        print(f'  candidate{index}: bytes={len(value)}, scheme={safe_scheme}, printf={formatting}, pgx_suffix={regexp_suffix}')
        print(f'    scheme_mask={shape(scheme)} left_mask={shape(first)} right_mask={shape(last)}')
