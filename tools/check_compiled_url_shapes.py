"""Report structural scanner diagnostics only, never possible credential values."""
from pathlib import Path
import json,re,subprocess,sys
old=re.compile(rb'[a-z][a-z0-9+.-]*://[^\s/"<>]+:[^\s/"<>]+@',re.I)
literal=re.compile(rb'//[^\n]*|/\*.*?\*/|`[^`]*`|"(?:[^"\\\r\n]|\\.)*"',re.S)

def shape(value):
    return ''.join(chr(c) if chr(c) in ':@{}[]()?%-.!$&*+,;=~^' else 'A' if 65<=c<=90 or 97<=c<=122 else '0' if 48<=c<=57 else '?' for c in value[:160])

def public_literals():
    template='{{range .GoFiles}}{{printf "%s\\t%s\\t%s\\n" $.ImportPath $.Dir .}}{{end}}'
    raw=subprocess.check_output(['go','list','-deps','-f',template,'./cmd/enrollment-admin','./cmd/overlay-worker'],stderr=subprocess.DEVNULL,timeout=30)
    by_prefix={}
    for row in raw.decode().splitlines():
        if not row:continue
        package,directory,file=row.split('\t')
        if not re.fullmatch(r'[A-Za-z0-9_./-]+',package) or not re.fullmatch(r'[A-Za-z0-9_.-]+\.go',file):continue
        src=Path(directory)/file
        if src.stat().st_size>2*1024*1024:continue
        body=src.read_bytes()
        for match in literal.finditer(body):
            token=match[0]
            if token.startswith(b'/'):continue
            try:
                value=token[1:-1].replace(b'\r',b'') if token.startswith(b'`') else json.loads(token).encode('utf-8')
            except (ValueError,UnicodeError):continue
            if not 3<=len(value)<=256 or not value.isascii():continue
            by_prefix.setdefault(value[:3],{}).setdefault(value,(package,file,src,match.start()))
    return by_prefix

def source_origins(data,match,literals):
    start,end=match.span()
    positions=[]
    for offset in range(max(0,start-64),end):
        for value,where in literals.get(data[offset:offset+3],{}).items():
            finish=offset+len(value)
            if finish>start and data.startswith(value,offset):positions.append((offset,finish,where))
    # Prefer complete, longer source literals over incidental short matches.
    positions.sort(key=lambda row:(row[0],-(row[1]-row[0])))
    kept=[]
    for left,right,where in positions:
        if any(a<=left and right<=b for a,b,_ in kept):continue
        kept.append((left,right,where))
        if len(kept)==32:break
    for left,right,(package,file,src,offset) in kept:
        line=src.read_bytes().count(b'\n',0,offset)+1
        print(f'    public_literal offsets={left-start}..{right-start} source={package}/{file}:{line}')

origins=None

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
        if not regexp_suffix and path.name in ('enrollment-admin','overlay-worker') and index<4 and len(value)<=512:
            if origins is None:origins=public_literals()
            source_origins(data,match,origins)
