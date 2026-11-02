"""Require the complete synthetic browser gate, including the private-draft UI."""
from pathlib import Path
import xml.etree.ElementTree as ET

root = ET.parse(Path(__file__).resolve().parent.parent / 'web-tests/results.xml').getroot()
cases = list(root.iter('testcase'))
expected = {
    'administrator sends text and hostile content remains text',
    '25 MiB upload and authenticated verified download',
    'lost send acknowledgment retries exactly one message',
    'oversize file is rejected locally and session expiry erases contents',
    'role withdrawal clears the visible thread without deleting server history',
    'console safely renders source metadata and saves/reopens its private draft',
    'lost save response retries identical operation without another revision',
    'invalid plan keeps edit available, revoked rights and logout clear private memory',
    'phone layout stays dark and within viewport; expired session hides old data',
}
assert len(cases) >= 9
assert expected <= {c.get('name') for c in cases}, 'Required browser scenarios missing'
assert all(not any(c.find(tag) is not None for tag in ('skipped','failure','error')) for c in cases)
print(f'{len(cases)} required browser outcomes passed without skips')
