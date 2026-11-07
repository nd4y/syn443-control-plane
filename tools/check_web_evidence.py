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
    'source editor saves metadata without exposing prior secrets and tracks sync job',
    'source mutation lost acknowledgment retries the same request and clears new secret on success',
    'source permission withdrawal erases unsent credentials and disables mutation',
    'desired device view keeps revision provenance and hostile content separate from activation',
    'desired device view distinguishes unassigned expired and mismatched responses',
    'layer editor preserves inheritance and requires explicit reviewed publication',
    'layer save lost acknowledgment replays one private revision and remains reopenable',
    'layer publication lost acknowledgment reuses operation even after terminal commit',
    'layer conflict mismatched preview and expiry never enable publication',
    'layer edit invalidates review and authorization withdrawal erases private proposal',
    'layer comparison resolves conflict into a draft without silently saving or publishing',
    'three-way layer merge preserves current parents and combines independent paths',
    'three-way layer conflict requires an explicit local or server choice',
    'three-way layer merge refuses inherited edits unbound history and overlapping paths',
    'three-way layer merge represents removals and concurrent creation without lost edits',
    'private layer draft inventory lists metadata and reopens without implicit publication',
    'private layer draft inventory rejects substituted duplicate oversized and unexpected metadata',
    'private layer draft inventory disappears on rights withdrawal and logout',
    'empty private layer draft inventory preserves an unsaved proposal and does not invent a copy',
}
expected.update({
    'private layer discard requires confirmation and retains unsaved editor without publication',
    'private layer discard lost acknowledgment retains exact operation until verified receipt',
    'private layer discard conflicts and substituted receipts never clear the current editor',
    'source job history shows bounded retries and clears scoped results on logout',
})
assert len(cases) >= 32
assert expected <= {c.get('name') for c in cases}, 'Required browser scenarios missing'
assert all(not any(c.find(tag) is not None for tag in ('skipped','failure','error')) for c in cases)
print(f'{len(cases)} required browser outcomes passed without skips')
