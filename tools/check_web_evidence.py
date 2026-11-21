"""Require the complete synthetic browser gate, including the private-draft UI."""
from pathlib import Path
import xml.etree.ElementTree as ET

root = ET.parse(Path(__file__).resolve().parent.parent / 'web-tests/results.xml').getroot()
cases = list(root.iter('testcase'))
expected = {
    'look up an exact incident without opening or acknowledging a thread on standalone',
    'look up an exact incident without opening or acknowledging a thread on console',
    'late incident lookup cannot disclose the previous query on the phone',
    'mobile resource rename replays its exact request after a lost response',
    'sync changes require acknowledged impact and explicit retry after stronger login',
    'a conflicting resource update requires fresh inspection and planned providers stay read-only',
    'switching conversations clears the previous history and file on standalone',
    'long inbox and message history remain navigable on standalone',
    'long inbox and message history remain navigable on console',
    'switching conversations clears the previous history and file on console',
    'leaving support during final file verification cannot publish a save link',
    'administrator sends text and hostile content remains text',
    '25 MiB upload and authenticated verified download',
    'lost send acknowledgment retries exactly one message',
    'oversize file is rejected locally and session expiry erases contents',
    'role withdrawal clears the visible thread without deleting server history',
    'console safely renders source metadata and saves/reopens its private draft',
    'lost save response retries identical operation without another revision',
    'invalid plan keeps edit available, revoked rights and logout clear private memory',
    'phone layout stays light and within viewport; expired session hides old data',
    'source editor saves metadata without exposing prior secrets and tracks sync job',
    'source mutation lost acknowledgment retries the same request and clears new secret on success',
    'source permission withdrawal erases unsent credentials and disables mutation',
    'desired device view keeps revision provenance and hostile content separate from activation',
    'desired device view distinguishes unassigned expired and mismatched responses',
    'unassigned device can stage its first layer draft from an explicit plan',
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
    'mobile replay compares both policies on reference and uploaded observations without publishing',
    'malformed traces and a late comparison cannot replace a changed replay',
    'empty private layer draft inventory preserves an unsaved proposal and does not invent a copy',
}
expected.update({
    'private layer discard requires confirmation and retains unsaved editor without publication',
    'private layer discard lost acknowledgment retains exact operation until verified receipt',
    'private layer discard conflicts and substituted receipts never clear the current editor',
    'source job history shows bounded retries and clears scoped results on logout',
    'manual subscription file retries exactly once without exposing or storing its contents',
    'source recipient edits require confirmation and retry the same scoped mutation',
    'hourly telemetry distinguishes data empty and mismatched reports and clears on expiry',
    'scoped telemetry denial preserves an unrelated unsaved draft',
    'reserve probe cooldown requires explicit draft opt in and never publishes',
    'device workspace is private until sign in and opens a safe linked device',
    'mobile device form submits by keyboard and cannot keep a stale device selected',
    'console shell keeps the active section and keyboard focus visible on desktop',
    'console shell fits a narrow screen and retains a keyboard scroll region',
    'console sign-in is the only entry when no session is present',
    'PatternFly resources are same-origin and section history keeps an unsaved draft',
})
expected.update({
    'authorized device inventory opens a card without copying identifiers and separates old reports',
    'device inventory pagination is explicit and fits a narrow keyboard scroll region',
    'device inventory refuses malformed oversized duplicate and substituted metadata atomically',
    'device inventory clears withdrawn or expired sessions and keeps manual lookup after unavailable discovery',
})
expected.update({
    'selected device moves keyboard focus out of the collapsed discovery list',
    'issued algorithm metadata has its own line and cannot keep stale device data',
})
expected.update({
    'control reauthentication preserves the exact pending draft and requires explicit retry',
    'control reauthentication never turns withdrawn authority into a recoverable sign-in',
    'blocked reauthentication windows retain the unsaved draft without starting authentication',
    'substituted reauthentication navigation and expired sessions fail closed',
    'assurance recovery is keyboard accessible on a narrow screen and rejects untrusted error metadata',
})
expected.update({
    'runtime observation is separately attributed and never invents an activation or mutation',
    'runtime observation expires locally without polling or refreshing a historical receipt',
    'runtime observation refuses substituted future extra contradictory and stale sample metadata',
    'runtime observation denial and session expiry erase cached state and private proposals',
    'unknown or unavailable runtime keeps its configuration card and narrow keyboard actions usable',
})
expected.update({
    'open runtime card follows real new observations but polling cannot renew an old receipt',
    'runtime refresh pauses outside the visible device section and erases expired authority',
    'pending automatic runtime read stays single and cannot paint a changed device',
    'runtime read timeout keeps unrelated controls usable and later refresh recovers',
    'a previously empty runtime card receives a later observation without a manual reload',
})
expected.update({
    'stalled initial session never blocks sign-in indefinitely or paints a late identity',
    'stalled sign-in releases controls at its deadline and only an explicit retry navigates',
    'a committed save with a stalled response keeps its exact pending request for manual retry',
})
expected.update({
    'PatternFly console chat sends hostile text safely without leaving device administration',
    'PatternFly console chat transfers and verifies a full 25 MiB file',
    'explicit send preserves composition and exact Unicode on standalone',
    'explicit send preserves composition and exact Unicode on console',
    'source editor binds selection and retry to the owner and external pair',
    'source editor forgets a late selection when the listed owner changes',
    'mismatched send receipts retain the exact draft and files on standalone',
    'mismatched send receipts retain the exact draft and files on console',
    'PatternFly console chat retries a lost acknowledgment without duplicate delivery',
    'chat authority withdrawal erases its thread and preserves an unrelated console draft',
    'console logout cancels a late chat response and never paints the previous session',
    'console chat backs off failures and hidden navigation cannot bypass its admission',
    'console chat has a narrow empty state and rejects oversize attachments locally',
})
expected.update({
    'manual route preview sends only on request and shows DNS and proxy dial order on a phone',
    'manual route preview discards late results and distinguishes missing facts from default',
    'mobile source review compares both versions and retries the identical approved candidate',
    'changed subscription review requires a fresh comparison before rejecting its successor',
    'mobile provider usage preserves exact counters and the original provider timestamp',
    'unknown unlimited and exhausted provider quotas keep distinct labels on the phone',
})
assert len(cases) >= 79
assert expected <= {c.get('name') for c in cases}, 'Required browser scenarios missing'
assert all(not any(c.find(tag) is not None for tag in ('skipped','failure','error')) for c in cases)
print(f'{len(cases)} required browser outcomes passed without skips')
