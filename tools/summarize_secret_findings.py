"""Report bounded rule/known-field counts only, never finding content."""
import collections
import json
from pathlib import Path
import re
import sys

KNOWN_FIELDS = ('keyThumbprint', 'previewKeyId', 'previewRootSpkiB64', 'bodyHash',
                'ticket', 'requestId', 'originalBody64', 'apiOrigin', 'actor', 'jobId')


def summarize(rows):
    assert isinstance(rows, list) and len(rows) <= 10000
    counts = collections.Counter()
    for row in rows:
        assert isinstance(row, dict)
        rule = row.get('RuleID')
        rule = rule if isinstance(rule, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', rule) else 'invalid-rule'
        match = row.get('Match', '')
        hint = 'unclassified'
        if isinstance(match, str) and len(match) <= 1048576:
            for name in KNOWN_FIELDS:
                if re.search(r'(?<![A-Za-z0-9_])' + re.escape(name) + r'(?:\\?"|\s)*:', match):
                    hint = name
                    break
        counts[(rule, hint)] += 1
    return [{'rule': rule, 'knownFieldHint': hint, 'count': count}
            for (rule, hint), count in sorted(counts.items())]


if __name__ == '__main__':
    try:
        assert len(sys.argv) == 2
        path = Path(sys.argv[1])
        assert path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 16 * 1024 * 1024
        result = summarize(json.loads(path.read_text(encoding='utf-8')))
        print('Secret scanner rule counts only: ' + json.dumps(result, separators=(',', ':')))
    except Exception:
        print('Secret scanner rule summary unavailable; original scan remains failed')
        raise SystemExit(2)
