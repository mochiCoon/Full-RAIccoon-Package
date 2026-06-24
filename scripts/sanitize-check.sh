#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT" <<'PY'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
terms=["Lost"+" Boys", "lost"+"0x01", "rob"+"@", "PRIVATE"+" KEY", "OPENAI"+"_API"+"_KEY="+"sk-"]
allow={Path('README.md')}
bad=[]
for p in root.rglob('*'):
    if not p.is_file() or any(part in {'.git','.venv','__pycache__'} for part in p.parts):
        continue
    if p.relative_to(root) == Path('scripts/sanitize-check.sh'):
        continue
    try:
        text=p.read_text(errors='ignore')
    except Exception:
        continue
    for term in terms:
        if term in text:
            # The README may include the target GitHub SSH URL requested by the maintainer.
            if p.relative_to(root) in allow and term == 'lost'+'0x01':
                continue
            bad.append((str(p.relative_to(root)), term))
if bad:
    for path, term in bad:
        print(f'{path}: matched {term!r}')
    raise SystemExit('Sanitization check failed.')
print('Sanitization check passed.')
PY
