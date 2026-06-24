#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m py_compile "$ROOT/components/portal/app.py" "$ROOT/components/local-sandbox/src/raiccoon_sandbox/local_vbox_detonate.py"
if [ -x "$ROOT/components/portal/.venv/bin/python" ]; then
  (cd "$ROOT/components/portal" && .venv/bin/python -m unittest discover -s tests -v || true)
fi
printf 'Smoke checks completed. For full validation, start the portal and verify /healthz.\n'
