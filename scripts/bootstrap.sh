#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/components/portal"
if command -v uv >/dev/null 2>&1; then
  uv venv .venv
  . .venv/bin/activate
  uv pip install -r requirements.txt
else
  python3 -m venv .venv
  . .venv/bin/activate
  python3 -m pip install -r requirements.txt
fi
mkdir -p data/uploads data/reports data/generated-report-sources
printf 'Bootstrap complete. Copy .env.example to .env, tune it, then run scripts/run-portal.sh\n'
