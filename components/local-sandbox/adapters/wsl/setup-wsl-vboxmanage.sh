#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADAPTER_DIR="$ROOT/adapters/wsl"

case "$(uname -r 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
  *microsoft*|*wsl*) ;;
  *)
    printf 'WARNING: this does not look like WSL. Continuing because the adapter can still be inspected/tested.\n' >&2
    ;;
esac

export PATH="$ADAPTER_DIR:$PATH"
export RAICCOON_VBOXMANAGE_EXE="${RAICCOON_VBOXMANAGE_EXE:-/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe}"

printf 'Export these in your WSL shell before running the sandbox:\n\n'
printf '  export PATH=%q:\$PATH\n' "$ADAPTER_DIR"
printf '  export RAICCOON_VBOXMANAGE_EXE=%q\n' "$RAICCOON_VBOXMANAGE_EXE"
printf '\nTesting adapter...\n'
"$ADAPTER_DIR/VBoxManage" --adapter-self-test
