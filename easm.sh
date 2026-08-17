#!/usr/bin/env bash
# Linux/macOS launcher: symlink this as `easm` on your PATH, e.g.
#   ln -s "$(pwd)/easm.sh" ~/.local/bin/easm
here="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
exec python3 "$here/run.py" "$@"
