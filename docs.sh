#!/usr/bin/env bash
# Launch the digger documentation site locally and open a browser to it.
#
# Usage:
#   ./docs.sh                # serves on http://127.0.0.1:8765/
#   ./docs.sh 9000           # serves on the given port
#   ./docs.sh --no-open      # don't open the browser
#
# The site is fully static (HTML + CSS + a small JS shim that injects the
# shared sidebar). No build step needed — pages live directly under docs/.

set -euo pipefail

PORT=8765
OPEN=1
for arg in "$@"; do
    case "$arg" in
        --no-open) OPEN=0 ;;
        --help|-h)
            sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            if [[ "$arg" =~ ^[0-9]+$ ]]; then
                PORT="$arg"
            else
                echo "unknown arg: $arg" >&2
                exit 2
            fi
            ;;
    esac
done

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOC_DIR="$SCRIPT_DIR/docs"

if [[ ! -d "$DOC_DIR" ]]; then
    echo "docs/ not found at $DOC_DIR" >&2
    exit 1
fi

PY=$(command -v python3 || command -v python)
if [[ -z "$PY" ]]; then
    echo "python3 not found in PATH" >&2
    exit 1
fi

URL="http://127.0.0.1:$PORT/"

echo "  digger docs"
echo "  ─────────────────────────────────────────"
echo "  serving $DOC_DIR"
echo "  on      $URL"
echo "  press Ctrl-C to stop"
echo

if [[ "$OPEN" -eq 1 ]]; then
    (
        sleep 0.5
        if   command -v open      >/dev/null 2>&1; then open      "$URL"
        elif command -v xdg-open  >/dev/null 2>&1; then xdg-open  "$URL"
        elif command -v start     >/dev/null 2>&1; then start     "$URL"
        else echo "  (could not auto-open browser; visit $URL manually)"
        fi
    ) &
fi

cd "$DOC_DIR"
exec "$PY" -m http.server "$PORT" --bind 127.0.0.1
