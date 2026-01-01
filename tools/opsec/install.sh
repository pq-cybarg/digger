#!/usr/bin/env bash
#
# tools/opsec/install.sh — install the post-commit timestamp-
# cleanse hook into the current repo's .git/hooks/.
#
# Usage:
#   ./tools/opsec/install.sh             # install into $(git rev-parse --show-toplevel)
#   ./tools/opsec/install.sh --uninstall # remove it
#
# Idempotent: re-running overwrites the existing hook with the
# current version of post-commit-cleanse.

set -euo pipefail

cd "$(dirname "$0")"
SRC="$PWD/post-commit-cleanse"

UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=1 ;;
        --help|-h)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

REPO=$(git rev-parse --show-toplevel 2>/dev/null) \
    || { echo "  ✗ not inside a git repo" >&2; exit 1; }

HOOK="$REPO/.git/hooks/post-commit"

if [[ "$UNINSTALL" -eq 1 ]]; then
    if [[ -f "$HOOK" ]] && head -2 "$HOOK" \
            | grep -q "post-commit-cleanse"; then
        rm "$HOOK"
        echo "  ✓ removed $HOOK"
    else
        echo "  → no digger cleanse hook at $HOOK (nothing to remove)"
    fi
    exit 0
fi

mkdir -p "$REPO/.git/hooks"
cp "$SRC" "$HOOK"
chmod +x "$HOOK"
echo "  ✓ installed $HOOK"
echo
echo "  Default sentinel date: 2026-01-01T00:00:00+0000"
echo "  Override via env:"
echo "    DIGGER_CLEANSE_DATE='2025-06-15T00:00:00+0000' \\"
echo "    DIGGER_CLEANSE_TOUCH='202506150000.00' git commit ..."
echo "  Disable single commit: DIGGER_CLEANSE_DISABLE=1 git commit ..."
