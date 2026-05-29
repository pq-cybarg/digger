#!/usr/bin/env bash
#
# tools/identity/install.sh — install or refresh the multi-identity
# GitHub tooling (ghid CLI + ghidbar menu-bar app) on this machine.
#
# Layout after install:
#     ~/.local/bin/ghid                   — CLI
#     ~/.local/bin/ghidbar                — launcher for the menu-bar app
#     ~/.local/share/ghidbar/ghidbar.py   — the app itself
#     ~/.local/share/ghidbar/venv/        — self-contained venv with rumps
#     ~/.config/ghidbar/                  — runtime state + logs + pidfile
#     ~/Library/LaunchAgents/com.ghidbar.menubar.plist  — auto-start at login (opt-in)
#
# Usage:
#     ./tools/identity/install.sh                # install / upgrade in place
#     ./tools/identity/install.sh --launchd      # install + register launchd auto-start
#     ./tools/identity/install.sh --uninstall    # remove everything
#     ./tools/identity/install.sh --help

set -euo pipefail

cd "$(dirname "$0")"
SRC="$PWD"

INSTALL_LAUNCHD=0
UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --launchd)   INSTALL_LAUNCHD=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --help|-h)
            sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

PLIST_PATH="$HOME/Library/LaunchAgents/com.ghidbar.menubar.plist"
ZSHRC="$HOME/.zshrc"
RC_MARK_START="# >>> ghidbar-here shell function (added by tools/identity/install.sh) >>>"
RC_MARK_END="# <<< ghidbar-here shell function <<<"

if [[ "$UNINSTALL" -eq 1 ]]; then
    if [[ -f "$PLIST_PATH" ]]; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        rm -f "$PLIST_PATH"
        echo "  ✓ launchd plist removed"
    fi
    pkill -9 -f "ghidbar/ghidbar.py" 2>/dev/null || true
    rm -rf "$HOME/.local/share/ghidbar" "$HOME/.config/ghidbar"
    rm -f "$HOME/.local/bin/ghid" "$HOME/.local/bin/ghidbar"
    # Strip the ghidbar-here block from ~/.zshrc if we ever added it.
    if [[ -f "$ZSHRC" ]] && grep -qF "$RC_MARK_START" "$ZSHRC"; then
        # macOS sed: -i needs an explicit backup-suffix arg (use '')
        sed -i '' "/$RC_MARK_START/,/$RC_MARK_END/d" "$ZSHRC"
        echo "  ✓ removed ghidbar-here block from $ZSHRC"
    fi
    echo "  ✓ uninstalled (your ~/.ssh/config and keys are untouched)"
    exit 0
fi

mkdir -p "$HOME/.local/bin" "$HOME/.local/share/ghidbar" "$HOME/.config/ghidbar"

# CLI
install -m 755 "$SRC/ghid" "$HOME/.local/bin/ghid"
echo "  ✓ $HOME/.local/bin/ghid"

# menu-bar app + launcher
install -m 644 "$SRC/ghidbar.py" "$HOME/.local/share/ghidbar/ghidbar.py"
install -m 755 "$SRC/ghidbar"    "$HOME/.local/bin/ghidbar"
echo "  ✓ $HOME/.local/share/ghidbar/ghidbar.py"
echo "  ✓ $HOME/.local/bin/ghidbar"

# venv with rumps — only build if missing or stale.
VENV="$HOME/.local/share/ghidbar/venv"
if [[ ! -x "$VENV/bin/python" ]]; then
    echo "  → building self-contained venv at $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --upgrade pip rumps
    echo "  ✓ venv ready (rumps installed)"
else
    "$VENV/bin/pip" show rumps >/dev/null 2>&1 || {
        echo "  → installing rumps into existing venv"
        "$VENV/bin/pip" install -q rumps
    }
    echo "  ✓ venv at $VENV (already healthy)"
fi

# launchd plist — substitute the templated $HOME at install time
if [[ "$INSTALL_LAUNCHD" -eq 1 ]]; then
    mkdir -p "$HOME/Library/LaunchAgents"
    sed "s|__HOME__|$HOME|g" "$SRC/ghidbar.plist" > "$PLIST_PATH"
    chmod 644 "$PLIST_PATH"
    # Reload if previously loaded
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    launchctl load   "$PLIST_PATH"
    echo "  ✓ launchd: $PLIST_PATH (auto-start at login enabled)"
else
    echo
    echo "  Skipped launchd auto-start. To enable later:"
    echo "      $SRC/install.sh --launchd"
    echo "  Or launch manually now:  ghidbar &"
fi

# PATH check (the most common foot-gun after install)
if ! echo "$PATH" | tr ':' '\n' | grep -q "^$HOME/.local/bin$"; then
    echo
    echo "  ⚠ ~/.local/bin is not on your PATH. Add to ~/.zshrc:"
    echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ghidbar-here / gbh shell function — tells the menu-bar app which
# repo to watch. Append idempotently:
#   - If a `ghidbar-here()` function already exists (with or without
#     our markers), do nothing.
#   - Otherwise append a marked block to ~/.zshrc.
if [[ -f "$ZSHRC" ]] && grep -qE "^ghidbar-here[[:space:]]*\(\)" "$ZSHRC"; then
    echo "  ✓ ghidbar-here shell function already in $ZSHRC"
else
    [[ -f "$ZSHRC" ]] || touch "$ZSHRC"
    cat >> "$ZSHRC" <<ZSHRC_BLOCK

$RC_MARK_START
# Tells the ghidbar menu-bar app which repo to watch. State is the
# JSON file at ~/.config/ghidbar/state.json; the menu-bar app polls
# it every 5 s.
#   ghidbar-here            # use \$PWD's repo
#   ghidbar-here /some/path # use a different repo
ghidbar-here() {
    local target="\${1:-\$PWD}"
    local repo
    repo=\$(git -C "\$target" rev-parse --show-toplevel 2>/dev/null) || {
        echo "ghidbar-here: not in a git repo: \$target" >&2
        return 1
    }
    mkdir -p "\$HOME/.config/ghidbar"
    python3 -c "
import json, pathlib, sys
pathlib.Path('\$HOME/.config/ghidbar/state.json').write_text(
    json.dumps({'repo': sys.argv[1]}, indent=2) + '\n'
)
" "\$repo" || {
        echo "ghidbar-here: failed to write state file" >&2
        return 1
    }
    echo "ghidbar watching: \$repo"
}
alias gbh='ghidbar-here'
$RC_MARK_END
ZSHRC_BLOCK
    echo "  ✓ added ghidbar-here to $ZSHRC (open a new shell or run 'source ~/.zshrc')"
fi

echo
echo "  Next:  ghid doctor"
echo "         ghid list"
