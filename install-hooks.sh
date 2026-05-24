#!/usr/bin/env bash
#
# install-hooks.sh
#
# Installs a single pre-push git hook in .git/hooks/ that does two jobs:
#
#   1. Identity check  — if `git config --local ghid.lock-identity <id>` is
#      set, refuses any push whose target remote URL doesn't go through
#      the matching `git@github-<id>:...` SSH alias. Compatible with
#      anything `ghid lock` sets.
#
#   2. gh-pages sync   — if `main` is being pushed AND `docs/` has changed
#      since the last gh-pages commit, automatically runs
#      sync-gh-pages.sh and pushes the resulting `gh-pages` ref along
#      with the main push. The hook prints what it did; it can be
#      bypassed for a single push with:
#          GHID_NO_AUTOSYNC=1 git push origin main
#
# Idempotent: re-running this script overwrites the hook with the
# latest version. If a NON-ghidbar pre-push hook already exists, the
# installer refuses unless --force is passed (and shows you what's
# there first).
#
# Usage:
#     ./install-hooks.sh              # install (refuses on conflict)
#     ./install-hooks.sh --force      # replace whatever's there
#     ./install-hooks.sh --uninstall  # remove the hook

set -euo pipefail

cd "$(dirname "$0")"
HOOK="$(git rev-parse --git-dir)/hooks/pre-push"
MARKER="# GHID_AUTOSYNC_HOOK_V1"

if [[ "${1:-}" == "--uninstall" ]]; then
    if [[ -f "$HOOK" ]] && grep -q "^$MARKER" "$HOOK"; then
        rm "$HOOK"
        echo "  ✓ pre-push hook removed"
    else
        echo "  no ghidbar hook installed (nothing to remove)"
    fi
    exit 0
fi

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

if [[ -f "$HOOK" ]] && ! grep -q "^$MARKER" "$HOOK" && [[ "$FORCE" -ne 1 ]]; then
    echo "  ✗ a different pre-push hook already exists:" >&2
    echo >&2
    sed 's/^/      /' "$HOOK" | head -20 >&2
    echo >&2
    echo "      …" >&2
    echo >&2
    echo "  Pass --force to replace it, or merge manually." >&2
    exit 2
fi

cat > "$HOOK" <<'HOOK_BODY'
#!/usr/bin/env bash
# GHID_AUTOSYNC_HOOK_V1
# Installed by install-hooks.sh in the digger repo. Two behaviors:
#   1. Honor `git config --local ghid.lock-identity <id>` (refuses push
#      if the remote URL doesn't go through git@github-<id>:...)
#   2. When pushing `main` and `docs/` has changed since the last
#      gh-pages commit, run ./sync-gh-pages.sh and push gh-pages too.
# Set GHID_NO_AUTOSYNC=1 to skip behavior #2 for a single push.

set -euo pipefail

remote_name="$1"
remote_url="$2"

# ---- 1. Identity check ----
lock_id=$(git config --local --get ghid.lock-identity 2>/dev/null || true)
if [[ -n "$lock_id" ]]; then
    case "$remote_url" in
        git@github-${lock_id}:*) ;;
        *)
            echo "" >&2
            echo "  ✗ ghid: push refused — repo locked to identity '$lock_id'" >&2
            echo "    push target is: $remote_url" >&2
            echo "    Switch with:    ghid switch $lock_id" >&2
            echo "    Or unlock with: ghid unlock" >&2
            exit 1
            ;;
    esac
fi

# ---- 2. gh-pages auto-sync ----
[[ "${GHID_NO_AUTOSYNC:-0}" == "1" ]] && exit 0

# Read the push spec from stdin. Format per line:
#   <local-ref> <local-sha> <remote-ref> <remote-sha>
pushing_main=0
while read -r local_ref local_sha remote_ref remote_sha; do
    [[ "$local_ref" == "refs/heads/main" ]] && pushing_main=1
done

[[ "$pushing_main" -eq 0 ]] && exit 0

# Find the docs/ tree-sha at our about-to-be-pushed main HEAD.
main_docs_tree=$(git ls-tree -d HEAD docs 2>/dev/null | awk '{print $3}')
if [[ -z "$main_docs_tree" ]]; then
    # No docs/ on main — nothing to sync.
    exit 0
fi

# What docs/ tree-sha did gh-pages capture last? We stamp it in the
# commit trailer when sync-gh-pages.sh runs. If no gh-pages branch
# locally, do an initial sync.
if git show-ref --verify -q refs/heads/gh-pages; then
    last_synced=$(git log -1 --format=%B gh-pages 2>/dev/null | \
                  awk -F': ' '/^docs-tree:/ {print $2; exit}' || true)
else
    last_synced=""
fi

if [[ "$main_docs_tree" == "$last_synced" ]]; then
    # Nothing to do.
    exit 0
fi

echo "  → docs/ changed since last gh-pages sync — running sync-gh-pages.sh"
if ! ./sync-gh-pages.sh >&2; then
    echo "  ✗ sync-gh-pages.sh failed — aborting push" >&2
    echo "    Fix the sync issue manually, then push again (or set GHID_NO_AUTOSYNC=1)." >&2
    exit 1
fi

# Push gh-pages now (separate `git push` — the outer push hasn't
# completed yet; ours runs as a sub-invocation).
echo "  → pushing gh-pages to $remote_name"
if ! git push "$remote_name" gh-pages >&2; then
    echo "  ⚠ gh-pages push failed but main push will continue." >&2
    echo "    Run manually: git push $remote_name gh-pages" >&2
fi

exit 0
HOOK_BODY

chmod +x "$HOOK"
echo "  ✓ pre-push hook installed at $HOOK"
echo
echo "  This hook will:"
echo "    • Refuse pushes if a ghid identity-lock is set and the remote"
echo "      URL doesn't match (compatible with \`ghid lock <id>\`)."
echo "    • When pushing main, auto-regenerate gh-pages from docs/ and"
echo "      push gh-pages too — but only if docs/ changed since last sync."
echo
echo "  Bypass auto-sync for one push:  GHID_NO_AUTOSYNC=1 git push origin main"
echo "  Remove the hook entirely:       ./install-hooks.sh --uninstall"
