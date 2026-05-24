#!/usr/bin/env bash
#
# sync-gh-pages.sh
#
# Regenerate the gh-pages branch from the current docs/ contents.
# The gh-pages branch is an orphan; this script wipes the working tree
# on that branch and copies in the rendered HTML/CSS/JS from docs/.
#
# Usage (from main):
#     ./sync-gh-pages.sh                       # commit but don't push
#     ./sync-gh-pages.sh --push                # commit + push
#
# Safety:
#   - Refuses to run if you have uncommitted changes on the current branch.
#   - Returns you to whatever branch you started on, even on failure.
#   - Never force-pushes; appends a normal commit each time.

set -euo pipefail

PUSH=0
for arg in "$@"; do
    case "$arg" in
        --push)   PUSH=1 ;;
        --help|-h)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# Where we are
cd "$(dirname "$0")"
start_branch=$(git rev-parse --abbrev-ref HEAD)
[[ "$start_branch" = "gh-pages" ]] && {
    echo "  already on gh-pages — switch to main first" >&2
    exit 2
}
[[ -d docs ]] || { echo "  no docs/ here — wrong directory?" >&2; exit 2; }

# Refuse if working tree is dirty (avoid silently stashing user work)
if [[ -n "$(git status --porcelain)" ]]; then
    echo "  working tree has uncommitted changes — commit or stash first." >&2
    git status --short >&2
    exit 2
fi

# Always return to the start branch, even on failure / Ctrl-C.
trap 'git checkout -q "$start_branch" 2>/dev/null || true' EXIT INT TERM

# Snapshot the current docs/ to a temp dir before switching branches
# (the branch switch would otherwise replace the working tree).
staging=$(mktemp -d -t ghpages.XXXXXX)
rsync -a --delete docs/ "$staging/" >/dev/null

# Capture the source docs/ tree-sha now so the gh-pages commit stamps
# its origin. The pre-push auto-sync hook (install-hooks.sh) reads the
# stamped tree-sha back to decide whether anything actually changed
# since the last sync.
src_tree_sha=$(git ls-tree -d "$start_branch" docs | awk '{print $3}')
src_commit_sha=$(git log -1 --format=%h --abbrev=10 "$start_branch")

echo "  → switching to gh-pages"
if git show-ref --verify -q refs/heads/gh-pages; then
    git checkout -q gh-pages
else
    echo "  gh-pages branch missing — refusing to create one here."
    echo "  Initial-publish path is documented in README on the gh-pages branch." >&2
    exit 2
fi

# Wipe the working tree (everything tracked AND untracked, except .git)
git ls-files | xargs -I{} rm -f {}
find . -mindepth 1 -maxdepth 1 -not -name .git -not -name . -exec rm -rf {} +

# Copy staged docs back in, drop the build script (not publishable)
rsync -a "$staging/" ./ >/dev/null
rm -f _build_sample_report.py
touch .nojekyll

# README for the gh-pages branch itself
cat > README.md <<'README'
# digger — published documentation site

Orphan branch serving the docs site at:
→  https://pq-cybarg.github.io/digger/

Source lives at `docs/` on `main`. Regenerate with `./sync-gh-pages.sh`
from a checkout of `main`. Auto-generated; don't hand-edit here.
README

git add -A
if git diff --cached --quiet; then
    echo "  → no changes since last sync — nothing to commit"
    rm -rf "$staging"
    exit 0
fi
TZ=UTC git commit -q -m "gh-pages: sync from docs/ @ ${src_commit_sha}

docs-tree: ${src_tree_sha}
source-commit: ${src_commit_sha}
"
echo "  ✓ commit on gh-pages: $(git log -1 --format='%h  %s')"

rm -rf "$staging"

if [[ "$PUSH" -eq 1 ]]; then
    echo "  → pushing gh-pages to origin"
    git push origin gh-pages
    echo "  ✓ pushed"
else
    echo
    echo "  Not pushed. Run when ready:"
    echo "      git push origin gh-pages"
fi
