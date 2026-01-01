#!/usr/bin/env bash
#
# tools/opsec/bulk-cleanse.sh — bulk timestamp opsec cleanse across
# multiple local clones.
#
# For each local repo path passed on the command line (or stdin):
#   1. Verify remote origin uses git@github-pq-cybarg:pq-cybarg/<name>.git
#      (skipped if remote is local-only / not pq-cybarg-owned)
#   2. Disable any post-commit hook present during the operation
#   3. filter-branch --env-filter rewrites every commit's
#      author + committer date to the sentinel (default
#      2026-01-01T00:00:00+0000)
#   4. Delete refs/original/* (filter-branch's backup refs)
#   5. Force-push all branches + tags
#   6. reflog expire + gc --prune=now --aggressive
#   7. Run wipe-birthtimes.py on the working tree
#   8. Re-enable the post-commit hook
#   9. Verify every commit object bears the sentinel
#
# Usage:
#   ./bulk-cleanse.sh <repo-path> [<repo-path> ...]
#   ./bulk-cleanse.sh < paths.txt              # one path per line
#
# Config (env vars, all optional):
#   DIGGER_CLEANSE_DATE   — ISO sentinel (default below)
#   DIGGER_CLEANSE_TOUCH  — touch -t format matching the above
#
# Identity-isolation guardrail: only touches remotes that route
# through the github-pq-cybarg SSH alias OR origin-local. Refuses
# to push if the remote is HTTPS (would use osxkeychain).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WIPE_BTIMES="$SCRIPT_DIR/wipe-birthtimes.py"

DATE="${DIGGER_CLEANSE_DATE:-2026-01-01T00:00:00+0000}"
TOUCH="${DIGGER_CLEANSE_TOUCH:-202601010000.00}"
EXPECTED_SENTINEL_TS=$(date -j -u -f "%Y-%m-%dT%H:%M:%S%z" \
    "${DATE/+00:00/+0000}" "+%s" 2>/dev/null || echo 1767225600)

c_grn() { printf "\033[32m%s\033[0m" "$*"; }
c_red() { printf "\033[31m%s\033[0m" "$*"; }
c_yel() { printf "\033[33m%s\033[0m" "$*"; }
c_dim() { printf "\033[2m%s\033[0m" "$*"; }
ok()    { echo "    $(c_grn ✓) $*"; }
warn()  { echo "    $(c_yel ⚠) $*"; }
err()   { echo "    $(c_red ✗) $*" >&2; }

cleanse_one() {
    local repo="$1"
    echo
    echo "==[ $(c_dim "$repo") ]=="

    [[ -d "$repo/.git" ]] || { err "not a git repo: $repo"; return 1; }

    local url
    url=$(git -C "$repo" config --get remote.origin.url 2>/dev/null || true)
    case "$url" in
        git@github-pq-cybarg:pq-cybarg/*)
            ok "remote uses identity alias  ($url)"
            ;;
        https://github.com/pq-cybarg/*)
            err "remote uses HTTPS ($url) — would leak via osxkeychain. Rewrite to git@github-pq-cybarg:... first."
            return 1
            ;;
        "")
            warn "no origin remote; will cleanse history but skip push"
            ;;
        *)
            err "unexpected remote: $url. Skipping."
            return 1
            ;;
    esac

    # Stash a post-commit hook out of the way (recursion guard insufficient
    # for filter-branch's per-commit replay).
    local moved_hook=0
    if [[ -f "$repo/.git/hooks/post-commit" ]]; then
        mv "$repo/.git/hooks/post-commit" "$repo/.git/hooks/post-commit.bulk-cleanse.disabled"
        moved_hook=1
    fi

    # Rewrite. filter-branch is slow but reliable for env-only changes.
    if ! FILTER_BRANCH_SQUELCH_WARNING=1 \
            git -C "$repo" filter-branch --env-filter "
                export GIT_AUTHOR_DATE='$DATE'
                export GIT_COMMITTER_DATE='$DATE'
            " --tag-name-filter cat -- --all >/tmp/bulk-cleanse.$$.log 2>&1; then
        err "filter-branch failed; see /tmp/bulk-cleanse.$$.log"
        [[ "$moved_hook" -eq 1 ]] && mv "$repo/.git/hooks/post-commit.bulk-cleanse.disabled" "$repo/.git/hooks/post-commit" || true
        return 1
    fi
    ok "filter-branch complete"

    # Drop refs/original/* (the safety-backup refs filter-branch creates).
    git -C "$repo" for-each-ref --format='%(refname)' refs/original/ \
        | while read r; do git -C "$repo" update-ref -d "$r"; done

    # Reflog + gc.
    git -C "$repo" reflog expire --expire=now --all 2>/dev/null
    git -C "$repo" gc --prune=now --aggressive >/dev/null 2>&1
    ok "reflog expired + gc complete"

    # Verify every reachable commit bears the sentinel.
    local n_total n_normalized
    n_total=$(git -C "$repo" log --all --oneline 2>/dev/null | wc -l | tr -d ' ')
    n_normalized=$(git -C "$repo" log --all --format='%at|%ct' 2>/dev/null \
        | grep -c "^${EXPECTED_SENTINEL_TS}|${EXPECTED_SENTINEL_TS}$" || true)
    if [[ "$n_normalized" = "$n_total" ]]; then
        ok "all $n_total commits at sentinel"
    else
        err "$n_normalized / $n_total at sentinel — bailing before push"
        [[ "$moved_hook" -eq 1 ]] && mv "$repo/.git/hooks/post-commit.bulk-cleanse.disabled" "$repo/.git/hooks/post-commit" || true
        return 1
    fi

    # Force-push every ref to the remote (if we have one).
    if [[ -n "$url" ]]; then
        # Push branches and tags separately for cleaner output.
        git -C "$repo" push --force --all origin 2>&1 | tail -5 | sed 's/^/      /'
        git -C "$repo" push --force --tags origin 2>&1 | tail -5 | sed 's/^/      /'
        ok "force-pushed branches + tags"
    fi

    # Wipe working-tree btime/mtime/atime on tracked files.
    if [[ -x "$WIPE_BTIMES" ]]; then
        (cd "$repo" && "$WIPE_BTIMES" 2>&1 | head -2 | sed 's/^  /    /')
    else
        warn "wipe-birthtimes.py not executable; skipping working-tree btime wipe"
    fi

    # Restore the post-commit hook so future commits stay normalized.
    [[ "$moved_hook" -eq 1 ]] && mv "$repo/.git/hooks/post-commit.bulk-cleanse.disabled" "$repo/.git/hooks/post-commit"

    ok "done"
}

# Collect repo paths from args + stdin.
declare -a REPOS=()
for arg in "$@"; do REPOS+=("$arg"); done
if [[ ${#REPOS[@]} -eq 0 ]] && [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        [[ -n "$line" ]] && REPOS+=("$line")
    done
fi
if [[ ${#REPOS[@]} -eq 0 ]]; then
    echo "usage: $0 <repo-path> [<repo-path> ...]" >&2
    echo "   or: $0 < paths.txt" >&2
    exit 2
fi

n_ok=0; n_err=0
for repo in "${REPOS[@]}"; do
    if cleanse_one "$repo"; then
        n_ok=$((n_ok+1))
    else
        n_err=$((n_err+1))
    fi
done

echo
echo "================================================================"
echo "  bulk-cleanse done — $n_ok succeeded, $n_err failed"
echo "================================================================"
[[ "$n_err" -eq 0 ]]
