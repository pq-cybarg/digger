# tools/identity — multi-identity GitHub tooling

Two small tools that prevent the class of mistakes that happen when one
machine has several GitHub identities (work account, personal account,
isolated-purpose account, etc.).

## Why it exists

GitHub identifies SSH-authenticated users by key fingerprint. The
`User <name>` field in `~/.ssh/config` is cosmetic and does **not**
change which GitHub account a push lands under. Multi-identity hosts
where every block uses `Host github.com` will silently auth every
operation as whichever identity comes first in the file — without any
warning to the user.

`ghid` forces explicit identity-aliased URLs
(`git@github-<identity>:owner/repo.git`) and provides safety nets so
the wrong identity cannot slip through. `ghidbar` is a macOS menu-bar
companion that surfaces the current repo's bound identity at a glance.

## Components

| File | What it is |
|---|---|
| `ghid` | Bash CLI: list / doctor / current / switch / lock / unlock / verify / whoami / new / rotate |
| `ghidbar.py` | macOS menu-bar app (uses [rumps](https://github.com/jaredks/rumps)) |
| `ghidbar` | shell launcher for the menu-bar app |
| `ghidbar.plist` | launchd template for auto-start at login (uses `__HOME__` placeholder) |
| `install.sh` | One-shot installer / upgrader / uninstaller |

## Install

```bash
# From the repo root:
./tools/identity/install.sh                # ghid + ghidbar in ~/.local
./tools/identity/install.sh --launchd      # also register auto-start at login

# Uninstall:
./tools/identity/install.sh --uninstall    # removes binaries + venv + state
                                           # ~/.ssh/config + keys untouched
```

After install, add `~/.local/bin` to your `PATH` if it isn't already,
then run `ghid doctor` to sanity-check your `~/.ssh/config`.

## Quick start

```bash
# 1. Add an identity (creates an SSH key + alias in ~/.ssh/config).
#    Reuses an existing ~/.ssh/<name>-GitHub key if present.
ghid new pq-cybarg

# 2. In a repo, bind it to that identity and lock so any push under a
#    different identity is refused:
cd ~/some/repo
ghid switch pq-cybarg
ghid lock pq-cybarg

# 3. Confirm GitHub actually resolves the key to the expected user:
ghid verify pq-cybarg
# → ✓ alias github-pq-cybarg resolves to GitHub user pq-cybarg
```

In the menu bar, ghidbar shows `🔑 pq-cybarg 🔒` while you're in the repo
(its watched repo is set via the `ghidbar-here` / `gbh` shell function
added to `~/.zshrc` by the install).

## Key rotation

```bash
ghid rotate pq-cybarg
# → Archives old key to ~/.ssh/.ghid-archive/, generates fresh one,
#   prints both new pubkey and old fingerprint so you know what to
#   add and what to delete on github.com/settings/keys.
```

## Identity isolation guarantee

When `ghid lock <id>` is set on a repo, the unified pre-push hook
(installed by `install-hooks.sh` in the repo root) refuses any push
whose remote URL doesn't go through `git@github-<id>:...`.

The lock survives across:
- Manual `git push` from any terminal
- IDE-integrated push buttons (most IDEs honor git hooks)
- `git push --force` (still subject to pre-push)

The lock does **not** prevent:
- Renaming the remote URL (which `ghid switch` does intentionally) —
  the lock checks identity, not URL stability
- Removing the hook by hand or with `--no-verify` on push (git's
  documented escape hatch)
