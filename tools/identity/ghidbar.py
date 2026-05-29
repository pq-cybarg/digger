#!/usr/bin/env python3
"""ghidbar — macOS menu-bar UI for the `ghid` GitHub identity manager.

Sits in the menu bar. Shows the GitHub identity bound to the selected
repo's origin in the title (🔑 myalias ✓). Click to switch identities,
lock the repo, verify, or change the watched repo. All logic shells out
to the `ghid` CLI so the two stay in lockstep.

Watched-repo state lives at ~/.config/ghidbar/state.json. macOS
notifications announce the result of verify / switch / lock operations.

Why a GUI: multi-identity GitHub on one host is a class of mistake
that's easy to make and hard to undo. Putting the active identity in
the menu bar at all times turns "did I push as the right account?"
from a question you ask after the fact into a glance.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

import rumps


GHID = shutil.which("ghid") or str(Path.home() / ".local/bin/ghid")
STATE_DIR = Path.home() / ".config" / "ghidbar"
STATE_PATH = STATE_DIR / "state.json"
LOG_PATH = STATE_DIR / "ghidbar.log"
LOCK_PATH = STATE_DIR / "ghidbar.lock"

# Configure once at import. Logs survive across terminal closes / launchd
# restarts so the user can always check ~/.config/ghidbar/ghidbar.log.
STATE_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
)
log = logging.getLogger("ghidbar")
# Also route uncaught exceptions into the log
def _excepthook(exc_type, exc, tb):
    log.error("uncaught: %s", "".join(traceback.format_exception(exc_type, exc, tb)))
    sys.__excepthook__(exc_type, exc, tb)
sys.excepthook = _excepthook


# ---- ghid wrapper ---- #


def ghid(*args: str, timeout: int = 20) -> tuple[int, str]:
    """Run ghid <args>. Returns (returncode, combined-output-stripped-of-ansi)."""
    if not Path(GHID).is_file():
        return 127, f"ghid CLI not found at {GHID}"
    try:
        r = subprocess.run(
            [GHID, *args],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(load_state().get("repo") or Path.home()),
            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, f"failed to launch ghid: {exc}"
    # Strip ANSI color codes (ghid uses them but we want clean strings)
    import re
    clean = re.sub(r"\x1b\[[0-9;]*[mGKHF]", "", (r.stdout or "") + (r.stderr or ""))
    return r.returncode, clean.strip()


def list_identities() -> list[str]:
    """Parse `ghid list` for identity names."""
    code, out = ghid("list")
    ids: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("github-"):
            continue
        alias = line.split()[0]
        ids.append(alias.replace("github-", "", 1))
    return ids


def current_repo_identity(repo: Path) -> tuple[str, bool, bool]:
    """For the given repo, return (identity, verified, locked).

    verified=True means `ghid verify` agreed the SSH key resolves to the
    expected GitHub user. locked=True means a ghid pre-push hook is
    installed.
    """
    if not (repo / ".git").exists():
        return "", False, False
    # Pull origin URL directly to skip ghid's ANSI for this hot-path call.
    try:
        url = subprocess.check_output(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            stderr=subprocess.DEVNULL, text=True, timeout=3,
        ).strip()
    except (subprocess.SubprocessError, OSError):
        url = ""
    identity = ""
    if url.startswith("git@github-"):
        identity = url[len("git@github-"):].split(":", 1)[0]
    locked = False
    hook = repo / ".git" / "hooks" / "pre-push"
    if hook.is_file():
        try:
            if "GHID_LOCK=" in hook.read_text(errors="replace"):
                locked = True
        except OSError:
            pass
    return identity, False, locked  # verified left False here (slow op)


# ---- state ---- #


def load_state() -> dict:
    if not STATE_PATH.is_file():
        return {}
    try:
        return json.loads(STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


# ---- UI ---- #


class GhidBarApp(rumps.App):
    def __init__(self) -> None:
        super().__init__("🔑 ghid", quit_button=None)
        self.menu = self._build_menu()
        # Auto-refresh title every 5 s in case the repo state changed
        # outside the app (e.g. user ran `ghid lock` in a terminal).
        rumps.Timer(self._tick, 5).start()

    # ---- menu construction ---- #

    def _build_menu(self) -> list:
        items: list = []
        state = load_state()
        repo = Path(state.get("repo", "")) if state.get("repo") else None

        if not repo:
            items.append(rumps.MenuItem("(no repo selected)"))
        else:
            identity, _verified, locked = current_repo_identity(repo)
            items.append(rumps.MenuItem(f"Repo: {self._short(repo)}",
                                          callback=self._open_repo_in_finder))
            items.append(rumps.MenuItem(
                f"Identity: {identity or '⚠ not aliased'}" +
                ("  🔒 LOCKED" if locked else "")))
            items.append(None)

        items.append(rumps.MenuItem("Change repo…",
                                     callback=self._cmd_pick_repo))
        items.append(None)

        # Switch submenu
        switch = rumps.MenuItem("Switch identity")
        for ident in list_identities() or ["(run ghid doctor)"]:
            switch.add(rumps.MenuItem(ident,
                                       callback=self._make_switch_cb(ident)))
        items.append(switch)

        items.append(rumps.MenuItem("Verify identity",
                                     callback=self._cmd_verify))
        if repo:
            _, _, locked = current_repo_identity(repo)
            items.append(rumps.MenuItem(
                "Unlock this repo" if locked else "Lock this repo",
                callback=self._cmd_toggle_lock))
        items.append(None)

        manage = rumps.MenuItem("Manage identities")
        for ident in list_identities():
            manage.add(rumps.MenuItem(
                f"{ident}",
                callback=self._make_identity_info_cb(ident)))
        manage.add(None)
        manage.add(rumps.MenuItem("Add new identity…",
                                    callback=self._cmd_add_identity))
        items.append(manage)

        items.append(rumps.MenuItem("Doctor (check config)",
                                     callback=self._cmd_doctor))
        items.append(None)
        items.append(rumps.MenuItem("Quit ghidbar",
                                     callback=rumps.quit_application))
        return items

    def _refresh_menu(self) -> None:
        self.menu.clear()
        for item in self._build_menu():
            if item is None:
                self.menu.add(rumps.separator)
            else:
                self.menu.add(item)
        self._tick(None)

    # ---- title ticker ---- #

    def _tick(self, _sender) -> None:
        state = load_state()
        repo = Path(state.get("repo", "")) if state.get("repo") else None
        if not repo or not (repo / ".git").exists():
            self.title = "🔑 ghid"
            return
        identity, _verified, locked = current_repo_identity(repo)
        if not identity:
            self.title = "🔑 ⚠"
            return
        lock = " 🔒" if locked else ""
        self.title = f"🔑 {identity}{lock}"

    # ---- helpers ---- #

    @staticmethod
    def _short(p: Path) -> str:
        s = str(p).replace(str(Path.home()), "~")
        return s if len(s) <= 38 else "…" + s[-37:]

    @staticmethod
    def _notify(title: str, subtitle: str, message: str = "") -> None:
        try:
            rumps.notification(title=title, subtitle=subtitle, message=message)
        except Exception:
            # Notifications need a signed bundle on recent macOS; fall back
            # to a tiny modal so the user still sees the result.
            rumps.alert(title=title, message=(subtitle + "\n\n" + message).strip())

    # ---- command callbacks ---- #

    def _open_repo_in_finder(self, _sender) -> None:
        state = load_state()
        repo = state.get("repo")
        if repo and Path(repo).exists():
            subprocess.run(["open", repo], check=False)

    def _cmd_pick_repo(self, _sender) -> None:
        # AppleScript file picker — rumps doesn't ship one.
        script = '''
        set chosen to choose folder with prompt "Pick a git repo for ghidbar to watch"
        return POSIX path of chosen
        '''
        try:
            r = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, text=True, timeout=600,
            )
            path = (r.stdout or "").strip().rstrip("/")
            if not path:
                return
            if not (Path(path) / ".git").exists():
                rumps.alert(title="Not a git repo",
                             message=f"{path} doesn't contain a .git directory.")
                return
            save_state({"repo": path})
            self._refresh_menu()
        except subprocess.SubprocessError:
            pass

    def _make_switch_cb(self, ident: str):
        def cb(_sender):
            state = load_state()
            repo = state.get("repo")
            if not repo:
                rumps.alert("No repo selected",
                             "Pick a repo with “Change repo…” first.")
                return
            code, out = ghid("switch", ident)
            ok = code == 0
            self._notify(
                title=("ghid switch — " + ("OK" if ok else "FAILED")),
                subtitle=(f"{Path(repo).name} → {ident}" if ok else
                          f"could not switch to {ident}"),
                message=out.splitlines()[-3:][0] if out else "",
            )
            self._refresh_menu()
        return cb

    def _cmd_verify(self, _sender) -> None:
        state = load_state()
        repo = state.get("repo")
        if not repo:
            rumps.alert("No repo selected", "Pick a repo first.")
            return
        identity, _, _ = current_repo_identity(Path(repo))
        if not identity:
            rumps.alert("Not aliased",
                         "This repo's origin URL doesn't use a ghid identity alias. Switch identity first.")
            return
        code, out = ghid("verify", identity, timeout=15)
        ok = code == 0
        self._notify(
            title=("Identity verified" if ok else "Identity MISMATCH"),
            subtitle=f"expected: {identity}",
            message=out,
        )

    def _cmd_toggle_lock(self, _sender) -> None:
        state = load_state()
        repo = state.get("repo")
        if not repo:
            return
        identity, _, locked = current_repo_identity(Path(repo))
        if locked:
            code, out = ghid("unlock")
            self._notify("Lock removed", "", out)
        else:
            if not identity:
                rumps.alert("Cannot lock", "Switch to an identity first.")
                return
            code, out = ghid("lock", identity)
            self._notify(f"Locked to {identity}",
                          "Push attempts under any other identity will be refused.",
                          out)
        self._refresh_menu()

    def _cmd_doctor(self, _sender) -> None:
        code, out = ghid("doctor", timeout=10)
        rumps.alert(title="ghid doctor",
                     message=out if out else "(no output)")

    def _cmd_add_identity(self, _sender) -> None:
        win = rumps.Window(
            title="Add GitHub identity",
            message=("Enter the GitHub username for the new identity.\n"
                     "ghidbar will copy the setup command to your clipboard "
                     "for you to run in your terminal of choice. The command "
                     "generates an SSH key (you'll choose a passphrase), "
                     "appends an alias to ~/.ssh/config, and prints the "
                     "public key for you to register with GitHub."),
            default_text="",
            dimensions=(280, 24),
        )
        win.add_buttons("Cancel")
        response = win.run()
        if response.clicked != 1:  # OK is button index 1 in rumps
            return
        ident = response.text.strip()
        if not ident or "/" in ident or " " in ident:
            rumps.alert(title="Invalid identity name",
                         message="Use a plain alphanumeric name (no spaces or slashes).")
            return
        cmd = f"{GHID} new {ident}"
        # Copy via pbcopy: no Automation permission needed, terminal-agnostic.
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=cmd.encode("utf-8"))
            copied = (p.returncode == 0)
        except (OSError, subprocess.SubprocessError) as exc:
            rumps.alert(
                title="Could not copy to clipboard",
                message=(f"pbcopy failed: {exc}\n\n"
                         f"Run this manually in your terminal:\n\n  {cmd}"),
            )
            return
        if not copied:
            rumps.alert(
                title="Could not copy to clipboard",
                message=(f"pbcopy returned non-zero.\n\n"
                         f"Run this manually in your terminal:\n\n  {cmd}"),
            )
            return
        rumps.alert(
            title="Command copied — paste and run it",
            message=(
                f"In any terminal, paste (⌘V) and run:\n\n"
                f"  {cmd}\n\n"
                f"You'll be prompted for an SSH key passphrase, then "
                f"the command prints the public key. Paste the public "
                f"key at https://github.com/settings/ssh/new in a "
                f"fresh private/incognito browser window logged in as "
                f"'{ident}'.\n\n"
                f"When done, click 'Verify identity' in this menu to "
                f"confirm GitHub resolves the key to '{ident}'."
            ),
        )
        self._refresh_menu()

    def _make_identity_info_cb(self, ident: str):
        def cb(_sender):
            code, out = ghid("verify", ident, timeout=15)
            ok = code == 0
            self._notify(
                title=f"{ident}: " + ("✓ matches GitHub" if ok else "MISMATCH"),
                subtitle="",
                message=out,
            )
        return cb


def _acquire_singleton_lock() -> None:
    """Refuse to launch if another ghidbar is already running.

    Uses fcntl.flock on a pidfile — atomic, automatically released on
    process exit (even on SIGKILL), works across launchd respawns and
    manual launches. If the lock is held, log and exit cleanly so the
    menu bar stays at one icon no matter how many times the launcher
    is invoked.
    """
    import atexit
    import fcntl
    fh = open(LOCK_PATH, "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        # Another instance has the lock. Read whose PID it is, log it,
        # and exit silently — the user sees the existing icon stay.
        fh.seek(0)
        existing = fh.read().strip()
        log.info("another ghidbar is running (pid %s); this instance exits",
                  existing or "?")
        sys.exit(0)
    # Got the lock. Write our pid + keep fh open for the process lifetime.
    fh.seek(0); fh.truncate()
    fh.write(f"{os.getpid()}\n"); fh.flush()
    # Keep the fh alive (module-level) and clean up on exit.
    globals()["_lock_fh"] = fh
    def _cleanup():
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            fh.close()
            if LOCK_PATH.exists():
                LOCK_PATH.unlink()
        except OSError:
            pass
    atexit.register(_cleanup)


def main() -> None:
    if not Path(GHID).is_file():
        print(f"ghid CLI not found at {GHID} — install it first.", file=sys.stderr)
        sys.exit(1)
    _acquire_singleton_lock()
    log.info("ghidbar starting (pid=%d)", os.getpid())
    GhidBarApp().run()


if __name__ == "__main__":
    main()
