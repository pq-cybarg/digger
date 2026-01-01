"""Shell init / profile file collector.

Reads every common shell rc / profile / login file under the
running user's home and under /etc/. Shell rc files are a
top-tier persistence + injection surface — a single line like
``alias sudo='/tmp/x'`` or ``curl ... | sh`` in ~/.bashrc fires
on every new terminal.

Existing detectors only partially cover this:
  - TrapDoor matches specific campaign markers in known rc files
  - PersistenceDetector / Lateral catch shared-NFS-home rc files
We don't have a collector that records the rc-file contents for
general audit — this fills the gap and the
``ShellProfileDetector`` runs SH1-SH8 rules on top.

Strictly read-only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS

# Per-user shell files (read under HOME).
_HOME_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
    ".profile",
    ".zshrc", ".zprofile", ".zlogin", ".zshenv", ".zlogout",
    ".kshrc",
    ".cshrc", ".tcshrc",
    ".inputrc",
)

# Per-user XDG / nested config (path relative to HOME).
_HOME_NESTED = (
    ".config/zsh/.zshrc",
    ".config/zsh/.zshenv",
    ".config/zsh/.zprofile",
    ".config/fish/config.fish",
    ".config/nushell/config.nu",
    ".config/nushell/env.nu",
    ".config/nu/config.nu",
    ".config/nu/env.nu",
)

# Globs under HOME — each matched file becomes its own artifact.
_HOME_GLOBS = (
    ".config/fish/conf.d/*.fish",
    ".config/fish/functions/*.fish",
)

# System-wide files / dirs.
_SYSTEM_FILES = (
    "/etc/bash.bashrc",
    "/etc/bash_completion",
    "/etc/profile",
    "/etc/zshrc",
    "/etc/zprofile",
    "/etc/zshenv",
    "/etc/csh.cshrc",
    "/etc/csh.login",
)

_SYSTEM_GLOBS = (
    "/etc/profile.d/*.sh",
    "/etc/profile.d/*",
)

# Read cap per file.
_MAX_BYTES = 256 * 1024


def _read_text(p: Path) -> tuple[str, dict] | None:
    """Return (contents, stat_dict) for the file or None on error."""
    try:
        st = p.stat()
    except OSError:
        return None
    if st.st_size > _MAX_BYTES * 4:
        # avoid loading huge files into memory; we still cap the
        # captured contents below.
        pass
    try:
        with open(p, "rb") as fh:
            data = fh.read(_MAX_BYTES)
    except (OSError, PermissionError):
        return None
    text = data.decode("utf-8", errors="replace")
    return text, {
        "size": st.st_size,
        "owner_uid": st.st_uid,
        "mode": st.st_mode,
        "mtime": st.st_mtime,
    }


class ShellProfileCollector(Collector):
    name = "shell.profile"
    category = "persistence"
    supported_os = (OS.LINUX, OS.MACOS)
    description = (
        "Shell init / profile / login files (bash, zsh, fish, "
        "nu, ksh, csh) under HOME and /etc/. Captures full text "
        "for downstream audit."
    )

    def collect(self) -> Iterable[Artifact]:
        home = Path.home()
        seen: set[str] = set()

        # Per-user direct files.
        for name in _HOME_FILES:
            p = home / name
            if str(p) in seen:
                continue
            seen.add(str(p))
            if not p.is_file():
                continue
            res = _read_text(p)
            if res is None:
                continue
            text, stat = res
            yield self.make(
                subject=f"shell-rc:user:{p}",
                path=str(p),
                scope="user",
                shell=_infer_shell(name),
                contents=text,
                **stat,
                mitre="T1546.004",
            )

        # Per-user XDG / nested.
        for rel in _HOME_NESTED:
            p = home / rel
            if str(p) in seen:
                continue
            seen.add(str(p))
            if not p.is_file():
                continue
            res = _read_text(p)
            if res is None:
                continue
            text, stat = res
            yield self.make(
                subject=f"shell-rc:user:{p}",
                path=str(p),
                scope="user",
                shell=_infer_shell(rel),
                contents=text,
                **stat,
                mitre="T1546.004",
            )

        # Per-user globs.
        for pat in _HOME_GLOBS:
            for p in sorted(home.glob(pat)):
                if str(p) in seen:
                    continue
                seen.add(str(p))
                if not p.is_file():
                    continue
                res = _read_text(p)
                if res is None:
                    continue
                text, stat = res
                yield self.make(
                    subject=f"shell-rc:user:{p}",
                    path=str(p),
                    scope="user",
                    shell=_infer_shell(p.name),
                    contents=text,
                    **stat,
                    mitre="T1546.004",
                )

        # System-wide direct files.
        for sysp in _SYSTEM_FILES:
            p = Path(sysp)
            if str(p) in seen:
                continue
            seen.add(str(p))
            if not p.is_file():
                continue
            res = _read_text(p)
            if res is None:
                continue
            text, stat = res
            yield self.make(
                subject=f"shell-rc:system:{p}",
                path=str(p),
                scope="system",
                shell=_infer_shell(p.name),
                contents=text,
                **stat,
                mitre="T1546.004",
            )

        # System-wide globs.
        for pat in _SYSTEM_GLOBS:
            base = Path(pat).parent
            if not base.is_dir():
                continue
            for p in sorted(base.glob(Path(pat).name)):
                if str(p) in seen:
                    continue
                seen.add(str(p))
                if not p.is_file():
                    continue
                res = _read_text(p)
                if res is None:
                    continue
                text, stat = res
                yield self.make(
                    subject=f"shell-rc:system:{p}",
                    path=str(p),
                    scope="system",
                    shell=_infer_shell(p.name),
                    contents=text,
                    **stat,
                    mitre="T1546.004",
                )


_ZSH_FILES = {
    ".zshrc", ".zprofile", ".zlogin", ".zshenv", ".zlogout",
}


def _infer_shell(name: str) -> str:
    n = name.lower()
    base = n.rsplit("/", 1)[-1]
    if "zsh" in n or base in _ZSH_FILES:
        return "zsh"
    if "bash" in n:
        return "bash"
    if "fish" in n:
        return "fish"
    if "nu" in n and ("config.nu" in n or "env.nu" in n):
        return "nushell"
    if n in (".kshrc",) or "/ksh" in n:
        return "ksh"
    if n in (".cshrc", ".tcshrc") or "csh" in n:
        return "csh"
    if n == ".profile" or n == "profile":
        return "sh"
    return "sh"
