"""Placeholder resolver for ForensicArtifacts path expansion.

ForensicArtifacts paths use ``%%knowledge_base.entry%%`` placeholders
that expand at runtime to host-specific values. Common ones:

    %%users.homedir%%             every user's home directory
    %%users.username%%            every username on the host
    %%users.appdata%%             Windows AppData per-user
    %%users.localappdata%%        Windows LocalAppData per-user
    %%environ_systemroot%%        Windows %SystemRoot% (e.g. C:\\Windows)
    %%environ_programfiles%%      Windows %ProgramFiles%
    %%environ_programfilesx86%%   Windows %ProgramFiles(x86)%
    %%environ_systemdrive%%       Windows %SystemDrive% (e.g. C:)
    %%environ_allusersprofile%%   Windows ProgramData
    %%fqdn%%                      Host FQDN

Resolution is "expand-to-many": a single template path with
``%%users.homedir%%`` resolves to N paths, one per user on the host.
We return a flat list of concrete paths.

When a placeholder has no known value on the current host (e.g. Windows
environment variables on a Linux host), we drop that template silently
— the artifact source can't apply here.
"""

from __future__ import annotations

import os
import re
import socket
from pathlib import Path


_PLACEHOLDER = re.compile(r"%%([\w._]+)%%")


def _enumerate_users_homedir() -> list[str]:
    """Return every real-user home dir on the host."""
    out: list[str] = []
    try:
        import pwd
        for u in pwd.getpwall():
            # Skip system users with no shell or with a non-real home
            if u.pw_uid < 500 and u.pw_uid != 0:
                continue
            if not u.pw_dir or u.pw_dir == "/var/empty":
                continue
            if Path(u.pw_dir).exists():
                out.append(u.pw_dir)
    except (ImportError, OSError):
        pass
    # Windows fallback / supplement: enumerate C:\Users\*
    for base in ("C:\\Users", "C:\\Documents and Settings"):
        p = Path(base)
        if p.is_dir():
            for child in p.iterdir():
                if child.is_dir() and child.name.lower() not in {
                    "all users", "default", "default user", "public",
                }:
                    out.append(str(child))
    return list(dict.fromkeys(out))  # de-dup preserving order


def _enumerate_usernames() -> list[str]:
    out: list[str] = []
    try:
        import pwd
        for u in pwd.getpwall():
            if u.pw_uid >= 500 or u.pw_uid == 0:
                out.append(u.pw_name)
    except (ImportError, OSError):
        pass
    for base in ("C:\\Users",):
        p = Path(base)
        if p.is_dir():
            for child in p.iterdir():
                if child.is_dir():
                    out.append(child.name)
    return list(dict.fromkeys(out))


def _fqdn() -> str:
    try:
        return socket.getfqdn()
    except Exception:
        return ""


def _windows_env(name: str) -> list[str]:
    v = os.environ.get(name)
    return [v] if v else []


class ArtifactResolver:
    """Expand ForensicArtifacts placeholders to host-specific values."""

    def __init__(self):
        self._mapping: dict[str, list[str]] = {
            "users.homedir":            _enumerate_users_homedir(),
            "users.username":           _enumerate_usernames(),
            "environ_systemroot":       _windows_env("SystemRoot"),
            "environ_systemdrive":      _windows_env("SystemDrive"),
            "environ_programfiles":     _windows_env("ProgramFiles"),
            "environ_programfilesx86":  _windows_env("ProgramFiles(x86)"),
            "environ_allusersprofile":  _windows_env("ALLUSERSPROFILE")
                                          or _windows_env("ProgramData"),
            "environ_windir":           _windows_env("WINDIR")
                                          or _windows_env("SystemRoot"),
            "fqdn":                     [_fqdn()] if _fqdn() else [],
        }
        # users.appdata / users.localappdata are per-user — derive from
        # the homedirs.
        self._mapping["users.appdata"] = [
            f"{h}/AppData/Roaming"
            for h in self._mapping["users.homedir"]
        ]
        self._mapping["users.localappdata"] = [
            f"{h}/AppData/Local"
            for h in self._mapping["users.homedir"]
        ]
        self._mapping["users.desktop"] = [
            f"{h}/Desktop"
            for h in self._mapping["users.homedir"]
        ]

    def expand(self, template: str) -> list[str]:
        """Expand one path template to N concrete paths.

        If the template has no placeholders, returns a single-element
        list with the template verbatim. If a placeholder has no known
        value, returns an empty list."""
        placeholders = _PLACEHOLDER.findall(template)
        if not placeholders:
            return [template]

        # For each placeholder, look up the value list.
        value_lists: list[list[str]] = []
        for ph in placeholders:
            vals = self._mapping.get(ph)
            if not vals:
                return []  # unknown / not-available placeholder
            value_lists.append(vals)

        # Cartesian product across placeholders. Common case (one
        # placeholder repeated) avoids combinatorial blow-up because
        # each placeholder's value list is the same object reused.
        results: list[str] = []
        from itertools import product
        for combo in product(*value_lists):
            out = template
            for ph, val in zip(placeholders, combo):
                out = out.replace(f"%%{ph}%%", val, 1)
            # Replace any remaining occurrences of the same placeholder.
            for ph, val in zip(placeholders, combo):
                out = out.replace(f"%%{ph}%%", val)
            results.append(out)
        return results

    def expand_many(self, templates: list[str]) -> list[str]:
        out: list[str] = []
        for t in templates:
            out.extend(self.expand(t))
        return list(dict.fromkeys(out))  # de-dup preserving order
