"""Cross-platform code-signing verification.

verify_path(path) -> SigInfo

  state:   one of SUPPORTED_STATES
  signer:  authority / package name where derivable
  details: free-form details string from the underlying tool
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


SUPPORTED_STATES = (
    "signed",          # platform-trusted signature verified
    "ad_hoc",          # macOS ad-hoc: signed but with no developer identity
    "unsigned",        # no signature at all
    "invalid",         # signature present, verification failed
    "expired",         # certificate expired
    "revoked",         # certificate revoked
    "package_owned",   # Linux: file belongs to a package
    "package_orphan",  # Linux: no package claims this file
    "skipped",         # file unreadable / unsupported platform / not applicable
    "unknown",         # check ran but result wasn't classifiable
)


@dataclass
class SigInfo:
    path: str
    state: str
    signer: Optional[str] = None      # CN / authority / package name
    team_id: Optional[str] = None     # macOS team identifier
    cdhash: Optional[str] = None      # macOS code-directory hash
    details: str = ""
    raw: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---- macOS ------------------------------------------------------------- #


def _verify_macos(path: str) -> SigInfo:
    info = SigInfo(path=path, state="unknown")
    if not shutil.which("codesign"):
        info.state = "skipped"
        info.details = "codesign(1) not available"
        return info
    try:
        cs = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", "-vv", path],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        info.state = "skipped"
        info.details = f"codesign failed to run: {exc}"
        return info
    info.raw = (cs.stderr or cs.stdout).strip()

    # codesign reports on stderr by convention.
    err = cs.stderr or ""
    if cs.returncode == 0:
        info.state = "signed"
    else:
        if "code object is not signed" in err.lower() or "not signed at all" in err.lower():
            info.state = "unsigned"
        elif "ad-hoc" in err.lower():
            info.state = "ad_hoc"
        elif "expired" in err.lower():
            info.state = "expired"
        elif "revoked" in err.lower():
            info.state = "revoked"
        else:
            info.state = "invalid"

    # Pull details with codesign -dvv (works even on ad-hoc / unsigned for
    # the ad-hoc case). Capture team identifier and CDHash if available.
    try:
        dv = subprocess.run(
            ["codesign", "-dvv", path],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except Exception:
        dv = None
    if dv:
        body = (dv.stderr or "") + (dv.stdout or "")
        m_auth = re.search(r"^Authority=(.+)$", body, re.M)
        if m_auth:
            info.signer = m_auth.group(1).strip()
        m_tid = re.search(r"^TeamIdentifier=(\S+)", body, re.M)
        if m_tid:
            info.team_id = m_tid.group(1).strip()
            if info.team_id.lower() == "not set":
                # Apple's apparent canonical phrasing when no team id.
                info.team_id = None
                if info.state == "signed":
                    # Apple's first-party tools may sign with no team id;
                    # we still call this signed. Some malware does this
                    # too, so propagate it as a detail.
                    info.details = "no TeamIdentifier"
        m_cd = re.search(r"^CDHash=(\S+)", body, re.M)
        if m_cd:
            info.cdhash = m_cd.group(1).strip()
        if not info.signer and "Signature=adhoc" in body:
            info.state = "ad_hoc"
            info.signer = "adhoc"

    return info


# ---- Linux ------------------------------------------------------------- #


_DPKG_RE = re.compile(r"^([^:]+):\s")


def _verify_linux(path: str) -> SigInfo:
    info = SigInfo(path=path, state="unknown")
    if shutil.which("dpkg"):
        try:
            r = subprocess.run(
                ["dpkg", "-S", path],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except Exception as exc:
            info.state = "skipped"
            info.details = f"dpkg failed: {exc}"
            return info
        info.raw = (r.stdout or r.stderr).strip()[:600]
        if r.returncode == 0:
            m = _DPKG_RE.match(r.stdout or "")
            if m:
                info.signer = m.group(1).strip()
                info.state = "package_owned"
                info.details = "claimed by dpkg package"
                return info
        info.state = "package_orphan"
        info.details = "no dpkg package claims this file"
        return info
    if shutil.which("rpm"):
        try:
            r = subprocess.run(
                ["rpm", "-qf", path],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except Exception as exc:
            info.state = "skipped"
            info.details = f"rpm failed: {exc}"
            return info
        info.raw = (r.stdout or r.stderr).strip()[:600]
        if r.returncode == 0 and "not owned" not in (r.stdout or "").lower():
            info.signer = (r.stdout or "").strip()
            info.state = "package_owned"
            return info
        info.state = "package_orphan"
        info.details = "no rpm package claims this file"
        return info
    info.state = "skipped"
    info.details = "no supported package manager available"
    return info


# ---- Windows ---------------------------------------------------------- #


def _verify_windows(path: str) -> SigInfo:
    info = SigInfo(path=path, state="skipped",
                   details="Windows code-signing check not implemented in v1; "
                           "use signtool / Get-AuthenticodeSignature externally")
    return info


# ---- public --------------------------------------------------------- #


def verify_path(path: str | os.PathLike) -> SigInfo:
    p = str(path)
    if not p or not os.path.exists(p):
        return SigInfo(path=p, state="skipped", details="path missing or unreadable")
    if not os.path.isfile(p):
        return SigInfo(path=p, state="skipped", details="not a regular file")
    if sys.platform == "darwin":
        return _verify_macos(p)
    if sys.platform == "linux":
        return _verify_linux(p)
    if sys.platform == "win32":
        return _verify_windows(p)
    return SigInfo(path=p, state="skipped",
                   details=f"unsupported platform: {sys.platform}")
