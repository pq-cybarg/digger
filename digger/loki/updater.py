"""Clone or update Neo23x0/signature-base via git.

We shell out to `git` because:
  - signature-base is a real git repository, not a release tarball,
    and shallow clone + pull is the cleanest way to keep it current.
  - This is the same approach LOKI's own upgrader uses.

Falls back to a `curl`-based tarball download if `git` is unavailable.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

DEFAULT_REPO = "https://github.com/Neo23x0/signature-base.git"
DEFAULT_TARBALL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz"


@dataclass
class UpdateResult:
    target: Path
    method: str
    ok: bool
    message: str


def update_signature_base(
    target: Optional[Path | str] = None,
    repo_url: str = DEFAULT_REPO,
    tarball_url: str = DEFAULT_TARBALL,
    depth: int = 1,
    auto_sign_key: Optional[Path | str] = None,
    sign_alg: str = "ML-DSA-65",
) -> UpdateResult:
    """Clone signature-base if it doesn't exist; else fast-forward pull.

    If ``auto_sign_key`` is provided (or ``DIGGER_LOKI_SIGN_KEY`` env var
    is set), the corpus is PQC-signed immediately after a successful
    pull/clone so subsequent ``digger loki verify`` can confirm the
    bytes on disk haven't been tampered with.
    """
    from digger.loki.signature_base import signature_base_dir

    if target is None:
        target = signature_base_dir()
    target = Path(target).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)

    import os
    if auto_sign_key is None:
        env_key = os.environ.get("DIGGER_LOKI_SIGN_KEY")
        if env_key:
            auto_sign_key = env_key

    def _maybe_sign(result: UpdateResult) -> UpdateResult:
        if result.ok and auto_sign_key:
            try:
                from digger.loki.integrity import sign_snapshot
                sig_path = sign_snapshot(target, auto_sign_key, algorithm=sign_alg)
                result.message = (result.message + f"\nauto-signed: {sig_path}").strip()
            except Exception as exc:
                result.message = (result.message + f"\nauto-sign failed: {exc}").strip()
        return result

    git = shutil.which("git")
    if git:
        if (target / ".git").is_dir():
            try:
                r = subprocess.run(
                    [git, "-C", str(target), "pull", "--ff-only"],
                    capture_output=True, text=True, timeout=120, check=False,
                )
                return _maybe_sign(UpdateResult(
                    target=target, method="git pull",
                    ok=(r.returncode == 0),
                    message=(r.stdout + r.stderr).strip()[-400:],
                ))
            except Exception as exc:
                return UpdateResult(target, "git pull", False, str(exc))
        try:
            cmd = [git, "clone"]
            if depth > 0:
                cmd += ["--depth", str(depth)]
            cmd += [repo_url, str(target)]
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False,
            )
            return _maybe_sign(UpdateResult(
                target=target, method="git clone",
                ok=(r.returncode == 0),
                message=(r.stdout + r.stderr).strip()[-400:],
            ))
        except Exception as exc:
            return UpdateResult(target, "git clone", False, str(exc))

    # ---- tarball fallback ---- #
    try:
        r = requests.get(tarball_url, timeout=120)
        r.raise_for_status()
        # The tarball extracts to signature-base-master/. We want its contents
        # under `target`, so extract to a temp dir and move.
        scratch = target.parent / (target.name + ".tmp")
        if scratch.exists():
            shutil.rmtree(scratch)
        scratch.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
            tar.extractall(scratch)
        # find the single subdir
        subdirs = [d for d in scratch.iterdir() if d.is_dir()]
        if not subdirs:
            return UpdateResult(target, "tarball", False, "empty tarball")
        if target.exists():
            shutil.rmtree(target)
        shutil.move(str(subdirs[0]), str(target))
        shutil.rmtree(scratch, ignore_errors=True)
        return _maybe_sign(UpdateResult(target, "tarball", True, "downloaded archive"))
    except requests.RequestException as exc:
        return UpdateResult(target, "tarball", False, str(exc))
