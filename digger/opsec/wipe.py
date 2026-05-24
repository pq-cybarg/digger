"""Secure-delete a case directory.

Modern filesystems (SSD/NVMe with wear-leveling, copy-on-write FSes like
APFS / Btrfs / ZFS) cannot guarantee bit-level overwrite — the
controller may have moved the data block elsewhere transparently. Treat
"secure wipe" as best-effort hardening on top of OS-native deletion, not
as proof against forensic recovery on flash storage.

For confidential cases on flash, the only durable answer is full-disk
encryption (so plaintext was never persisted in the clear). For cases on
spinning rust, the multi-pass overwrite below is sufficient.
"""

from __future__ import annotations

import os
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class WipeResult:
    target: Path
    files_overwritten: int = 0
    bytes_overwritten: int = 0
    files_unlinked: int = 0
    errors: list[str] = field(default_factory=list)
    note: str = ""


def secure_wipe_file(path: str | Path, passes: int = 3, chunk: int = 1 << 20) -> WipeResult:
    """Overwrite a file's contents `passes` times with random data, then
    truncate and unlink it."""
    p = Path(path)
    out = WipeResult(target=p)
    try:
        size = p.stat().st_size
    except OSError as exc:
        out.errors.append(f"{p}: stat failed: {exc}")
        return out
    try:
        with open(p, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(chunk, remaining)
                    f.write(secrets.token_bytes(n))
                    remaining -= n
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            f.seek(0)
            f.truncate(0)
            out.files_overwritten = 1
            out.bytes_overwritten = size * passes
    except OSError as exc:
        out.errors.append(f"{p}: overwrite failed: {exc}")
    try:
        os.remove(p)
        out.files_unlinked = 1
    except OSError as exc:
        out.errors.append(f"{p}: unlink failed: {exc}")
    return out


def secure_wipe_dir(case_dir: str | Path, passes: int = 3) -> WipeResult:
    """Walk and overwrite every file under ``case_dir`` before removing it.

    Refuses paths that don't look like digger case directories (must
    contain ``evidence.db`` or ``chain_of_custody.json``) to prevent
    accidentally wiping the wrong directory.
    """
    d = Path(case_dir).expanduser().resolve()
    out = WipeResult(target=d)
    if not d.exists():
        out.errors.append(f"{d}: does not exist")
        return out
    if not d.is_dir():
        out.errors.append(f"{d}: not a directory")
        return out
    sentinels = ("evidence.db", "chain_of_custody.json")
    if not any((d / s).exists() for s in sentinels):
        out.errors.append(
            f"{d}: does not contain {sentinels} — refusing to wipe (safety check)"
        )
        return out

    # Bottom-up walk so directories are empty when we rmdir them
    for root, dirs, files in os.walk(d, topdown=False):
        for name in files:
            full = Path(root) / name
            sub = secure_wipe_file(full, passes=passes)
            out.files_overwritten += sub.files_overwritten
            out.bytes_overwritten += sub.bytes_overwritten
            out.files_unlinked    += sub.files_unlinked
            out.errors            += sub.errors
        for name in dirs:
            try:
                os.rmdir(Path(root) / name)
            except OSError as exc:
                out.errors.append(f"{Path(root) / name}: rmdir failed: {exc}")
    try:
        os.rmdir(d)
    except OSError as exc:
        out.errors.append(f"{d}: rmdir failed: {exc}")

    out.note = (
        "Best-effort wipe complete. On SSD/NVMe with wear-leveling, "
        "block-level recovery may still be possible — for adversaries "
        "with physical disk access, rely on full-disk encryption rather "
        "than overwrite."
    )
    return out
