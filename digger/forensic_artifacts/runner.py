"""Execute a ForensicArtifacts artifact and emit digger Artifacts.

Supports the three source types that cover ~80% of definitions:

  FILE       — read each resolved path and emit one Artifact per file
               (size, mtime, sha256 when small, content snippet)
  DIRECTORY  — enumerate each resolved directory and emit one
               Artifact listing the entries (no content)
  COMMAND    — shell out to a command and emit one Artifact with the
               captured stdout/stderr/rc

PATH and ARTIFACT_GROUP are also handled (PATH treated like
DIRECTORY-without-listing; ARTIFACT_GROUP recursively runs the
referenced artifacts).

REGISTRY_KEY / REGISTRY_VALUE / WMI / VOLATILE_REGISTRY_KEY return
an "unsupported" Artifact stub on non-Windows hosts and a TODO note
on Windows (the digger Windows registry collector lives elsewhere
and can be hooked in later).

Safety
------
COMMAND sources can be arbitrary shell commands. We honor the ethics
contract by gating command execution behind ``DIGGER_FA_RUN_COMMANDS=1``
— without it, COMMAND sources are recorded as "would have run X" and
skipped. This protects users running ``digger fa run`` against a
poisoned corpus from getting RCE on their own box.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

from digger.core.evidence import Artifact as DiggerArtifact
from digger.core.platform import OS, current_os
from digger.forensic_artifacts.loader import Artifact, ArtifactSource
from digger.forensic_artifacts.resolver import ArtifactResolver


# Cap stored file content + command output to keep the evidence
# store size manageable. Beyond this we record the hash + size only.
_MAX_FILE_BYTES = 64 * 1024       # 64 KB
_MAX_OUTPUT_BYTES = 32 * 1024     # 32 KB
_COMMAND_TIMEOUT_S = 30


def _os_supported_now(art: Artifact) -> bool:
    """True if the artifact targets the current OS (or is OS-agnostic)."""
    me = {
        OS.WINDOWS: "windows",
        OS.MACOS:   "darwin",
        OS.LINUX:   "linux",
    }.get(current_os(), "")
    return art.supports(me) if me else not art.supported_os


def _read_file_sample(path: Path) -> dict[str, Any]:
    try:
        st = path.stat()
    except OSError as exc:
        return {"path": str(path), "error": f"stat failed: {exc}"}
    out: dict[str, Any] = {
        "path": str(path),
        "size": st.st_size,
        "mtime": st.st_mtime,
        "mode": oct(st.st_mode),
    }
    if not path.is_file():
        out["kind"] = "non-file"
        return out
    out["kind"] = "file"
    try:
        with path.open("rb") as f:
            data = f.read(_MAX_FILE_BYTES)
            extra = f.read(1)
        # Hash the bytes we actually have. If truncated, mark it.
        h = hashlib.sha256(data).hexdigest()
        out["sha256_prefix"] = h
        out["truncated"] = bool(extra)
        # Content is best-effort utf-8; binary files store hex.
        try:
            out["content_snippet"] = data.decode("utf-8")[:8192]
        except UnicodeDecodeError:
            out["content_snippet_hex"] = data[:1024].hex()
    except (PermissionError, OSError) as exc:
        out["error"] = f"read failed: {exc}"
    return out


def _list_directory(path: Path) -> dict[str, Any]:
    try:
        entries = []
        for child in path.iterdir():
            try:
                st = child.stat()
                entries.append({
                    "name": child.name,
                    "kind": "dir" if child.is_dir() else "file",
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
            except (PermissionError, OSError):
                entries.append({"name": child.name, "kind": "unknown"})
        return {
            "path": str(path),
            "kind": "directory",
            "entry_count": len(entries),
            "entries": entries[:500],   # cap
            "entries_truncated": len(entries) > 500,
        }
    except (PermissionError, OSError) as exc:
        return {"path": str(path), "error": f"list failed: {exc}"}


def _run_command(args: list[str]) -> dict[str, Any]:
    try:
        r = subprocess.run(
            args, capture_output=True, text=True,
            timeout=_COMMAND_TIMEOUT_S, check=False,
        )
        stdout = (r.stdout or "")[-_MAX_OUTPUT_BYTES:]
        stderr = (r.stderr or "")[-_MAX_OUTPUT_BYTES:]
        return {
            "command": args,
            "returncode": r.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": len(r.stdout or "") > _MAX_OUTPUT_BYTES,
            "stderr_truncated": len(r.stderr or "") > _MAX_OUTPUT_BYTES,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": args, "returncode": None, "timeout": True,
            "stdout": (exc.stdout or "")[-_MAX_OUTPUT_BYTES:] if exc.stdout else "",
            "stderr": (exc.stderr or "")[-_MAX_OUTPUT_BYTES:] if exc.stderr else "",
        }
    except (OSError, FileNotFoundError) as exc:
        return {
            "command": args, "returncode": None,
            "error": f"exec failed: {exc}",
        }


def _process_file_source(
    art: Artifact, src: ArtifactSource, resolver: ArtifactResolver, store,
) -> int:
    templates = [str(p) for p in (src.attributes.get("paths") or [])]
    paths = resolver.expand_many(templates)
    count = 0
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        data = _read_file_sample(path)
        data["fa_artifact"] = art.name
        data["fa_source_type"] = src.type
        data["fa_template"] = templates
        store.add_artifact(DiggerArtifact(
            collector="forensic_artifacts",
            category="filesystem",
            subject=f"fa:{art.name}:{p}",
            data=data,
        ))
        count += 1
    return count


def _process_directory_source(
    art: Artifact, src: ArtifactSource, resolver: ArtifactResolver, store,
) -> int:
    templates = [str(p) for p in (src.attributes.get("paths") or [])]
    paths = resolver.expand_many(templates)
    count = 0
    for p in paths:
        path = Path(p)
        if not path.is_dir():
            continue
        data = _list_directory(path)
        data["fa_artifact"] = art.name
        data["fa_source_type"] = src.type
        data["fa_template"] = templates
        store.add_artifact(DiggerArtifact(
            collector="forensic_artifacts",
            category="filesystem",
            subject=f"fa:{art.name}:{p}",
            data=data,
        ))
        count += 1
    return count


def _process_command_source(
    art: Artifact, src: ArtifactSource, _resolver, store,
) -> int:
    cmd = src.attributes.get("cmd")
    args = src.attributes.get("args") or []
    if not cmd:
        return 0
    full_args = [str(cmd)] + [str(a) for a in args]
    # The opt-in gate
    if os.environ.get("DIGGER_FA_RUN_COMMANDS") != "1":
        store.add_artifact(DiggerArtifact(
            collector="forensic_artifacts",
            category="command",
            subject=f"fa:{art.name}:command:skipped",
            data={
                "fa_artifact": art.name,
                "fa_source_type": "COMMAND",
                "command": full_args,
                "skipped_reason": (
                    "COMMAND source skipped — set "
                    "DIGGER_FA_RUN_COMMANDS=1 to enable shell-out. "
                    "ForensicArtifacts COMMAND sources can be "
                    "arbitrary shell; opt in only on a sandbox or "
                    "if you trust the corpus."
                ),
            },
        ))
        return 1
    result = _run_command(full_args)
    result["fa_artifact"] = art.name
    result["fa_source_type"] = "COMMAND"
    store.add_artifact(DiggerArtifact(
        collector="forensic_artifacts",
        category="command",
        subject=f"fa:{art.name}:command",
        data=result,
    ))
    return 1


def _process_unsupported_source(
    art: Artifact, src: ArtifactSource, store,
) -> int:
    store.add_artifact(DiggerArtifact(
        collector="forensic_artifacts",
        category="unsupported",
        subject=f"fa:{art.name}:{src.type}",
        data={
            "fa_artifact": art.name,
            "fa_source_type": src.type,
            "fa_attributes": src.attributes,
            "note": (
                f"Source type {src.type} not implemented in the "
                "ForensicArtifacts runner yet. Definition preserved "
                "for future native-collector wiring."
            ),
        },
    ))
    return 1


def _process_artifact_group_source(
    art: Artifact, src: ArtifactSource, resolver, store, all_artifacts_by_name: dict,
) -> int:
    names = src.attributes.get("names") or []
    count = 0
    for name in names:
        nested = all_artifacts_by_name.get(name)
        if nested is None:
            continue
        count += run_artifact(
            nested, store, resolver=resolver,
            all_artifacts_by_name=all_artifacts_by_name,
        )
    return count


def run_artifact(
    art: Artifact,
    store,
    *,
    resolver: ArtifactResolver | None = None,
    all_artifacts_by_name: dict | None = None,
) -> int:
    """Execute every source clause of an artifact and add digger
    Artifacts to the store. Returns the number of digger Artifacts
    emitted (may be > number of sources for FILE sources covering
    many files)."""
    if not _os_supported_now(art):
        return 0
    resolver = resolver or ArtifactResolver()
    name_map = all_artifacts_by_name or {}
    total = 0
    for src in art.sources:
        # Per-source supported_os also gates execution
        if src.supported_os and not Artifact(
            name="_tmp", supported_os=src.supported_os,
        ).supports({
            OS.WINDOWS: "windows", OS.MACOS: "darwin", OS.LINUX: "linux",
        }.get(current_os(), "")):
            continue

        if src.type == "FILE":
            total += _process_file_source(art, src, resolver, store)
        elif src.type in ("DIRECTORY", "PATH"):
            total += _process_directory_source(art, src, resolver, store)
        elif src.type == "COMMAND":
            total += _process_command_source(art, src, resolver, store)
        elif src.type == "ARTIFACT_GROUP":
            total += _process_artifact_group_source(
                art, src, resolver, store, name_map,
            )
        else:
            total += _process_unsupported_source(art, src, store)
    return total
