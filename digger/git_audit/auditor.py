"""Git hook auditor.

For every git repo found under the given roots, inspect each
executable hook in ``.git/hooks/`` (or in ``core.hooksPath`` if
overridden) and emit one GitHookRecord per hook. The detector
then walks the records and flags:

  - hooks containing network-fetch commands (curl / wget / nc / etc)
  - hooks that eval attacker-controllable input
  - hooks that self-modify (write to .git/config or .git/hooks/)
  - hooks containing long base64 / hex / encoded payloads
  - the post-checkout / post-merge / pre-push triad — these run
    on every routine operation and so are the textbook silent-
    persistence primitive

Strictly local; we never run the hook, never alter the repo,
never call out to the network.
"""

from __future__ import annotations

import hashlib
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


class GitAuditError(RuntimeError):
    pass


# ---- tunables ---- #

# All canonical git-hook names (man githooks).
HOOK_NAMES = (
    "applypatch-msg", "pre-applypatch", "post-applypatch",
    "pre-commit", "pre-merge-commit", "prepare-commit-msg",
    "commit-msg", "post-commit",
    "pre-rebase", "post-checkout", "post-merge",
    "pre-push", "pre-receive", "update", "post-receive",
    "post-update", "reference-transaction",
    "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman",
    "p4-changelist", "p4-prepare-changelist",
    "p4-post-changelist", "p4-pre-submit",
)

# Hooks that fire on routine operations — silent persistence
# primitives.
SILENT_OPERATION_HOOKS = {
    "post-checkout",  # every checkout + every clone
    "post-merge",     # every pull
    "post-rewrite",   # every rebase
    "pre-push",       # every push (attacker may want to gate
                      # actions on a successful push)
    "post-commit",    # every local commit
}

# Sample-hook signatures: git ships these as ``*.sample`` files. We
# pre-compute their sha256 so we can identify operator-customized
# hooks vs. literal git defaults that someone executable-bit'd.
GIT_SAMPLE_FIRST_LINE = "#!/bin/sh"

_MAX_HOOK_BYTES = 1024 * 1024
_MAX_HOOKS_PER_REPO = 64
_MAX_REPOS_PER_ROOT = 5000

# Directory names we don't descend into when looking for git repos.
# (Vendored deps often contain leftover .git/ from packages that ship them.)
_VENDOR_DIRS = frozenset({
    "node_modules", ".venv", "venv", "build", "dist",
    "__pycache__", ".tox", ".cache", "site-packages",
})


# Patterns we recognize as suspicious. These are deliberately broad —
# the operator decides whether the hit is legitimate.
_NETWORK_FETCH_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|python\s+-c\s+['\"]import\s+(?:socket|urllib|http))",
    re.IGNORECASE,
)
_EVAL_INPUT_RE = re.compile(
    r"\beval\s+[\"\']?\$",
)
_HOOK_SELF_MODIFY_RE = re.compile(
    r"\.git/(?:config|hooks/|packed-refs)",
)
_LONG_BASE64_RE = re.compile(
    r"[A-Za-z0-9+/]{120,}={0,2}",
)
_LONG_HEX_RE = re.compile(
    r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){40,}",
)
_REMOTE_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)[^|]*\|\s*(?:sh|bash|zsh|/bin/sh|/bin/bash)\b",
    re.IGNORECASE,
)


# ---- record shape ---- #


@dataclass
class GitHookRecord:
    repo_path: str
    hook_path: str
    hook_name: str
    size_bytes: int = 0
    mode: int = 0
    sha256: str = ""
    first_line: str = ""
    is_executable: bool = False
    is_silent_operation_hook: bool = False
    is_known_sample: bool = False
    contains_network_fetch: bool = False
    contains_eval_input: bool = False
    contains_self_modify: bool = False
    contains_long_base64: bool = False
    contains_long_hex: bool = False
    contains_pipe_to_shell: bool = False
    suspicious_matches: list[str] = field(default_factory=list)
    parse_error: str = ""


# ---- repo discovery ---- #


def _find_repos_under(root: Path, max_repos: int) -> Iterable[Path]:
    """Yield every directory under ``root`` that contains a ``.git``
    subdir. Bounded; never recurses into ``.git`` itself."""
    count = 0
    try:
        if (root / ".git").is_dir():
            yield root
            count += 1
    except OSError:
        return
    if count >= max_repos:
        return
    try:
        stack: list[Path] = []
        for child in root.iterdir():
            if not child.is_dir():
                continue
            if child.name == ".git":
                continue
            if child.name in _VENDOR_DIRS:
                continue
            stack.append(child)
        while stack and count < max_repos:
            d = stack.pop()
            try:
                if (d / ".git").is_dir():
                    yield d
                    count += 1
                    continue
                for child in d.iterdir():
                    if not child.is_dir():
                        continue
                    if child.name == ".git":
                        continue
                    # Don't recurse into vendored directories. node_modules
                    # / .venv / build / dist usually contain nested .git/
                    # leftovers from packages that ship them.
                    if child.name in _VENDOR_DIRS:
                        continue
                    stack.append(child)
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        return


# ---- hook parsing ---- #


def _resolve_hooks_dir(repo: Path) -> Path:
    """Return the hooks dir, honoring ``core.hooksPath`` in
    ``.git/config`` if set."""
    cfg = repo / ".git" / "config"
    if cfg.is_file():
        try:
            for line in cfg.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines():
                ls = line.strip()
                if ls.startswith("hooksPath"):
                    _, _, val = ls.partition("=")
                    val = val.strip()
                    if val:
                        p = Path(val)
                        if not p.is_absolute():
                            p = (repo / p).resolve()
                        return p
        except OSError:
            pass
    return repo / ".git" / "hooks"


def _safe_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def parse_hook(hook_path: Path | str,
                *,
                repo_path: str = "") -> GitHookRecord:
    p = Path(hook_path)
    name = p.name
    rec = GitHookRecord(
        repo_path=repo_path or str(p.parents[2])
            if len(p.parents) >= 3 else "",
        hook_path=str(p),
        hook_name=name,
    )
    if not p.is_file():
        rec.parse_error = "not a file"
        return rec
    try:
        st = p.stat()
    except OSError as exc:
        rec.parse_error = f"stat failed: {exc}"
        return rec
    rec.size_bytes = st.st_size
    rec.mode = st.st_mode
    rec.is_executable = bool(st.st_mode & (
        stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    ))
    rec.is_silent_operation_hook = (
        rec.hook_name in SILENT_OPERATION_HOOKS
    )
    if st.st_size > _MAX_HOOK_BYTES:
        rec.parse_error = (
            f"hook {st.st_size} bytes > {_MAX_HOOK_BYTES} cap"
        )
        return rec
    try:
        with open(p, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        rec.parse_error = f"read failed: {exc}"
        return rec
    rec.sha256 = _safe_sha256(raw)
    try:
        text = raw.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""

    first_line = text.split("\n", 1)[0][:200]
    rec.first_line = first_line

    # is_known_sample: git ships every default hook as ``*.sample`` —
    # exact name doesn't matter; what we care about is whether
    # someone made the .sample executable and copied its content
    # verbatim. The "Standard sample hook" git uses is a shebang +
    # a comment block + an empty body. As a proxy, treat hooks whose
    # whole body is a comment block as "known sample".
    body_lines = [
        ls for ls in text.splitlines()
        if ls.strip() and not ls.strip().startswith("#")
    ]
    rec.is_known_sample = (
        len(body_lines) == 0
        and first_line == GIT_SAMPLE_FIRST_LINE
    )

    matches: list[str] = []
    if _NETWORK_FETCH_RE.search(text):
        rec.contains_network_fetch = True
        matches.append("network_fetch")
    if _EVAL_INPUT_RE.search(text):
        rec.contains_eval_input = True
        matches.append("eval_input")
    if _HOOK_SELF_MODIFY_RE.search(text):
        rec.contains_self_modify = True
        matches.append("self_modify")
    if _LONG_BASE64_RE.search(text):
        rec.contains_long_base64 = True
        matches.append("long_base64")
    if _LONG_HEX_RE.search(text):
        rec.contains_long_hex = True
        matches.append("long_hex")
    if _REMOTE_PIPE_TO_SHELL_RE.search(text):
        rec.contains_pipe_to_shell = True
        matches.append("pipe_to_shell")
    rec.suspicious_matches = matches

    return rec


def _audit_repo_hooks(repo: Path) -> list[GitHookRecord]:
    out: list[GitHookRecord] = []
    hooks_dir = _resolve_hooks_dir(repo)
    if not hooks_dir.is_dir():
        return out
    try:
        children = sorted(hooks_dir.iterdir())
    except OSError:
        return out
    seen = 0
    for child in children:
        if seen >= _MAX_HOOKS_PER_REPO:
            break
        if not child.is_file():
            continue
        if child.name.endswith(".sample"):
            continue
        rec = parse_hook(child, repo_path=str(repo))
        if not rec.is_executable:
            continue
        out.append(rec)
        seen += 1
    return out


# ---- walker ---- #


def audit_git_repos(
    roots: Iterable[Path | str] | None = None,
    *,
    max_repos_per_root: int = _MAX_REPOS_PER_ROOT,
) -> list[GitHookRecord]:
    """Discover every git repo under ``roots`` and audit its hooks.

    If ``roots`` is None, defaults to ``[cwd]``."""
    if roots is None:
        roots = [Path.cwd()]
    out: list[GitHookRecord] = []
    for root in roots:
        root_p = Path(root)
        if not root_p.exists():
            continue
        for repo in _find_repos_under(root_p, max_repos_per_root):
            out += _audit_repo_hooks(repo)
    return out


# ---- emit ---- #


def emit_records_to_store(records: Iterable[GitHookRecord], store) -> int:
    from dataclasses import asdict
    from digger.core.evidence import Artifact
    n = 0
    for rec in records:
        data = asdict(rec)
        subject = f"git:hook:{rec.hook_name}:{rec.hook_path}"
        store.add_artifact(Artifact(
            collector="git.hook_audit",
            category="dev_env",
            subject=subject[:380],
            data=data,
        ))
        n += 1
    return n
