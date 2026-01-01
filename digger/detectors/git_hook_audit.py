"""Git hook security detector.

Consumes Artifacts emitted by ``digger.git_audit.audit_git_repos``
(one GitHookRecord per executable hook on the host) and emits
findings for the canonical hook-abuse patterns:

  G1  Pipe-to-shell in a hook:               critical
      Hook contains ``curl ... | sh`` or ``wget -O- | bash``.
      This is the canonical "download + execute" primitive and
      essentially never legitimate in a hook.

  G2  Network-fetch + silent-operation hook: high
      A post-checkout / post-merge / post-rewrite / pre-push /
      post-commit hook that issues a network request. Silent
      hooks fire on every routine `git pull`, so any C2 they
      reach is essentially every-time-the-dev-touches-git.

  G3  Network-fetch in any hook:             medium
      A network call in a hook is rarely needed (legit cases:
      pre-receive in server-side CI, sendemail-validate). Worth
      a manual review.

  G4  Eval of user-controlled input:         high
      ``eval "$VAR"`` / ``eval $1`` in a hook is a classic
      command-injection primitive. Particularly dangerous in
      pre-commit / commit-msg where the input is the commit
      message itself.

  G5  Self-modifying hook:                   high
      Hook writes to ``.git/config``, ``.git/hooks/``, or
      ``.git/packed-refs``. Hook persistence + self-replication
      primitive.

  G6  Encoded payload in hook:               medium
      Hook contains a long base64 / hex sequence. Often hides
      a download-cradle or shellcode.

A G7 surface-area sub-finding fires on the bare existence of
``post-checkout`` / ``post-merge`` / ``post-rewrite`` hooks at
``info`` level — these are silent-operation primitives the
operator should know about even if the content looks clean.
"""

from __future__ import annotations

from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


class GitHookAuditDetector(Detector):
    name = "git_hook_audit"
    description = (
        "Git hook abuse detection: pipe-to-shell, network-fetch "
        "(escalated for silent-operation hooks), eval of "
        "attacker-controlled input, self-modifying hooks, "
        "encoded payloads, plus surface-area info findings for "
        "post-checkout / post-merge / post-rewrite hooks."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious git hook on developer host",
            "id": "digger-git-hook-audit-template",
            "description": (
                "Executable hook in .git/hooks/ failed the digger "
                "git-hook audit (pipe-to-shell, network-fetch in "
                "silent-op hook, eval input, self-modify, encoded "
                "payload)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "dev_env"},
            "detection": {
                "selection": {
                    "kind": [
                        "pipe_to_shell_in_hook",
                        "network_fetch_silent_hook",
                        "network_fetch_in_hook",
                        "eval_input_in_hook",
                        "self_modify_hook",
                        "encoded_payload_hook",
                        "silent_operation_hook_present",
                        "hook_parse_error",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1546", "attack.t1059", "attack.t1027",
                "attack.t1505.003", "attack.t1195",
                "attack.persistence", "attack.execution",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="git.hook_audit",
                                          category="dev_env"):
            yield from self._check_hook(art)

    def _check_hook(self, art) -> Iterable[Finding]:
        rec = art["data"] or {}
        hook_path = rec.get("hook_path") or "?"
        hook_name = rec.get("hook_name") or "?"
        repo_path = rec.get("repo_path") or ""
        label = f"{hook_name} in {repo_path or hook_path}"
        ref = art["artifact_uuid"]

        if rec.get("parse_error"):
            yield Finding(
                detector=self.name,
                severity="info",
                title=f"Could not parse git hook: {hook_path}",
                summary=(
                    f"digger could not parse the hook at "
                    f"``{hook_path}``: ``{rec.get('parse_error')}``."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "hook_parse_error",
                    "hook_path": hook_path,
                    "hook_name": hook_name,
                    "parse_error": rec.get("parse_error"),
                },
                mitre="T1546",
            )
            return

        if rec.get("is_known_sample"):
            # Bare git sample (header + comment only). No finding.
            return

        # G1 pipe-to-shell
        if rec.get("contains_pipe_to_shell"):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"Pipe-to-shell download cradle in git hook: "
                    f"{label}"
                ),
                summary=(
                    f"Hook ``{hook_path}`` contains a "
                    "``curl ... | sh`` (or equivalent wget / "
                    "fetch) pattern. This is the canonical "
                    "download-and-execute primitive — the hook "
                    "fetches a remote script and runs it without "
                    "verification. Effectively never legitimate. "
                    "Disable the hook (chmod -x or delete) and "
                    "verify the upstream of the script."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "pipe_to_shell_in_hook",
                    "hook_path": hook_path,
                    "hook_name": hook_name,
                    "repo_path": repo_path,
                },
                mitre="T1059",
            )

        # G2 / G3 network-fetch  (escalated for silent-op hooks)
        if rec.get("contains_network_fetch") and \
                not rec.get("contains_pipe_to_shell"):
            silent = rec.get("is_silent_operation_hook")
            sev = "high" if silent else "medium"
            kind = ("network_fetch_silent_hook" if silent
                    else "network_fetch_in_hook")
            summary = (
                f"Hook ``{hook_path}`` issues a network "
                "request (curl / wget / nc / socat / python "
                "socket import). "
            )
            if silent:
                summary += (
                    "Hook fires on every routine "
                    f"``git`` operation matching ``{hook_name}`` "
                    "— so the network call happens silently with "
                    "every pull / checkout / merge / push, making "
                    "any C2 callback essentially every-time-the-"
                    "dev-touches-git. Treat as persistence."
                )
            else:
                summary += (
                    "Hook does not fire silently, but a network "
                    "call in a hook is rarely needed. Manual review."
                )
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Network fetch in"
                    f"{' silent-op' if silent else ''} "
                    f"git hook: {label}"
                ),
                summary=summary,
                artifact_refs=[ref],
                evidence={
                    "kind": kind,
                    "hook_path": hook_path,
                    "hook_name": hook_name,
                    "repo_path": repo_path,
                    "matches": rec.get("suspicious_matches"),
                },
                mitre="T1546",
            )

        # G4 eval input
        if rec.get("contains_eval_input"):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Eval of attacker-controllable input in "
                    f"git hook: {label}"
                ),
                summary=(
                    f"Hook ``{hook_path}`` contains an "
                    "``eval \"$VAR\"`` / ``eval $1`` pattern. "
                    "Classic command-injection primitive — "
                    "the hook's `$1`, `$@`, or environment "
                    "variables are the input. In a commit-msg "
                    "hook the input is the commit message itself; "
                    "in a post-checkout hook it's the old ref / "
                    "new ref. An attacker who can land a commit "
                    "or a ref with shell metacharacters gets "
                    "code execution on every checkout."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "eval_input_in_hook",
                    "hook_path": hook_path,
                    "hook_name": hook_name,
                    "repo_path": repo_path,
                },
                mitre="T1059",
            )

        # G5 self-modifying
        if rec.get("contains_self_modify"):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Self-modifying git hook writes to "
                    f".git/: {label}"
                ),
                summary=(
                    f"Hook ``{hook_path}`` references "
                    "``.git/config``, ``.git/hooks/``, or "
                    "``.git/packed-refs``. The hook can edit "
                    "git's own state, install or rewrite "
                    "additional hooks, or change the remote "
                    "URL. Combined with a silent-operation hook "
                    "(post-checkout / post-merge), this is a "
                    "self-replicating persistence primitive — "
                    "Shai-Hulud / TrapDoor / octofiles shape."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "self_modify_hook",
                    "hook_path": hook_path,
                    "hook_name": hook_name,
                    "repo_path": repo_path,
                },
                mitre="T1546",
            )

        # G6 encoded payload
        if rec.get("contains_long_base64") or \
                rec.get("contains_long_hex"):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Encoded payload in git hook: {label}"
                ),
                summary=(
                    f"Hook ``{hook_path}`` contains a long "
                    "base64 or escaped-hex sequence. Sometimes "
                    "legitimate (pre-commit linters bundling "
                    "config), often a download cradle or "
                    "shellcode hidden from casual inspection. "
                    "Decode + review."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "encoded_payload_hook",
                    "hook_path": hook_path,
                    "hook_name": hook_name,
                    "repo_path": repo_path,
                    "base64": rec.get("contains_long_base64"),
                    "hex": rec.get("contains_long_hex"),
                },
                mitre="T1027",
            )

        # G7 silent-operation hook surface-area info
        if rec.get("is_silent_operation_hook") and not (
            rec.get("contains_pipe_to_shell")
            or rec.get("contains_network_fetch")
            or rec.get("contains_eval_input")
            or rec.get("contains_self_modify")
            or rec.get("contains_long_base64")
            or rec.get("contains_long_hex")
        ):
            yield Finding(
                detector=self.name,
                severity="info",
                title=(
                    f"Silent-operation git hook present: {label}"
                ),
                summary=(
                    f"Hook ``{hook_name}`` is executable in "
                    f"``{repo_path}``. Silent-operation hooks "
                    "(post-checkout, post-merge, post-rewrite, "
                    "pre-push, post-commit) fire automatically "
                    "on routine git operations — perfectly fine "
                    "for legitimate workflows (formatters, "
                    "ctags, secret-scanners) but worth knowing "
                    "where they exist so a tampered one stands "
                    "out next time."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "silent_operation_hook_present",
                    "hook_path": hook_path,
                    "hook_name": hook_name,
                    "repo_path": repo_path,
                    "sha256": rec.get("sha256"),
                },
                mitre="T1546",
            )
