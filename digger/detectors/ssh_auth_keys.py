"""SSH authorized_keys / authorized_keys2 surprise detector."""

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


class SshAuthKeysDetector(Detector):
    name = "ssh_auth_keys"
    description = "authorized_keys with forced commands, no-restrict options, or many keys."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="ssh_keys"):
            if not art["subject"].startswith("authorized_keys"):
                continue
            lines = [
                ln for ln in (art["data"].get("lines") or [])
                if ln.strip() and not ln.strip().startswith("#")
            ]
            if not lines:
                continue
            if len(lines) > 8:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=f"authorized_keys has {len(lines)} entries",
                    summary=(
                        f"{art['data'].get('path')} has {len(lines)} keys. Audit them — "
                        "stale and unaccounted-for keys are a common backdoor."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"count": len(lines), "path": art["data"].get("path")},
                    mitre="T1098.004",
                )
            for line in lines:
                if "command=" in line:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title="authorized_keys entry with forced command",
                        summary=(
                            f"{art['data'].get('path')} contains an entry with `command=` "
                            "constraint. Verify the command. A common backdoor pattern is to "
                            "force-execute a reverse-shell helper."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"line": line, "path": art["data"].get("path")},
                        mitre="T1098.004",
                    )
                if "no-pty" not in line and "from=" not in line and "ssh-" in line:
                    # purely informational — wide-open key, no restrictions
                    pass
