"""Linux audit framework (auditd / auditctl / ausearch)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class AuditCollector(Collector):
    name = "linux.audit"
    category = "logs"
    supported_os = (OS.LINUX,)
    requires_admin = True
    description = "auditd configuration and recent audit.log entries."

    def collect(self) -> Iterable[Artifact]:
        cfg = Path("/etc/audit/auditd.conf")
        if cfg.exists():
            try:
                yield self.make(subject="auditd.conf", path=str(cfg), contents=cfg.read_text(errors="replace"))
            except (PermissionError, OSError):
                pass
        rules_dir = Path("/etc/audit/rules.d")
        if rules_dir.is_dir():
            for r in rules_dir.glob("*.rules"):
                try:
                    yield self.make(
                        subject=f"audit-rules:{r.name}",
                        path=str(r),
                        contents=r.read_text(errors="replace"),
                    )
                except (PermissionError, OSError):
                    continue
        if shutil.which("auditctl"):
            try:
                out = subprocess.run(
                    ["auditctl", "-l"],
                    capture_output=True, text=True, timeout=10, check=False,
                ).stdout
                yield self.make(subject="auditctl-l", raw=out)
            except Exception:
                pass
        audit_log = Path("/var/log/audit/audit.log")
        if audit_log.exists():
            try:
                text = audit_log.read_text(errors="replace")
                yield self.make(
                    subject="audit-log",
                    path=str(audit_log),
                    size=len(text),
                    tail=text[-500_000:],
                )
            except (PermissionError, OSError):
                pass
