"""Environment-variable hijack detector — LD_PRELOAD, DYLD_INSERT_LIBRARIES, PATH injection."""

from __future__ import annotations

import os
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


class EnvHijackDetector(Detector):
    name = "env_hijack"
    description = "Hijack vars present in env or process environment."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="env", category="environment"):
            if art["subject"] != "interesting":
                continue
            values = art["data"].get("values") or {}
            for var in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_AUDIT"):
                if var in values and values[var]:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"{var} set in environment",
                        summary=(
                            f"{var} is set to '{values[var]}'. This forces the dynamic linker "
                            "to load an attacker-controlled library into every spawned process. "
                            "Almost never legitimate on user desktops."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"var": var, "value": values[var]},
                        mitre="T1574.006",
                    )
            for var in ("PROMPT_COMMAND", "BASH_ENV", "ENV"):
                if var in values and values[var]:
                    yield Finding(
                        detector=self.name,
                        severity="medium",
                        title=f"Shell init hook present: {var}",
                        summary=(
                            f"{var} is set to '{values[var]}'. This is a shell-startup hook that "
                            "runs on every interactive/non-interactive shell launch. Verify it."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"var": var, "value": values[var]},
                        mitre="T1546.004",
                    )
            # PATH writability — any element a non-root user can write to before
            # /usr/bin etc is a classic privilege-escalation surface.
            path = values.get("PATH") or ""
            for entry in path.split(os.pathsep):
                if entry and (entry.startswith("/tmp") or entry.startswith("/var/tmp")
                              or "/.cache/" in entry):
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"Writable temp dir in PATH: {entry}",
                        summary=(
                            f"PATH contains '{entry}' which is a writable temporary location. "
                            "Any binary dropped there will be found before legitimate ones."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"path_entry": entry},
                        mitre="T1574.007",
                    )
