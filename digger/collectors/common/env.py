"""Environment variables of the calling shell. Useful for detecting LD_PRELOAD, DYLD_INSERT_LIBRARIES, PATH hijacks."""

from __future__ import annotations

import os
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact

_INTERESTING = {
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_BIND_NOW",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH",
    "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "BASH_ENV", "ENV", "PROMPT_COMMAND", "PS1",
    "HOME", "USER", "USERNAME", "SHELL", "LOGNAME", "TMPDIR", "TMP", "TEMP",
}


class EnvCollector(Collector):
    name = "env"
    category = "environment"
    description = "Process environment, with extra attention to hijack-relevant vars."

    def collect(self) -> Iterable[Artifact]:
        env = dict(os.environ)
        flagged = {k: v for k, v in env.items() if k in _INTERESTING}
        yield self.make(subject="environment", count=len(env), all_keys=sorted(env.keys()))
        yield self.make(subject="interesting", values=flagged)
        path_entries = (env.get("PATH") or "").split(os.pathsep)
        yield self.make(subject="path", entries=path_entries)
