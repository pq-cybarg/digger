"""Operator-side opsec: protect the investigator and the case data.

The rest of digger protects the *evidence*. This module protects the
*investigator*: their case bundle confidentiality, their network
footprint while collecting threat intel, who else is watching them
collect, and the lifecycle of sensitive data on the host.

Submodules:

  bundle    encrypt / decrypt / sign whole case dirs into single archives
            using NIST PQC-KEM + AES-256-GCM hybrid encryption
  redact    pseudonymize usernames / hostnames / IPs / paths for sharing
  watchers  enumerate processes that may be observing the investigation
            (ptrace/dtrace/lldb attached, packet captures, accessibility,
             screen recording, EDR/AV agents, audit listeners)
  airgap    refuse every network-dependent feature; verify post-hoc that
            no outbound traffic happened
  wipe      secure-delete a case directory (multi-pass overwrite + unlink)
  status    summarize operator posture (network state, intel freshness,
            LLM contact, active watchers, bytes sent)
"""

from digger.opsec.bundle import (
    encrypt_case, decrypt_case,
    BundleHeader, BundleResult,
)
from digger.opsec.redact import (
    RedactionPolicy, redact_case, REDACTION_DEFAULT_POLICY,
)
from digger.opsec.watchers import (
    Watcher, find_watchers,
)
from digger.opsec.airgap import (
    AirgapMode, enable_airgap, in_airgap_mode, assert_network_allowed,
)
from digger.opsec.wipe import (
    secure_wipe_dir, secure_wipe_file,
)
from digger.opsec.status import opsec_status

__all__ = [
    "encrypt_case", "decrypt_case", "BundleHeader", "BundleResult",
    "RedactionPolicy", "redact_case", "REDACTION_DEFAULT_POLICY",
    "Watcher", "find_watchers",
    "AirgapMode", "enable_airgap", "in_airgap_mode", "assert_network_allowed",
    "secure_wipe_dir", "secure_wipe_file",
    "opsec_status",
]
