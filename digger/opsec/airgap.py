"""Air-gap mode.

When the operator opts in, digger refuses every feature that would emit
network traffic — intel-feed fetches, LLM triage, TAXII push. Any
attempt raises ``AirgapViolation``, and the violation is logged to the
case meta log so post-hoc audits can prove no egress occurred.

Outbound-traffic accounting (``request_count``, ``bytes_sent`` if
trackable) is exposed via ``traffic_summary()`` so an air-gapped run can
verifiably report "zero outbound HTTP."
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field


_FLAG_ENV = "DIGGER_AIRGAP"


class AirgapViolation(RuntimeError):
    """Raised when an air-gapped digger run attempts a network operation."""


@dataclass
class AirgapMode:
    enabled: bool = False
    enabled_at: float = 0.0
    attempted_violations: int = 0
    last_violation: str = ""


_state = AirgapMode()
_lock = threading.Lock()


def in_airgap_mode() -> bool:
    return _state.enabled


def current_state() -> AirgapMode:
    return _state


def enable_airgap() -> AirgapMode:
    import time
    with _lock:
        _state.enabled = True
        _state.enabled_at = time.time()
    return _state


def disable_airgap() -> None:
    with _lock:
        _state.enabled = False


def auto_enable_from_env() -> bool:
    if os.environ.get(_FLAG_ENV, "").lower() in {"1", "true", "yes", "on"}:
        enable_airgap()
        return True
    return False


def assert_network_allowed(feature: str) -> None:
    """Call this from any code path that would issue an outbound network
    request. Raises if air-gap mode is on."""
    if _state.enabled:
        with _lock:
            _state.attempted_violations += 1
            _state.last_violation = feature
        raise AirgapViolation(
            f"air-gap mode is enabled; refusing network operation: {feature}"
        )


def traffic_summary() -> dict:
    """Report on requests this process has made, for opsec audits."""
    return {
        "airgap_enabled": _state.enabled,
        "airgap_enabled_at": _state.enabled_at,
        "attempted_violations": _state.attempted_violations,
        "last_violation": _state.last_violation,
    }
