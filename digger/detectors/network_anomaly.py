"""Network anomaly detection: bogon-ish remote addresses, listeners on uncommon ports."""

from __future__ import annotations

import ipaddress
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector

# Listeners on these ports are normally fine; everything else gets reported.
_BENIGN_LISTEN_PORTS = {
    22, 25, 53, 80, 88, 110, 123, 137, 138, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 993, 995, 1024,  # ephemeral threshold
    3000, 3306, 5000, 5432, 6379, 6443, 7000, 8000, 8080, 8443, 8888,
    9000, 9090, 27017,
    # Apple / macOS daemons
    548, 2049, 5353, 5354, 7000, 49152, 49153, 49154, 49155, 49156,
}

# Known telemetry / cloud endpoints to suppress as noise. Conservative.
_TELEMETRY_CIDRS = []


def _is_remote_addr_interesting(remote_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    return ip.is_global


class NetworkAnomalyDetector(Detector):
    name = "network_anomaly"
    description = "Listening ports outside the common set; external established sessions."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # Cross-reference listening sockets with their owning process.
        proc_index = {}
        for a in store.iter_artifacts(collector="processes"):
            pid = a["data"].get("pid")
            if pid is not None:
                proc_index[pid] = a["data"]

        for art in store.iter_artifacts(collector="network"):
            data = art["data"]
            laddr = data.get("laddr")
            raddr = data.get("raddr")
            status = (data.get("status") or "").upper()

            # Listeners
            if status == "LISTEN" and laddr:
                port = laddr[1] if len(laddr) > 1 else 0
                if port not in _BENIGN_LISTEN_PORTS and port < 60000:
                    yield Finding(
                        detector=self.name,
                        severity="low",
                        title=f"Listener on uncommon port {port}",
                        summary=(
                            f"Process is listening on {laddr[0]}:{port}. Not in the common "
                            "service-port list. Verify what's bound and whether it should be."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"laddr": laddr, "pid": data.get("pid")},
                        mitre="T1571",
                    )

            # External connections
            if status == "ESTABLISHED" and raddr and len(raddr) >= 2:
                if _is_remote_addr_interesting(raddr[0]):
                    pid = data.get("pid")
                    proc = proc_index.get(pid) if pid else None
                    yield Finding(
                        detector=self.name,
                        severity="info",
                        title=f"External connection to {raddr[0]}:{raddr[1]}",
                        summary=(
                            f"Established connection to public address {raddr[0]}:{raddr[1]} "
                            f"from PID {pid} ({(proc or {}).get('name', '?')}). "
                            "Triage to confirm expected destination."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"raddr": raddr, "pid": pid, "process": proc},
                        mitre="T1071",
                    )
