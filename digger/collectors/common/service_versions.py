"""Detect installed service binaries and capture their version banners.

Pure local introspection: we run ``<binary> --version`` (or equivalent)
with a strict timeout and parse the output. No remote probing, no
network — this honors P1 (local-host only) and P2 (observation default)
of the ethics contract.

We *only* invoke binaries that resolve via ``shutil.which()`` to a
system path (``/usr/sbin``, ``/usr/bin``, ``/usr/local/bin``,
``/opt/homebrew/bin``, ``C:\\Windows\\System32\\``, etc). We refuse to
execute random binaries in user-writable directories, so a malicious
binary planted in ``~/bin`` cannot use the collector as an exec primitive.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, Optional

from digger.core.collector import Collector
from digger.core.evidence import Artifact


# Whitelist of trusted parent directories. A binary discovered outside
# these is not executed.
_TRUSTED_PREFIXES = (
    "/usr/", "/bin/", "/sbin/", "/opt/homebrew/", "/opt/local/",
    "C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\",
)


@dataclass(frozen=True)
class ServiceProbe:
    """One service probe: binary name + flag + regex to pull the version out."""
    service: str
    binary: str
    args: tuple[str, ...]
    version_re: str
    # Some binaries (sshd, mysqld, php-fpm) write version to stderr.
    stderr: bool = False


# Curated probe list. Add new services here.
_PROBES: tuple[ServiceProbe, ...] = (
    ServiceProbe("openssh-server", "sshd", ("-V",), r"OpenSSH[_/]([\d.p]+)", stderr=True),
    ServiceProbe("openssh-client", "ssh", ("-V",), r"OpenSSH[_/]([\d.p]+)", stderr=True),
    ServiceProbe("nginx", "nginx", ("-v",), r"nginx/([\d.]+)", stderr=True),
    ServiceProbe("apache-httpd", "httpd", ("-v",), r"Apache/([\d.]+)"),
    ServiceProbe("apache-httpd", "apache2", ("-v",), r"Apache/([\d.]+)"),
    ServiceProbe("redis", "redis-server", ("--version",), r"v=([\d.]+)"),
    ServiceProbe("postgresql", "postgres", ("--version",), r"PostgreSQL\)?\s+([\d.]+)"),
    ServiceProbe("postgresql", "psql", ("--version",), r"PostgreSQL\)?\s+([\d.]+)"),
    ServiceProbe("mysql", "mysqld", ("--version",), r"Ver\s+([\d.]+)"),
    ServiceProbe("mariadb", "mariadbd", ("--version",), r"Ver\s+([\d.]+)"),
    ServiceProbe("mongodb", "mongod", ("--version",), r"db version v([\d.]+)"),
    ServiceProbe("python3", "python3", ("--version",), r"Python\s+([\d.]+)"),
    ServiceProbe("nodejs", "node", ("--version",), r"v?([\d.]+)"),
    ServiceProbe("openssl", "openssl", ("version",), r"OpenSSL\s+([\d.]+[a-z]*)"),
    ServiceProbe("curl", "curl", ("--version",), r"curl\s+([\d.]+)"),
    ServiceProbe("git", "git", ("--version",), r"git version\s+([\d.]+)"),
    ServiceProbe("docker", "docker", ("--version",), r"Docker version\s+([\d.]+)"),
    ServiceProbe("docker-daemon", "dockerd", ("--version",), r"Docker version\s+([\d.]+)"),
    ServiceProbe("php", "php", ("--version",), r"PHP\s+([\d.]+)"),
    ServiceProbe("ruby", "ruby", ("--version",), r"ruby\s+([\d.]+)"),
    ServiceProbe("go", "go", ("version",), r"go\s*version\s*go([\d.]+)"),
    ServiceProbe("rustc", "rustc", ("--version",), r"rustc\s+([\d.]+)"),
    ServiceProbe("kubectl", "kubectl", ("version", "--client", "--short"),
                 r"Client Version:\s*v?([\d.]+)"),
    ServiceProbe("kubelet", "kubelet", ("--version",), r"Kubernetes\s+v?([\d.]+)"),
    ServiceProbe("elasticsearch", "elasticsearch", ("--version",), r"Version:\s*([\d.]+)"),
    ServiceProbe("memcached", "memcached", ("--version",), r"memcached\s+([\d.]+)"),
    ServiceProbe("haproxy", "haproxy", ("-v",), r"version\s+([\d.]+)"),
    ServiceProbe("squid", "squid", ("-v",), r"Squid Cache:\s+Version\s+([\d.]+)"),
    ServiceProbe("varnish", "varnishd", ("-V",), r"varnish[d-]+\s+([\d.]+)", stderr=True),
    ServiceProbe("rabbitmq", "rabbitmqctl", ("version",), r"^\s*([\d.]+)\s*$"),
    ServiceProbe("samba", "smbd", ("--version",), r"Version\s+([\d.]+)"),
    ServiceProbe("bind9", "named", ("-v",), r"BIND\s+([\d.]+)"),
    ServiceProbe("powerdns", "pdns_server", ("--version",), r"PowerDNS Authoritative Server\s+([\d.]+)", stderr=True),
)


def _is_trusted_path(path: str) -> bool:
    p = os.path.realpath(path)
    return any(p.startswith(pref) for pref in _TRUSTED_PREFIXES)


def _run_probe(probe: ServiceProbe, path: str, timeout: float = 4.0) -> Optional[str]:
    """Execute the probe with a hard timeout. Returns the matched version string."""
    try:
        r = subprocess.run(
            [path, *probe.args],
            capture_output=True, text=True, timeout=timeout,
            # Some binaries try to bind ports (mysqld --version on misconfigured
            # systems prints to stderr). We don't pass any env that would cause
            # network ops, and the timeout caps damage.
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"},
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    blob = (r.stderr if probe.stderr else r.stdout) or (r.stdout if probe.stderr else r.stderr) or ""
    m = re.search(probe.version_re, blob)
    return m.group(1) if m else None


class ServiceVersionsCollector(Collector):
    name = "service_versions"
    category = "service"
    description = "Versions of well-known service binaries installed on this host."

    def collect(self) -> Iterable[Artifact]:
        seen: set[tuple[str, str]] = set()
        for probe in _PROBES:
            path = shutil.which(probe.binary)
            if not path:
                continue
            if not _is_trusted_path(path):
                # Skip user-bin / venv / npm-prefix copies of well-known names.
                continue
            version = _run_probe(probe, path)
            if not version:
                continue
            key = (probe.service, version)
            if key in seen:
                continue
            seen.add(key)
            yield self.make(
                subject=f"{probe.service} {version}",
                service=probe.service,
                binary=probe.binary,
                path=path,
                version=version,
                args=list(probe.args),
            )
