"""SSH key material and known_hosts — for catching unexpected authorized_keys entries."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact


class SshKeysCollector(Collector):
    name = "ssh_keys"
    category = "identity"
    description = "~/.ssh contents — authorized_keys, known_hosts, config, key fingerprints."

    def collect(self) -> Iterable[Artifact]:
        for ssh_dir in self._candidate_dirs():
            if not ssh_dir.is_dir():
                continue
            try:
                entries = []
                for f in ssh_dir.iterdir():
                    if not f.is_file():
                        continue
                    try:
                        st = f.stat()
                        entries.append({
                            "name": f.name,
                            "size": st.st_size,
                            "mode": oct(st.st_mode),
                            "mtime": st.st_mtime,
                        })
                    except OSError:
                        continue
                yield self.make(subject=f"ssh-dir:{ssh_dir}", path=str(ssh_dir), entries=entries)
            except PermissionError:
                continue
            # authorized_keys
            ak = ssh_dir / "authorized_keys"
            if ak.exists():
                try:
                    yield self.make(
                        subject=f"authorized_keys:{ak}",
                        path=str(ak),
                        lines=ak.read_text(errors="replace").splitlines(),
                    )
                except PermissionError:
                    pass
            # known_hosts
            kh = ssh_dir / "known_hosts"
            if kh.exists():
                try:
                    lines = kh.read_text(errors="replace").splitlines()
                    yield self.make(
                        subject=f"known_hosts:{kh}",
                        path=str(kh),
                        count=len(lines),
                        first_n=lines[:100],
                    )
                except PermissionError:
                    pass

    def _candidate_dirs(self):
        out = [Path.home() / ".ssh"]
        # On Unix, also enumerate other users' .ssh if we're root
        try:
            import pwd
            if os.getuid() == 0:
                for u in pwd.getpwall():
                    if u.pw_dir:
                        out.append(Path(u.pw_dir) / ".ssh")
        except Exception:
            pass
        return out
