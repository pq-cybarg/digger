"""Counter-cloud-attack: detect cloud-targeting tradecraft from collected data.

Observational only. Signals:

  K1  IMDS endpoint queried by an unusual process
      169.254.169.254 (AWS/GCP/Azure v1) and fd00:ec2::254 (AWS v6) +
      Azure 169.254.169.254 endpoint paths. Legitimate clients: cloud-
      provider SDKs, agents (cloud-init, ssm-agent, ec2-instance-connect,
      kubelet, ondemand). Anything else (curl, wget, python -c, bash)
      hitting IMDS = credential theft pattern.

  K2  Cloud credentials in env vars
      AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN /
      AZURE_CLIENT_SECRET / GOOGLE_APPLICATION_CREDENTIALS / GCP_SA_KEY
      in a process env_sample is fine for the SDK clients but a smell on
      a shell or random script.

  K3  ~/.aws/credentials, ~/.azure/*, ~/.config/gcloud/* world-readable
      Credentials files with permissions > 0600 are a privesc primitive
      for anyone with local-user access.

  K4  Container escape primitives
      Process arguments containing release_agent (CVE-2022-0492),
      core_pattern abuse, /sys/kernel/debug write, kubeconfig theft via
      `cat /var/lib/kubelet/...`, mounted /var/run/docker.sock used by
      non-orchestrator processes.

  K5  kubeconfig theft signatures
      Processes reading /var/lib/kubelet/kubeconfig, /etc/kubernetes/
      admin.conf, ~/.kube/config from non-{kubectl, kubelet, helm,
      kustomize, k9s, lens, telepresence} processes.

  K6  Cloud-CLI invocations from shells with role-assumption / token-grant
      `aws sts assume-role`, `aws sts get-session-token`,
      `az ad sp create-for-rbac`, `gcloud auth application-default
      print-access-token`, `gcloud iam service-accounts keys create`.

MITRE: T1552.005 (Cloud Instance Metadata API),
T1078.004 (Cloud Accounts), T1611 (Escape to Host),
T1552.001 (Unsecured Credentials in Files), T1528 (Steal Application
Access Token).
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- IMDS endpoints --------------------------------------------------------

_IMDS_IPS = {"169.254.169.254", "fd00:ec2::254", "fd00:ec2::255"}

# Process names that legitimately query IMDS in cloud environments.
_IMDS_FRIENDLY_PROC_NAMES = {
    "cloud-init", "cloud-init-local",
    "amazon-ssm-agent", "ssm-agent", "ssm-agent-worker",
    "ec2-instance-connect", "ec2-instance-connect-config",
    "amazon-cloudwatch-agent",
    "google_metadata_script", "google-metadata-script", "google_guest_agent",
    "google-osconfig-agent", "google_osconfig_agent",
    "kubelet", "containerd", "containerd-shim", "dockerd",
    "aws", "aws-c++-sdk", "boto3", "azure-cli", "gcloud",
    "telegraf", "fluent-bit", "fluentd",
    "node_exporter", "prometheus",
    # SDK runtimes that load AWS_REGION etc.
    "java", "python", "python3", "node", "go",  # SDK userspace — see noise note
}

# Cloud-credential environment-variable names. Presence in env_sample for a
# shell or generic-script process is the signal (SDKs pull these legitimately).
_CRED_ENV_NAMES = {
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "AZURE_AUTHORITY_HOST",
    "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SA_KEY",
    "GCP_PROJECT", "GOOGLE_CLOUD_PROJECT",
    "DIGITALOCEAN_TOKEN", "DIGITALOCEAN_ACCESS_TOKEN",
    "DOCKERHUB_TOKEN", "GHCR_TOKEN",
    "TF_VAR_aws_access_key", "TF_VAR_secret_key",
}

# Shell-like processes for which env-cred presence is a strong signal.
_SHELL_LIKE = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
}

# Cloud-CLI subcommands that produce / use credentials and should be reviewed
# when seen in a shell-launched cmdline.
_CLOUD_CLI_PATTERNS = [
    (re.compile(r"\baws\s+sts\s+(?:assume-role|get-session-token|get-caller-identity)\b", re.I),
     "aws sts (role assumption / token request)", "T1528"),
    (re.compile(r"\baws\s+iam\s+(?:create-access-key|create-user|attach-user-policy|put-user-policy|create-login-profile)\b",
                re.I),
     "aws iam (privesc-relevant write)", "T1098.001"),
    (re.compile(r"\baws\s+ec2\s+create-key-pair\b", re.I),
     "aws ec2 create-key-pair", "T1098.001"),
    (re.compile(r"\baz\s+ad\s+sp\s+create-for-rbac\b", re.I),
     "az ad sp create-for-rbac (new SP creation)", "T1098.001"),
    (re.compile(r"\baz\s+role\s+assignment\s+create\b", re.I),
     "az role assignment create (RBAC privesc)", "T1098.003"),
    (re.compile(r"\bgcloud\s+iam\s+service-accounts\s+keys\s+create\b", re.I),
     "gcloud SA key creation", "T1098.001"),
    (re.compile(r"\bgcloud\s+auth\s+application-default\s+print-access-token\b", re.I),
     "gcloud ADC access-token print", "T1528"),
    (re.compile(r"\bgcloud\s+projects\s+add-iam-policy-binding\b", re.I),
     "gcloud add-iam-policy-binding (RBAC privesc)", "T1098.003"),
]

# Container-escape primitive markers.
_CONTAINER_ESCAPE_PATTERNS = [
    (re.compile(r"release_agent\b", re.I),
     "cgroups v1 release_agent escape (CVE-2022-0492 family)",
     "T1611"),
    (re.compile(r"/sys/kernel/debug/tracing", re.I),
     "debugfs tracing write (kernel info-leak / escape)",
     "T1611"),
    (re.compile(r"core_pattern\b", re.I),
     "core_pattern abuse (writing to /proc/sys/kernel/core_pattern)",
     "T1611"),
    (re.compile(r"/var/run/docker\.sock\b", re.I),
     "/var/run/docker.sock reference (container escape if mounted)",
     "T1611"),
    (re.compile(r"\bunshare\s+-[a-zA-Z]*r\b|\bnsenter\s+-t\s+1\b", re.I),
     "nsenter -t 1 / unshare into PID 1 namespace",
     "T1611"),
    (re.compile(r"\bcapsh\s+--print", re.I),
     "capsh capability enumeration (pre-escape recon)",
     "T1611"),
]

# kubeconfig theft — paths that hold cluster admin credentials.
_KUBECONFIG_PATHS = (
    "/etc/kubernetes/admin.conf",
    "/var/lib/kubelet/kubeconfig",
    "/var/lib/kubelet/config.yaml",
    "/root/.kube/config",
)

_KUBE_CLIENT_NAMES = {
    "kubectl", "kubelet", "kube-apiserver", "kube-controller-manager",
    "kube-scheduler", "kube-proxy",
    "helm", "kustomize", "k9s", "lens", "telepresence",
    "kubeadm", "kops", "minikube", "kind",
    "argocd", "fluxctl",
}


def _cmdline_str(cmdline) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(c) for c in cmdline if c)
    return cmdline or ""


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


def _raddr_ip(raddr) -> str | None:
    if not raddr:
        return None
    if isinstance(raddr, (list, tuple)) and len(raddr) >= 1:
        return raddr[0]
    if isinstance(raddr, str):
        return raddr.split(":")[0]
    return None


class CloudAttackDetector(Detector):
    name = "cloud_attacks"
    description = (
        "Counter-cloud-attack: IMDS theft, env-var credential dumps, "
        "world-readable cred files, kubeconfig theft, container-escape "
        "primitives, cloud-CLI role assumption."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Cloud-attack tradecraft: IMDS theft / kubeconfig read / container escape",
            "id": "digger-cloud-attacks-template",
            "description": (
                "Connection to 169.254.169.254 (IMDS) from a non-cloud-agent "
                "process; read of /etc/kubernetes/admin.conf or ~/.kube/config "
                "from a non-kube client; reference to release_agent or "
                "/var/run/docker.sock in a process cmdline."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection_imds": {
                    "DestinationIp": ["169.254.169.254", "fd00:ec2::254"],
                },
                "filter_cloud_agents": {
                    "Image|endswith": [
                        "/cloud-init", "/ssm-agent", "/amazon-ssm-agent",
                        "/google_guest_agent", "/kubelet", "/containerd",
                        "/dockerd", "/aws", "/azure-cli", "/gcloud",
                    ],
                },
                "condition": "selection_imds and not filter_cloud_agents",
            },
            "level": "critical",
            "tags": ["attack.t1552.005", "attack.t1078.004", "attack.t1611",
                    "attack.credential_access"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- K1 IMDS hits ----
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"]
            pid = d.get("pid")
            name = (d.get("name") or "").lower()
            base = (_basename(d.get("exe") or "") or name).lower()
            cmd = _cmdline_str(d.get("cmdline"))

            for conn in d.get("connections") or []:
                rip = _raddr_ip(conn.get("raddr"))
                if rip not in _IMDS_IPS:
                    continue
                if base in _IMDS_FRIENDLY_PROC_NAMES:
                    continue
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"IMDS endpoint hit by unusual process: pid {pid} ({base})",
                    summary=(
                        f"Process {base} (pid {pid}) connected to the instance-"
                        f"metadata endpoint {rip}. Legitimate consumers are "
                        "cloud agents and SDK clients; shells, curl/wget, and "
                        "ad-hoc scripts hitting IMDS = credential-theft "
                        "tradecraft (Capital One 2019, post-SSRF chains)."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "imds_unusual_process",
                        "pid": pid, "name": base, "imds_ip": rip,
                        "cmdline": cmd[:300],
                        "username": d.get("username"),
                    },
                    mitre="T1552.005",
                )

            # Also flag IMDS in cmdline (curl 169.254.169.254/...)
            if any(ip in cmd for ip in _IMDS_IPS):
                if base not in _IMDS_FRIENDLY_PROC_NAMES:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"IMDS endpoint in cmdline of pid {pid} ({base})",
                        summary=(
                            f"Process {base} (pid {pid}) command line contains "
                            "the cloud instance-metadata IP. This is the classic "
                            "exfil pattern for IAM role credentials."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "imds_cmdline_reference",
                            "pid": pid, "name": base, "cmdline": cmd[:400],
                        },
                        mitre="T1552.005",
                    )

            # ---- K2 cloud credentials in env_sample ----
            env = d.get("env_sample") or {}
            if isinstance(env, dict) and env:
                hits = sorted(k for k in env if k.upper() in _CRED_ENV_NAMES)
                if hits and base in _SHELL_LIKE:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"Cloud credentials in shell env: pid {pid} ({base}) — {len(hits)} keys",
                        summary=(
                            f"Shell-like process {base} (pid {pid}) has cloud "
                            f"credential env vars set: {hits}. Shells inheriting "
                            "cloud creds is fine for interactive admin sessions "
                            "but a smell on unattended ones — confirm provenance."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "cloud_creds_in_shell_env",
                            "pid": pid, "shell": base, "env_keys": hits,
                            "username": d.get("username"),
                        },
                        mitre="T1552.001",
                    )

            # ---- K4 container-escape primitives in cmdline ----
            for rx, label, mitre in _CONTAINER_ESCAPE_PATTERNS:
                if rx.search(cmd):
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Container escape primitive in pid {pid}: {label}",
                        summary=(
                            f"Process {base} (pid {pid}) command line matches "
                            f"the pattern: {label}. Container-escape primitives "
                            "rarely have legitimate non-debugging use; correlate "
                            "with whether this process is inside a container."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "container_escape_primitive",
                            "pid": pid, "name": base, "pattern": label,
                            "cmdline": cmd[:400],
                        },
                        mitre=mitre,
                    )
                    break  # one per process is enough

            # ---- K5 kubeconfig theft ----
            open_files = d.get("open_files") or []
            for op in open_files:
                op_s = str(op)
                if any(kp in op_s for kp in _KUBECONFIG_PATHS):
                    if base in _KUBE_CLIENT_NAMES:
                        continue
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Kubeconfig accessed by non-kube process: pid {pid} ({base})",
                        summary=(
                            f"Process {base} (pid {pid}) has {op_s} open. This "
                            "file holds Kubernetes cluster admin credentials; "
                            "only kube clients (kubectl/kubelet/helm/k9s/etc.) "
                            "should access it. Treat unauthorized access as "
                            "cluster-credentials theft."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "kubeconfig_theft",
                            "pid": pid, "name": base, "file": op_s,
                            "username": d.get("username"),
                        },
                        mitre="T1552.001",
                    )
                    break

            # ---- K6 cloud-CLI role-assumption from shells ----
            for rx, label, mitre in _CLOUD_CLI_PATTERNS:
                if rx.search(cmd):
                    yield Finding(
                        detector=self.name,
                        severity="medium",
                        title=f"Cloud-CLI privesc-relevant command in pid {pid}: {label}",
                        summary=(
                            f"Process {base} (pid {pid}) ran: {label}. These "
                            "cloud-CLI subcommands grant credentials, change "
                            "IAM, or assume privileged roles. Legitimate admin "
                            "work; review against expected change windows and "
                            "the user who launched it."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "cloud_cli_privesc",
                            "pid": pid, "name": base, "pattern": label,
                            "cmdline": cmd[:400],
                            "username": d.get("username"),
                        },
                        mitre=mitre,
                    )
                    break

        # ---- K3 world-readable credential files (via privesc-surface) ----
        # Re-use the existing privesc collector if available; otherwise scan
        # any 'recent_files' artifacts for cred-file paths with bad modes.
        # (A dedicated cloud-cred file collector is left to a follow-up; for
        # now we surface the artifact if it shows up as world-readable in the
        # privesc surface.)
        cred_file_globs = (
            "/.aws/credentials", "/.azure/", "/.config/gcloud/",
            "/.aws/config", "/.kube/config",
        )
        for art in store.iter_artifacts(category="privesc_surface"):
            d = art["data"]
            path = (d.get("path") or "").lower()
            if not any(g in path for g in cred_file_globs):
                continue
            mode = d.get("mode") or ""
            # Anything readable by group/other is bad for these files
            try:
                mode_int = int(mode, 8)
                bad = bool(mode_int & 0o044)
            except (TypeError, ValueError):
                bad = False
            if not bad and not d.get("world_writable"):
                continue
            yield Finding(
                detector=self.name,
                severity="high",
                title=f"Cloud credentials file is group/world-readable: {d.get('path')}",
                summary=(
                    f"{d.get('path')} has mode {mode} — any local user can "
                    "read your cloud credentials. Fix with `chmod 600`."
                ),
                artifact_refs=[art["artifact_uuid"]],
                evidence={
                    "kind": "cloud_creds_file_perms",
                    "path": d.get("path"),
                    "mode": mode,
                },
                mitre="T1552.001",
            )
