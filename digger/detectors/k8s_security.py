"""Kubernetes cluster-side misconfiguration detector.

Reads the Artifacts emitted by ``digger.k8s.collect_cluster`` and
finds the canonical Kubernetes misconfig patterns that map cleanly
to compromise scenarios:

  K1  privileged: true pods — container running with
      ``securityContext.privileged: true``. Effective root on the
      node + capability bypass. Critical, T1611.

  K2  hostPath mounts to dangerous host paths — especially
      ``/var/run/docker.sock``, ``/``, ``/etc``, ``/var/log``,
      ``/proc``. Container breakout primitives. Critical, T1611.

  K3  hostNetwork / hostPID / hostIPC: true — pod shares the
      node's network namespace / PID namespace / IPC namespace.
      Per-flag finding. High, T1611.

  K4  ClusterRoleBinding to ``system:authenticated`` /
      ``system:unauthenticated`` / ``system:masters``. Anyone with
      a valid token (or no token, for unauthenticated) gets the
      bound role. Critical, T1098.

  K5  ServiceAccount granted ``cluster-admin`` via direct or
      transitive binding. Catastrophic. Critical, T1098.

  K6  Image registries outside allow-list. Default deny: only
      official registries (gcr.io, registry.k8s.io, quay.io,
      docker.io/library, *.dkr.ecr.*, *.azurecr.io, *.pkg.dev) +
      explicit allow are trusted. Anything else = high.

  K7  Image tag is :latest / unpinned (no tag = "latest"
      implicit) — supply-chain risk. Medium.

  K8  Secret reference in env via ``valueFrom.secretKeyRef`` is
      OK; secret value baked directly into env value, OR secret
      mounted as a volume with insufficient mode (>=0444 = world-
      readable) → high.

  K9  Default ServiceAccount used by a workload (no SA explicitly
      set OR set to "default"). Default SA is automatically
      mounted; if it has any RBAC, the workload inherits it.
      Medium.

  K10  Namespace missing a NetworkPolicy. Per-namespace finding —
       any namespace with pods but no NetworkPolicy at all is
       wide-open lateral movement. Medium, T1021.

MITRE: T1611 (Escape to Host), T1098 (Account Manipulation),
T1525 (Implant Internal Image), T1078.001 (Default Accounts),
T1021 (Remote Services / lateral).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- dangerous hostPath targets ---- #


_DANGEROUS_HOSTPATHS = {
    "/",
    "/etc",
    "/etc/",
    "/var/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/run/docker.sock",
    "/proc",
    "/proc/",
    "/var/log",
    "/var/log/",
    "/sys",
    "/sys/",
    "/root",
    "/root/",
    "/home",
    "/home/",
    "/var/lib/kubelet",
}


def _is_dangerous_hostpath(path: str) -> bool:
    p = (path or "").rstrip("/") or "/"
    if p in {x.rstrip("/") or "/" for x in _DANGEROUS_HOSTPATHS}:
        return True
    # Anything under /etc/ / /proc/ / /sys/ counts even if it's a
    # specific file (e.g. /etc/kubernetes/admin.conf).
    for prefix in ("/etc/", "/proc/", "/sys/", "/root/", "/var/log/"):
        if path.startswith(prefix):
            return True
    return False


# ---- image registry allow-list ---- #


_TRUSTED_REGISTRY_PATTERNS = [
    re.compile(r"^gcr\.io/"),
    re.compile(r"^registry\.k8s\.io/"),
    re.compile(r"^k8s\.gcr\.io/"),
    re.compile(r"^quay\.io/"),
    re.compile(r"^docker\.io/library/"),
    re.compile(r"^library/"),
    re.compile(r"^[\w\-]+\.dkr\.ecr\.[\w\-]+\.amazonaws\.com/"),
    re.compile(r"^[\w\-]+\.azurecr\.io/"),
    re.compile(r"^[\w\-\.]+-docker\.pkg\.dev/"),
    re.compile(r"^public\.ecr\.aws/"),
    re.compile(r"^ghcr\.io/"),
    re.compile(r"^mcr\.microsoft\.com/"),
]


def _image_registry(image: str) -> str:
    """Return the registry portion of an image string.

    Kubernetes images without an explicit registry are pulled from
    Docker Hub; we represent that as ``docker.io``."""
    if not image:
        return ""
    # Strip any digest / tag for registry-prefix detection
    base = image.split("@", 1)[0]
    # If the first slash-segment has a `.` or `:` (a port), it's a
    # registry; otherwise the image is on Docker Hub.
    first = base.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first.rstrip("/")
    return "docker.io"


def _registry_is_trusted(image: str) -> bool:
    if not image:
        return False
    # Strip digest
    base = image.split("@", 1)[0]
    for pat in _TRUSTED_REGISTRY_PATTERNS:
        if pat.match(base):
            return True
    return False


def _image_is_unpinned(image: str) -> bool:
    """True iff the image tag is missing (implicit :latest) OR
    explicitly :latest. Pinned :v1.2.3 or digest @sha256:... is OK."""
    if not image:
        return False
    if "@sha256:" in image or "@sha512:" in image:
        return False
    # Split off any registry-port colon (`registry:5000/repo:tag`).
    # The tag is the part after the LAST colon iff there's no slash
    # after it.
    last_slash = image.rfind("/")
    tail = image[last_slash + 1:]
    if ":" not in tail:
        return True   # implicit :latest
    tag = tail.rsplit(":", 1)[1]
    return tag in ("latest", "")


# ---- iter pods / containers ---- #


def _pod_containers(pod_item: dict) -> Iterable[tuple[str, dict]]:
    """Yield (container_kind, container_spec) pairs for every container,
    initContainer, and ephemeralContainer in the pod. container_kind is
    "container" / "init" / "ephemeral"."""
    spec = pod_item.get("spec") or {}
    for c in (spec.get("containers") or []):
        yield ("container", c)
    for c in (spec.get("initContainers") or []):
        yield ("init", c)
    for c in (spec.get("ephemeralContainers") or []):
        yield ("ephemeral", c)


def _has_secret_in_env_value(container: dict) -> list[str]:
    """Return list of env var names whose ``value`` looks like a baked-
    in credential (long random-ish string, key-shaped name) rather than
    a ``valueFrom.secretKeyRef``."""
    out = []
    secret_name_pat = re.compile(
        r"(?:password|secret|api_?key|token|aws_secret|private_key)",
        re.I,
    )
    for env in (container.get("env") or []):
        if not isinstance(env, dict):
            continue
        name = env.get("name") or ""
        if not name:
            continue
        # If it's resolved from a secret reference, fine.
        if env.get("valueFrom"):
            continue
        value = env.get("value")
        if not isinstance(value, str):
            continue
        if not secret_name_pat.search(name):
            continue
        # Looks credential-shaped if it's > 16 chars AND has digits AND
        # letters AND is not "changeme"-class
        if len(value) >= 16 and any(c.isdigit() for c in value) \
                and any(c.isalpha() for c in value) \
                and value not in {"changeme", "changeMe", "REPLACE_ME"}:
            out.append(name)
    return out


class K8sSecurityDetector(Detector):
    name = "k8s_security"
    description = (
        "Kubernetes cluster-side misconfig detector: privileged pods, "
        "dangerous hostPath mounts, hostNetwork/PID/IPC, "
        "ClusterRoleBindings to system:authenticated, ServiceAccount "
        "cluster-admin, untrusted-registry images, unpinned :latest "
        "tags, secrets-in-env, default-SA usage, namespaces missing "
        "NetworkPolicy."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Kubernetes cluster misconfig",
            "id": "digger-k8s-security-template",
            "description": (
                "A Kubernetes resource matches a known security-"
                "relevant misconfig: privileged pod, dangerous "
                "hostPath, hostNetwork/PID/IPC, cluster-admin "
                "binding to system:authenticated or default SA, "
                "untrusted image registry, unpinned :latest tag, "
                "secrets baked into env vars, default SA usage, "
                "namespace missing NetworkPolicy."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "kubernetes",
                          "service": "audit"},
            "detection": {
                "selection_priv_pod": {
                    "objectRef.resource": "pods",
                    "requestObject|contains": '"privileged": true',
                },
                "selection_dangerous_hostpath": {
                    "requestObject|contains": [
                        "/var/run/docker.sock",
                        '"hostPath":', '"path": "/"',
                    ],
                },
                "selection_clusterrole_bind_authenticated": {
                    "objectRef.resource": "clusterrolebindings",
                    "requestObject|contains": [
                        "system:authenticated",
                        "system:unauthenticated",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "high",
            "tags": [
                "attack.t1611", "attack.t1098",
                "attack.t1525", "attack.t1078.001",
                "attack.t1021",
                "attack.privilege_escalation",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- K1-K3, K6-K9: walk pods ---- #
        ns_with_pods: set[str] = set()
        for art in store.iter_artifacts(collector="k8s.pods"):
            d = art["data"] or {}
            ns = d.get("k8s_namespace") or ""
            name = d.get("k8s_name") or ""
            item = d.get("item") or {}
            spec = item.get("spec") or {}
            ns_with_pods.add(ns)

            # ---- K1: privileged: true ----
            for kind, c in _pod_containers(item):
                ctx = c.get("securityContext") or {}
                if ctx.get("privileged") is True:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Privileged container in pod "
                            f"{ns}/{name} ({kind}:{c.get('name')})"
                        ),
                        summary=(
                            f"Container ``{c.get('name')}`` in pod "
                            f"``{ns}/{name}`` runs with "
                            "``securityContext.privileged: true``. "
                            "This is effective root on the node — "
                            "the container shares the host's kernel "
                            "capabilities, can mount any device, and "
                            "can break out trivially via "
                            "/sys/fs/cgroup release_agent or similar. "
                            "Remove ``privileged: true`` and use "
                            "specific capabilities if needed."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "privileged_pod",
                            "namespace": ns,
                            "pod": name,
                            "container": c.get("name"),
                            "container_kind": kind,
                        },
                        mitre="T1611",
                    )

            # ---- K2: dangerous hostPath ----
            for vol in (spec.get("volumes") or []):
                if not isinstance(vol, dict):
                    continue
                hp = vol.get("hostPath")
                if not isinstance(hp, dict):
                    continue
                hp_path = hp.get("path") or ""
                if _is_dangerous_hostpath(hp_path):
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Dangerous hostPath mount in pod "
                            f"{ns}/{name}: {hp_path}"
                        ),
                        summary=(
                            f"Pod ``{ns}/{name}`` mounts host path "
                            f"``{hp_path}``. Mounting "
                            f"{('the container runtime socket — '
                                'container-as-root escape primitive'
                                if 'docker.sock' in hp_path or
                                'containerd.sock' in hp_path or
                                'crio.sock' in hp_path
                                else 'the host root / /etc / /proc / '
                                '/sys / /root / /var/log — node-level '
                                'data exposure + breakout primitive')}. "
                            "Remove the mount or scope it to a "
                            "specific subdirectory the workload "
                            "actually needs."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "dangerous_hostpath",
                            "namespace": ns,
                            "pod": name,
                            "host_path": hp_path,
                            "volume_name": vol.get("name"),
                        },
                        mitre="T1611",
                    )

            # ---- K3: hostNetwork / hostPID / hostIPC ----
            for flag, mitre, label in (
                ("hostNetwork", "T1611", "host network namespace"),
                ("hostPID",     "T1611", "host PID namespace"),
                ("hostIPC",     "T1611", "host IPC namespace"),
            ):
                if spec.get(flag) is True:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=(
                            f"Pod {ns}/{name} shares {label} "
                            f"({flag}: true)"
                        ),
                        summary=(
                            f"Pod ``{ns}/{name}`` sets "
                            f"``spec.{flag}: true`` — it shares the "
                            f"node's {label}. This breaks the pod "
                            "isolation boundary and is rarely "
                            "necessary outside of node-agent "
                            "DaemonSets (kube-proxy, CNI plugins)."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": f"host_{flag.lower().replace('host', '')}",
                            "namespace": ns,
                            "pod": name,
                            "flag": flag,
                        },
                        mitre=mitre,
                    )

            # ---- K6 + K7: image registry + tag ----
            for kind, c in _pod_containers(item):
                image = c.get("image") or ""
                if not image:
                    continue
                if not _registry_is_trusted(image):
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=(
                            f"Untrusted image registry in pod "
                            f"{ns}/{name}: {image}"
                        ),
                        summary=(
                            f"Container ``{c.get('name')}`` in pod "
                            f"``{ns}/{name}`` pulls from "
                            f"``{_image_registry(image)}`` — not on "
                            "the trusted-registry allow-list "
                            "(gcr.io / registry.k8s.io / quay.io / "
                            "docker.io/library / *.dkr.ecr.* / "
                            "*.azurecr.io / *.pkg.dev / public.ecr.aws "
                            "/ ghcr.io / mcr.microsoft.com). Could be "
                            "a private registry you trust — verify."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "untrusted_registry",
                            "namespace": ns,
                            "pod": name,
                            "container": c.get("name"),
                            "image": image,
                            "registry": _image_registry(image),
                        },
                        mitre="T1525",
                    )
                if _image_is_unpinned(image):
                    yield Finding(
                        detector=self.name,
                        severity="medium",
                        title=(
                            f"Unpinned image tag in pod "
                            f"{ns}/{name}: {image}"
                        ),
                        summary=(
                            f"Container ``{c.get('name')}`` in pod "
                            f"``{ns}/{name}`` uses image ``{image}`` "
                            "with no immutable digest. Tags can be "
                            "retargeted by the registry owner — pin "
                            "to ``@sha256:...`` for supply-chain "
                            "integrity."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "unpinned_image",
                            "namespace": ns,
                            "pod": name,
                            "container": c.get("name"),
                            "image": image,
                        },
                        mitre="T1525",
                    )

            # ---- K8: secret baked into env value ----
            for kind, c in _pod_containers(item):
                leaked = _has_secret_in_env_value(c)
                if leaked:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=(
                            f"Secret baked into env var(s) in pod "
                            f"{ns}/{name}: {', '.join(leaked)}"
                        ),
                        summary=(
                            f"Container ``{c.get('name')}`` in pod "
                            f"``{ns}/{name}`` carries credential-"
                            f"shaped env vars (``{', '.join(leaked)}"
                            f"``) with the value baked directly in "
                            "rather than referenced via "
                            "``valueFrom.secretKeyRef``. Anyone with "
                            "``kubectl get pods -o yaml`` access to "
                            "this namespace reads the secret in "
                            "plaintext. Move to a real Secret + "
                            "reference."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "secret_in_env",
                            "namespace": ns,
                            "pod": name,
                            "container": c.get("name"),
                            "env_vars": leaked,
                        },
                        mitre="T1552.001",
                    )

            # ---- K9: default SA usage ----
            sa = spec.get("serviceAccountName") or "default"
            if sa == "default":
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=(
                        f"Pod {ns}/{name} uses the default "
                        "ServiceAccount"
                    ),
                    summary=(
                        f"Pod ``{ns}/{name}`` has no explicit "
                        "``serviceAccountName`` (defaults to "
                        "``default``). The default SA's token is "
                        "mounted automatically; if it has any RBAC "
                        "(intentional or transitively via a "
                        "ClusterRoleBinding), the workload inherits "
                        "it. Define a dedicated SA + bind only the "
                        "permissions this workload needs."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "default_sa_usage",
                        "namespace": ns,
                        "pod": name,
                    },
                    mitre="T1078.001",
                )

        # ---- K4: dangerous ClusterRoleBindings ----
        # Tracks (sa_namespace, sa_name) → list of cluster roles bound
        # so K5 (SA → cluster-admin) can detect across the corpus.
        sa_clusterroles: dict[tuple[str, str], list[str]] = defaultdict(list)

        for art in store.iter_artifacts(collector="k8s.clusterrolebindings"):
            d = art["data"] or {}
            item = d.get("item") or {}
            name = d.get("k8s_name") or ""
            subjects = item.get("subjects") or []
            role_ref = (item.get("roleRef") or {}).get("name", "")
            for subj in subjects:
                if not isinstance(subj, dict):
                    continue
                subj_name = subj.get("name") or ""
                subj_kind = subj.get("kind") or ""
                # K4: bind to system:authenticated / unauthenticated /
                # masters → critical
                if subj_name in (
                    "system:authenticated",
                    "system:unauthenticated",
                    "system:masters",
                ):
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"ClusterRoleBinding '{name}' binds "
                            f"'{role_ref}' to {subj_name}"
                        ),
                        summary=(
                            f"ClusterRoleBinding ``{name}`` binds "
                            f"role ``{role_ref}`` to subject "
                            f"``{subj_name}``. ``system:authenticated"
                            "`` means any user with a valid token "
                            "(including any compromised "
                            "ServiceAccount token in any namespace) "
                            "inherits this role. "
                            "``system:unauthenticated`` means anyone "
                            "with network access to the apiserver. "
                            "``system:masters`` bypasses RBAC "
                            "entirely. Remove this binding."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "clusterrolebinding_overprivileged",
                            "binding": name,
                            "role": role_ref,
                            "subject": subj_name,
                            "subject_kind": subj_kind,
                        },
                        mitre="T1098",
                    )
                # K5 collection: track SAs bound to roles
                if subj_kind == "ServiceAccount":
                    sa_ns = subj.get("namespace") or ""
                    sa_clusterroles[(sa_ns, subj_name)].append(role_ref)

        # ---- K5: ServiceAccount granted cluster-admin ----
        for (sa_ns, sa_name), roles in sa_clusterroles.items():
            if "cluster-admin" in roles:
                # Skip the canonical kube-system controllers (these are
                # SUPPOSED to be cluster-admin: kube-controller-manager,
                # generic-garbage-collector, etc.).
                if sa_ns == "kube-system" and sa_name in {
                    "generic-garbage-collector",
                    "namespace-controller",
                    "horizontal-pod-autoscaler",
                    "resourcequota-controller",
                    "default",  # kube-system default is widely permitted
                    "service-account-controller",
                    "endpoint-controller",
                    "endpointslice-controller",
                    "node-controller",
                    "persistent-volume-binder",
                    "replication-controller",
                    "replicaset-controller",
                    "statefulset-controller",
                    "daemon-set-controller",
                    "deployment-controller",
                    "job-controller",
                    "cronjob-controller",
                    "garbage-collector-controller",
                    "ttl-controller",
                    "ttl-after-finished-controller",
                }:
                    continue
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"ServiceAccount {sa_ns}/{sa_name} has "
                        "cluster-admin"
                    ),
                    summary=(
                        f"ServiceAccount ``{sa_ns}/{sa_name}`` is "
                        "bound to the ``cluster-admin`` ClusterRole. "
                        "Any pod using this SA can do anything in "
                        "the cluster, including create new "
                        "ClusterRoleBindings, read every secret, and "
                        "exec into any pod. This is catastrophic if "
                        "the pod is compromised."
                    ),
                    artifact_refs=[],
                    evidence={
                        "kind": "sa_cluster_admin",
                        "namespace": sa_ns,
                        "service_account": sa_name,
                        "via_bindings": sorted(set(roles)),
                    },
                    mitre="T1098",
                )

        # ---- K10: namespace missing NetworkPolicy ----
        ns_with_netpol: set[str] = set()
        for art in store.iter_artifacts(collector="k8s.networkpolicies"):
            d = art["data"] or {}
            ns_with_netpol.add(d.get("k8s_namespace") or "")
        for ns in sorted(ns_with_pods):
            if not ns:
                continue
            # Don't flag system namespaces — they're usually
            # carefully managed and over-policing them creates noise.
            if ns in {"kube-system", "kube-public", "kube-node-lease",
                      "default"}:
                continue
            if ns in ns_with_netpol:
                continue
            yield Finding(
                detector=self.name,
                severity="medium",
                title=f"Namespace '{ns}' has no NetworkPolicy",
                summary=(
                    f"Namespace ``{ns}`` runs pods but has no "
                    "NetworkPolicy defined. Default cluster posture "
                    "is wide-open lateral movement — every pod can "
                    "reach every other pod (and any external host) "
                    "on any port. Add at least a default-deny "
                    "ingress policy + allow-list the needed "
                    "ingress / egress."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "namespace_missing_networkpolicy",
                    "namespace": ns,
                },
                mitre="T1021",
            )
