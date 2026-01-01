"""Kubernetes cluster collector via the user-installed ``kubectl``.

Shells out to ``kubectl get <resource> -o json`` for a curated set
of cluster resources, parses the JSON, emits one digger Artifact
per resource into the EvidenceStore. Architecture mirrors the
existing external-tool bridges (digger.art / digger.volatility /
digger.plaso / digger.falco): discover binary, parse output,
degrade cleanly when missing.

Curated resource set
--------------------
The default set targets the canonical Kubernetes-side misconfigs
that map cleanly to security findings:

  * pods                 — ``hostPath``, ``privileged``, ``hostNetwork``,
                           image registries, default-SA usage,
                           secrets-in-env vs mounted secrets
  * serviceaccounts      — which exist + which are mounted
  * clusterrolebindings  — over-privileged subjects
                           (``system:authenticated``, ``system:unauth*``,
                           ``cluster-admin`` to a non-controller SA)
  * rolebindings         — namespace-scoped same
  * networkpolicies      — presence (absence in a namespace =
                           gap)
  * secrets (metadata-only, no `data` blob) — count + type
                                              for awareness

The detector consumes the emitted Artifacts and produces Findings;
this module just collects.

Safety
------
``kubectl get secrets -o json`` includes the base64-encoded secret
values in the ``data`` field. We strip it to metadata-only by post-
processing the JSON. Operators who want the values can ``kubectl
get secret -o json`` themselves; digger never stores them.

Per-resource size cap protects against pathological clusters
(e.g. 50k pods).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


# ---- exception ---- #


class KubectlError(RuntimeError):
    """Raised on binary-missing / cluster-unreachable / parse failure."""


# ---- binary discovery ---- #


def discover_binary() -> str | None:
    """Honors ``$DIGGER_KUBECTL_BIN`` if set; otherwise PATH-scans."""
    env = os.environ.get("DIGGER_KUBECTL_BIN")
    if env:
        return env if (os.path.isfile(env) and os.access(env, os.X_OK)) else None
    return shutil.which("kubectl")


def _require_binary() -> str:
    b = discover_binary()
    if not b:
        raise KubectlError(
            "no kubectl binary found in PATH. Install via your distro "
            "package manager or download from kubernetes.io. Set "
            "DIGGER_KUBECTL_BIN to override."
        )
    return b


# ---- curated resource list ---- #


# (resource, namespaced) — namespaced=True means we fetch with
# ``-A`` (all namespaces); namespaced=False means cluster-scoped.
DEFAULT_RESOURCES: list[tuple[str, bool]] = [
    ("pods",                True),
    ("serviceaccounts",     True),
    ("rolebindings",        True),
    ("networkpolicies",     True),
    ("secrets",             True),
    ("clusterrolebindings", False),
    ("clusterroles",        False),
]


# ---- subprocess safety caps ---- #


_KUBECTL_TIMEOUT_S = 60
_MAX_RESOURCE_BYTES = 64 * 1024 * 1024     # 64 MiB per resource fetch
_MAX_PER_ITEM_FIELD = 8192                  # truncate long strings


def _truncate(v: Any) -> Any:
    if isinstance(v, str) and len(v) > _MAX_PER_ITEM_FIELD:
        return v[:_MAX_PER_ITEM_FIELD] + " …<truncated>…"
    return v


def _scrub_secret_data(item: dict[str, Any]) -> dict[str, Any]:
    """Remove the ``data`` blob (base64-encoded secret values) from a
    Secret resource — keep only metadata + type. The detector only
    needs presence + shape, not the values."""
    if item.get("kind") == "Secret" or (
        "data" in item and item.get("type", "").startswith("kubernetes.io/")
    ):
        scrubbed = {k: v for k, v in item.items() if k != "data"}
        # Replace with the *count* of keys for awareness.
        if "data" in item and isinstance(item["data"], dict):
            scrubbed["_digger_data_key_count"] = len(item["data"])
            scrubbed["_digger_data_keys"] = sorted(item["data"].keys())
        return scrubbed
    return item


# ---- fetch_resource ---- #


def fetch_resource(
    resource: str,
    *,
    binary: str | None = None,
    namespaced: bool = True,
    context: str | None = None,
    namespace: str | None = None,
    timeout_s: int = _KUBECTL_TIMEOUT_S,
) -> dict[str, Any]:
    """Run ``kubectl get <resource> -o json`` and return the parsed dict.

    Raises ``KubectlError`` for binary-missing, cluster-unreachable,
    timeout, or oversized response (> 64 MiB)."""
    bin_path = binary or _require_binary()
    args = [bin_path, "get", resource, "-o", "json"]
    if context:
        args += ["--context", context]
    if namespace:
        args += ["-n", namespace]
    elif namespaced:
        args += ["-A"]
    try:
        r = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout_s, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise KubectlError(
            f"kubectl timed out after {timeout_s}s fetching {resource}"
        ) from exc
    except OSError as exc:
        raise KubectlError(f"kubectl OSError: {exc}") from exc
    if r.returncode != 0:
        raise KubectlError(
            f"kubectl get {resource} returned rc={r.returncode}: "
            f"{(r.stderr or '')[:500]}"
        )
    raw = r.stdout or ""
    if len(raw) > _MAX_RESOURCE_BYTES:
        raise KubectlError(
            f"kubectl get {resource} returned {len(raw)} bytes "
            f"(> {_MAX_RESOURCE_BYTES} cap). Use --namespace to scope."
        )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KubectlError(
            f"kubectl get {resource} returned non-JSON: {exc}"
        ) from exc


# ---- whole-cluster collect ---- #


@dataclass
class K8sCollectSummary:
    binary: str
    context: str | None
    namespace: str | None
    resources_attempted: int = 0
    resources_succeeded: int = 0
    items_emitted: int = 0
    per_resource: dict[str, int] = field(default_factory=dict)
    per_resource_errors: dict[str, str] = field(default_factory=dict)
    elapsed_s: float = 0.0


def _walk_item(item: dict[str, Any]) -> dict[str, Any]:
    """Apply per-item truncation + secret-scrubbing. Returns a new
    dict suitable for storing as an Artifact's data blob."""
    item = _scrub_secret_data(item)
    return {
        k: (_truncate(v) if not isinstance(v, (dict, list)) else v)
        for k, v in item.items()
    }


def collect_cluster(
    case_dir: str,
    *,
    binary: str | None = None,
    resources: Iterable[tuple[str, bool]] | None = None,
    context: str | None = None,
    namespace: str | None = None,
) -> K8sCollectSummary:
    """Fetch the curated resource set + emit one Artifact per item.

    Returns ``K8sCollectSummary`` with per-resource counts + errors.

    Per-resource failure is non-fatal — if kubectl errors on
    ``clusterrolebindings`` (e.g. RBAC denial) we record the error
    and continue. The summary's ``per_resource_errors`` is what the
    operator should review."""
    from digger.core.evidence import Artifact, EvidenceStore

    bin_path = binary or _require_binary()
    resources = list(resources) if resources else list(DEFAULT_RESOURCES)
    started = time.time()
    summary = K8sCollectSummary(
        binary=bin_path, context=context, namespace=namespace,
    )

    store = EvidenceStore(case_dir)
    try:
        for resource, is_namespaced in resources:
            summary.resources_attempted += 1
            try:
                doc = fetch_resource(
                    resource, binary=bin_path,
                    namespaced=is_namespaced,
                    context=context, namespace=namespace,
                )
            except KubectlError as exc:
                summary.per_resource_errors[resource] = str(exc)[:300]
                continue
            summary.resources_succeeded += 1
            items = doc.get("items") or []
            count = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                meta = item.get("metadata") or {}
                ns = meta.get("namespace", "")
                name = meta.get("name", "")
                subject_ns = f"{ns}/" if ns else ""
                store.add_artifact(Artifact(
                    collector=f"k8s.{resource}",
                    category="cluster",
                    subject=f"k8s:{resource}:{subject_ns}{name}",
                    data={
                        "k8s_resource": resource,
                        "k8s_namespace": ns,
                        "k8s_name": name,
                        "k8s_context": context or "",
                        "item": _walk_item(item),
                    },
                ))
                count += 1
            summary.per_resource[resource] = count
            summary.items_emitted += count
    finally:
        store.close()
    summary.elapsed_s = time.time() - started
    return summary
