"""Kubernetes cluster-side forensics.

A brand-new category for digger: until now, every collector ran on
the host being analyzed. The k8s module steps up a layer and asks
"what's misconfigured on the cluster this host is part of" — which
is where most modern workload-security incidents actually live
(supply-chain compromises like Mini Shai-Hulud pivot through CI
pods; service-account-token theft escalates cross-namespace;
ClusterRoleBinding-to-system:authenticated is a classic
catastrophic misconfig).

Architecture mirrors the existing external-tool bridges
(digger.art / digger.volatility / digger.plaso / digger.falco):
shell out to a user-installed ``kubectl`` binary, parse JSON
output, emit digger Artifacts. Graceful degradation when kubectl
is missing or the cluster is unreachable.

Public API
----------
``discover_binary()`` — find ``kubectl`` in PATH
``collect_cluster(case_dir, ...)`` — fetch resources + emit Artifacts
``KubectlError`` — raised on binary-missing / cluster-unreachable
"""

from __future__ import annotations

from digger.k8s.collector import (
    KubectlError,
    K8sCollectSummary,
    collect_cluster,
    discover_binary,
    fetch_resource,
)

__all__ = [
    "K8sCollectSummary",
    "KubectlError",
    "collect_cluster",
    "discover_binary",
    "fetch_resource",
]
