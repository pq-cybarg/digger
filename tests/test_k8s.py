"""Kubernetes collector + K8sSecurityDetector tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.k8s_security import (
    K8sSecurityDetector,
    _has_secret_in_env_value,
    _image_is_unpinned,
    _image_registry,
    _is_dangerous_hostpath,
    _pod_containers,
    _registry_is_trusted,
)
from digger.k8s.collector import (
    K8sCollectSummary,
    KubectlError,
    _scrub_secret_data,
    collect_cluster,
    discover_binary,
    fetch_resource,
)


# ---------------------------------------------------------------- #
# Collector
# ---------------------------------------------------------------- #


# ---- binary discovery ---- #


def test_discover_binary_honors_env(monkeypatch, tmp_path):
    fake = tmp_path / "fake_kubectl"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(0o755)
    monkeypatch.setenv("DIGGER_KUBECTL_BIN", str(fake))
    assert discover_binary() == str(fake)


def test_discover_binary_env_missing_returns_none(monkeypatch):
    monkeypatch.setenv("DIGGER_KUBECTL_BIN", "/nonexistent/zzz")
    assert discover_binary() is None


def test_discover_binary_path_scan(monkeypatch):
    monkeypatch.delenv("DIGGER_KUBECTL_BIN", raising=False)
    monkeypatch.setattr(
        "digger.k8s.collector.shutil.which",
        lambda name: "/usr/local/bin/kubectl" if name == "kubectl" else None,
    )
    assert discover_binary() == "/usr/local/bin/kubectl"


# ---- _scrub_secret_data ---- #


def test_scrub_secret_strips_data_blob_but_keeps_key_count():
    item = {
        "kind": "Secret",
        "metadata": {"name": "db-creds"},
        "type": "Opaque",
        "data": {
            "password": "c3VwZXJzZWNyZXQ=",
            "api_key": "YWJjMTIz",
        },
    }
    scrubbed = _scrub_secret_data(item)
    assert "data" not in scrubbed
    assert scrubbed["_digger_data_key_count"] == 2
    assert sorted(scrubbed["_digger_data_keys"]) == ["api_key", "password"]
    # NO base64 value anywhere
    blob = json.dumps(scrubbed)
    assert "c3VwZXJzZWNyZXQ=" not in blob
    assert "YWJjMTIz" not in blob


def test_scrub_non_secret_left_untouched():
    item = {"kind": "Pod", "metadata": {"name": "x"}, "spec": {}}
    assert _scrub_secret_data(item) == item


# ---- fetch_resource: kubectl shell-out via fake binary ---- #


def _install_fake_kubectl(tmp_path, *, stdout="{}", rc=0):
    """Drop a tiny fake `kubectl` binary that prints ``stdout`` and
    exits ``rc``."""
    fake = tmp_path / "fake_kubectl"
    # Use cat-heredoc so JSON quotes survive
    fake.write_text(
        "#!/bin/sh\n"
        f"cat <<'KCEOF'\n{stdout}\nKCEOF\n"
        f"exit {rc}\n"
    )
    fake.chmod(0o755)
    return fake


def test_fetch_resource_parses_json(monkeypatch, tmp_path):
    doc = {"items": [{"metadata": {"name": "p1"},
                        "spec": {"containers": [{"name": "c"}]}}]}
    fake = _install_fake_kubectl(tmp_path, stdout=json.dumps(doc))
    monkeypatch.setenv("DIGGER_KUBECTL_BIN", str(fake))
    out = fetch_resource("pods")
    assert out == doc


def test_fetch_resource_nonzero_rc_raises(monkeypatch, tmp_path):
    fake = _install_fake_kubectl(tmp_path, stdout="error: no cluster", rc=1)
    monkeypatch.setenv("DIGGER_KUBECTL_BIN", str(fake))
    with pytest.raises(KubectlError, match="rc=1"):
        fetch_resource("pods")


def test_fetch_resource_no_binary_raises(monkeypatch):
    monkeypatch.delenv("DIGGER_KUBECTL_BIN", raising=False)
    monkeypatch.setattr(
        "digger.k8s.collector.shutil.which", lambda name: None,
    )
    with pytest.raises(KubectlError, match="no kubectl"):
        fetch_resource("pods")


def test_fetch_resource_non_json_raises(monkeypatch, tmp_path):
    fake = _install_fake_kubectl(tmp_path, stdout="not json at all")
    monkeypatch.setenv("DIGGER_KUBECTL_BIN", str(fake))
    with pytest.raises(KubectlError, match="non-JSON"):
        fetch_resource("pods")


# ---- collect_cluster end-to-end ---- #


def test_collect_cluster_emits_one_artifact_per_item(monkeypatch, tmp_path):
    """Pretend kubectl returns a pod + a clusterrolebinding."""
    docs = {
        "pods": {"items": [
            {"metadata": {"namespace": "default", "name": "nginx"},
             "spec": {"containers": [{"name": "c", "image": "nginx:1.21"}]}},
        ]},
        "serviceaccounts": {"items": []},
        "rolebindings": {"items": []},
        "networkpolicies": {"items": []},
        "secrets": {"items": []},
        "clusterrolebindings": {"items": [
            {"metadata": {"name": "test-crb"},
             "subjects": [{"kind": "Group",
                           "name": "system:authenticated"}],
             "roleRef": {"name": "cluster-admin"}},
        ]},
        "clusterroles": {"items": []},
    }
    def _fake_fetch(resource, **kw):
        return docs.get(resource, {"items": []})
    monkeypatch.setattr(
        "digger.k8s.collector.fetch_resource", _fake_fetch,
    )
    # Don't actually require the binary in this test
    monkeypatch.setattr(
        "digger.k8s.collector._require_binary",
        lambda: "/fake/kubectl",
    )
    summary = collect_cluster(str(tmp_path / "case"))
    assert isinstance(summary, K8sCollectSummary)
    assert summary.resources_attempted == 7
    assert summary.resources_succeeded == 7
    assert summary.items_emitted == 2   # 1 pod + 1 CRB

    # Verify artifacts landed in the store
    store = EvidenceStore(str(tmp_path / "case"))
    pods = list(store.iter_artifacts(collector="k8s.pods"))
    crbs = list(store.iter_artifacts(collector="k8s.clusterrolebindings"))
    assert len(pods) == 1
    assert len(crbs) == 1
    assert pods[0]["data"]["k8s_name"] == "nginx"
    assert pods[0]["subject"] == "k8s:pods:default/nginx"
    assert crbs[0]["subject"] == "k8s:clusterrolebindings:test-crb"
    store.close()


def test_collect_cluster_per_resource_failure_non_fatal(
    monkeypatch, tmp_path,
):
    """If one resource fails (e.g. RBAC denial on clusterrolebindings),
    the rest still collect."""
    def _fake_fetch(resource, **kw):
        if resource == "clusterrolebindings":
            raise KubectlError("forbidden: User cannot list CRBs")
        return {"items": []}
    monkeypatch.setattr(
        "digger.k8s.collector.fetch_resource", _fake_fetch,
    )
    monkeypatch.setattr(
        "digger.k8s.collector._require_binary",
        lambda: "/fake/kubectl",
    )
    summary = collect_cluster(str(tmp_path / "case"))
    assert summary.resources_attempted == 7
    assert summary.resources_succeeded == 6
    assert "clusterrolebindings" in summary.per_resource_errors


# ---------------------------------------------------------------- #
# Detector helpers
# ---------------------------------------------------------------- #


@pytest.mark.parametrize("path", [
    "/", "/etc", "/etc/", "/etc/kubernetes/admin.conf",
    "/var/run/docker.sock", "/var/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock", "/run/docker.sock",
    "/proc", "/proc/1/root", "/sys/fs/cgroup",
    "/root", "/root/.ssh", "/home", "/var/log", "/var/log/syslog",
    "/var/lib/kubelet",
])
def test_is_dangerous_hostpath_true(path):
    assert _is_dangerous_hostpath(path)


@pytest.mark.parametrize("path", [
    "/data", "/srv", "/opt/myapp",
    "/var/lib/mydb",
    "/usr/local/share/x",
    "/home/user/data",   # specific subdir is NOT auto-dangerous
])
def test_is_dangerous_hostpath_false(path):
    assert not _is_dangerous_hostpath(path)


@pytest.mark.parametrize("image,expected", [
    ("gcr.io/google-containers/etcd:3.5.0", True),
    ("registry.k8s.io/pause:3.9", True),
    ("quay.io/prometheus/node-exporter:v1.5", True),
    ("docker.io/library/nginx:1.21", True),
    ("123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:v1", True),
    ("myregistry.azurecr.io/team/api:1.0", True),
    ("us-docker.pkg.dev/proj/repo/img:v1", True),
    ("ghcr.io/owner/repo:tag", True),
    ("mcr.microsoft.com/dotnet/sdk:8.0", True),
    ("attacker.example.com/payload:latest", False),
    ("random.evil.io/x:v1", False),
])
def test_registry_is_trusted(image, expected):
    assert _registry_is_trusted(image) is expected


@pytest.mark.parametrize("image,expected", [
    ("nginx", True),
    ("nginx:latest", True),
    ("nginx:1.21", False),
    ("nginx:1.21.0-alpine", False),
    ("nginx@sha256:abc123", False),
    ("registry:5000/repo:v1", False),
    ("registry:5000/repo", True),    # no tag → implicit latest
])
def test_image_is_unpinned(image, expected):
    assert _image_is_unpinned(image) is expected


def test_image_registry_parsing():
    assert _image_registry("nginx") == "docker.io"
    assert _image_registry("gcr.io/foo/bar:1") == "gcr.io"
    assert _image_registry("attacker.evil.io/x") == "attacker.evil.io"
    assert _image_registry("localhost:5000/img") == "localhost:5000"


def test_pod_containers_walks_init_and_ephemeral():
    pod = {"spec": {
        "containers": [{"name": "app"}],
        "initContainers": [{"name": "wait"}],
        "ephemeralContainers": [{"name": "debug"}],
    }}
    pairs = list(_pod_containers(pod))
    kinds = [p[0] for p in pairs]
    assert kinds == ["container", "init", "ephemeral"]


def test_has_secret_in_env_value_detects_baked_credential():
    c = {"env": [
        {"name": "DATABASE_PASSWORD", "value": "x9Kp2qFnA1qZv8mLrTwB"},
    ]}
    leaked = _has_secret_in_env_value(c)
    assert leaked == ["DATABASE_PASSWORD"]


def test_has_secret_in_env_value_skips_secret_ref():
    c = {"env": [
        {"name": "DATABASE_PASSWORD",
         "valueFrom": {"secretKeyRef":
                       {"name": "db-secret", "key": "password"}}},
    ]}
    leaked = _has_secret_in_env_value(c)
    assert leaked == []


def test_has_secret_in_env_value_skips_non_secret_named_vars():
    c = {"env": [
        {"name": "DATABASE_URL",
         "value": "postgres://localhost:5432/mydb"},
    ]}
    leaked = _has_secret_in_env_value(c)
    assert leaked == []


def test_has_secret_in_env_value_skips_changeme_placeholder():
    c = {"env": [{"name": "API_KEY", "value": "changeme"}]}
    leaked = _has_secret_in_env_value(c)
    assert leaked == []


# ---------------------------------------------------------------- #
# K8sSecurityDetector — end-to-end findings
# ---------------------------------------------------------------- #


def _store(tmp_path):
    return EvidenceStore(str(tmp_path / "case"))


def _add_pod(store, ns, name, *, containers=None, init=None,
              host_path=None, host_network=False, host_pid=False,
              host_ipc=False, service_account=None,
              volumes=None):
    spec = {
        "containers": containers or [{"name": "main",
                                        "image": "gcr.io/foo/bar:v1"}],
    }
    if init:
        spec["initContainers"] = init
    if host_network:
        spec["hostNetwork"] = True
    if host_pid:
        spec["hostPID"] = True
    if host_ipc:
        spec["hostIPC"] = True
    if service_account:
        spec["serviceAccountName"] = service_account
    if volumes:
        spec["volumes"] = volumes
    elif host_path:
        spec["volumes"] = [{
            "name": "hp-vol",
            "hostPath": {"path": host_path},
        }]
    item = {
        "kind": "Pod",
        "metadata": {"namespace": ns, "name": name},
        "spec": spec,
    }
    store.add_artifact(Artifact(
        collector="k8s.pods", category="cluster",
        subject=f"k8s:pods:{ns}/{name}",
        data={"k8s_resource": "pods", "k8s_namespace": ns,
              "k8s_name": name, "k8s_context": "",
              "item": item},
    ))


def _add_crb(store, name, role, subjects):
    item = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": name},
        "subjects": subjects,
        "roleRef": {"name": role, "kind": "ClusterRole"},
    }
    store.add_artifact(Artifact(
        collector="k8s.clusterrolebindings", category="cluster",
        subject=f"k8s:clusterrolebindings:{name}",
        data={"k8s_resource": "clusterrolebindings",
              "k8s_namespace": "", "k8s_name": name,
              "k8s_context": "", "item": item},
    ))


def _add_netpol(store, ns, name):
    item = {
        "kind": "NetworkPolicy",
        "metadata": {"namespace": ns, "name": name},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
    }
    store.add_artifact(Artifact(
        collector="k8s.networkpolicies", category="cluster",
        subject=f"k8s:networkpolicies:{ns}/{name}",
        data={"k8s_resource": "networkpolicies",
              "k8s_namespace": ns, "k8s_name": name,
              "k8s_context": "", "item": item},
    ))


# ---- K1 privileged pod ---- #


def test_k1_privileged_pod_critical(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "danger",
             containers=[{"name": "c",
                           "image": "gcr.io/foo/bar:v1",
                           "securityContext": {"privileged": True}}])
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "privileged_pod"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1611"
    assert hits[0].evidence["namespace"] == "default"
    assert hits[0].evidence["pod"] == "danger"
    store.close()


def test_k1_non_privileged_pod_no_finding(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "safe")
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "privileged_pod"] == []
    store.close()


# ---- K2 dangerous hostPath ---- #


@pytest.mark.parametrize("path", [
    "/var/run/docker.sock",
    "/", "/etc/kubernetes/admin.conf",
    "/proc/1/root",
])
def test_k2_dangerous_hostpath_critical(tmp_path, path):
    store = _store(tmp_path)
    _add_pod(store, "kube-system", "node-shell", host_path=path)
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "dangerous_hostpath"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].evidence["host_path"] == path
    store.close()


def test_k2_benign_hostpath_no_finding(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "data", host_path="/srv/myapp/data")
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "dangerous_hostpath"] == []
    store.close()


# ---- K3 hostNetwork / hostPID / hostIPC ---- #


def test_k3_host_network_high(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "ns-share", host_network=True)
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("flag") == "hostNetwork"]
    assert hits
    assert hits[0].severity == "high"
    store.close()


def test_k3_host_pid_high(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "pid-share", host_pid=True)
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("flag") == "hostPID"]
    assert hits
    store.close()


# ---- K4 CRB to system:authenticated / unauthenticated / masters ---- #


@pytest.mark.parametrize("group", [
    "system:authenticated",
    "system:unauthenticated",
    "system:masters",
])
def test_k4_clusterrole_to_dangerous_group_critical(tmp_path, group):
    store = _store(tmp_path)
    _add_crb(store, "bad-binding", "cluster-admin",
             subjects=[{"kind": "Group", "name": group}])
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "clusterrolebinding_overprivileged"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].evidence["subject"] == group
    store.close()


def test_k4_benign_clusterrolebinding_no_finding(tmp_path):
    store = _store(tmp_path)
    _add_crb(store, "ok-binding", "view",
             subjects=[{"kind": "User",
                        "name": "alice@example.com"}])
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "clusterrolebinding_overprivileged"] == []
    store.close()


# ---- K5 SA → cluster-admin ---- #


def test_k5_app_sa_cluster_admin_critical(tmp_path):
    store = _store(tmp_path)
    _add_crb(store, "app-admin", "cluster-admin",
             subjects=[{"kind": "ServiceAccount",
                        "name": "my-app",
                        "namespace": "default"}])
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "sa_cluster_admin"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].evidence["service_account"] == "my-app"
    store.close()


def test_k5_kube_system_canonical_controller_skipped(tmp_path):
    """kube-system controllers ARE supposed to be cluster-admin —
    don't flag them."""
    store = _store(tmp_path)
    _add_crb(store, "system:controller:generic-garbage-collector",
             "cluster-admin",
             subjects=[{"kind": "ServiceAccount",
                        "name": "generic-garbage-collector",
                        "namespace": "kube-system"}])
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "sa_cluster_admin"] == []
    store.close()


# ---- K6 untrusted registry ---- #


def test_k6_untrusted_registry_high(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "evil",
             containers=[{"name": "c",
                           "image": "attacker.evil.io/payload:v1"}])
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "untrusted_registry"]
    assert hits
    assert hits[0].severity == "high"
    assert hits[0].evidence["registry"] == "attacker.evil.io"
    store.close()


def test_k6_trusted_registry_no_finding(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "ok",
             containers=[{"name": "c",
                           "image": "gcr.io/google-containers/etcd:3.5"}])
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "untrusted_registry"] == []
    store.close()


# ---- K7 unpinned :latest ---- #


def test_k7_unpinned_latest_medium(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "nginx",
             containers=[{"name": "c",
                           "image": "docker.io/library/nginx:latest"}])
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "unpinned_image"]
    assert hits
    assert hits[0].severity == "medium"
    store.close()


def test_k7_pinned_digest_no_finding(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "pinned",
             containers=[{"name": "c",
                           "image": "gcr.io/foo/bar@sha256:abc123"}])
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "unpinned_image"] == []
    store.close()


# ---- K8 secret in env ---- #


def test_k8_secret_in_env_high(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "leaky",
             containers=[{"name": "c",
                           "image": "gcr.io/foo/bar:v1",
                           "env": [
                               {"name": "API_TOKEN",
                                "value": "tk_x9Kp2qFnA1qZv8mLrTwB"},
                           ]}])
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "secret_in_env"]
    assert hits
    assert hits[0].severity == "high"
    assert "API_TOKEN" in hits[0].evidence["env_vars"]
    store.close()


# ---- K9 default SA ---- #


def test_k9_default_sa_medium(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "no-sa")   # no serviceAccountName
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "default_sa_usage"]
    assert hits
    assert hits[0].severity == "medium"
    store.close()


def test_k9_explicit_sa_no_finding(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "default", "good", service_account="my-app-sa")
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "default_sa_usage"] == []
    store.close()


# ---- K10 namespace missing NetworkPolicy ---- #


def test_k10_namespace_missing_netpol_medium(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "production", "app", service_account="prod-sa")
    findings = list(K8sSecurityDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "namespace_missing_networkpolicy"]
    assert hits
    assert hits[0].evidence["namespace"] == "production"
    store.close()


def test_k10_namespace_with_netpol_no_finding(tmp_path):
    store = _store(tmp_path)
    _add_pod(store, "production", "app", service_account="prod-sa")
    _add_netpol(store, "production", "default-deny")
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "namespace_missing_networkpolicy"] == []
    store.close()


def test_k10_system_namespaces_skipped(tmp_path):
    """kube-system / kube-public / default get a pass even without a
    NetworkPolicy — they're managed differently."""
    store = _store(tmp_path)
    _add_pod(store, "kube-system", "kube-proxy",
             service_account="kube-proxy")
    findings = list(K8sSecurityDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "namespace_missing_networkpolicy"] == []
    store.close()


# ---------------------------------------------------------------- #
# Registration + Sigma
# ---------------------------------------------------------------- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "k8s_security" in [d.name for d in all_detectors()]


def test_sigma_template_present():
    tpl = K8sSecurityDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["logsource"]["product"] == "kubernetes"
    for tag in ("attack.t1611", "attack.t1098",
                "attack.t1525", "attack.t1078.001"):
        assert tag in tpl["tags"]


# ---------------------------------------------------------------- #
# CLI smoke
# ---------------------------------------------------------------- #


def test_cli_k8s_collect_without_binary_errors(tmp_path):
    env = {k: v for k, v in os.environ.items()
           if k != "DIGGER_KUBECTL_BIN"}
    env["DIGGER_KUBECTL_BIN"] = "/nonexistent/zzz/kubectl"
    env["PATH"] = "/usr/local/bin"   # narrow PATH to miss any kubectl
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "k8s", "collect", "--case-dir", str(tmp_path / "case")],
        capture_output=True, text=True, timeout=15, env=env,
    )
    assert r.returncode == 1
    assert "no kubectl binary" in r.stderr
